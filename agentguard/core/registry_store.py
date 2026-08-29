"""Signed POSIX persistence for the authoritative agent registry."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, NoReturn

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.core.registry import (  # noqa: TC001 - Pydantic resolves these at runtime
    AgentRegistryRecord,
    AgentRegistrySnapshot,
    AgentStatus,
)
from agentguard.core.registry_state import (
    InMemoryAuthoritativeAgentRegistry,
    RegistryMutationCommand,
    RegistryOperation,
    RegistryOperationState,
    RegistryPreparationError,
    SignedAuditReference,
)
from agentguard.exceptions import IdentityNotFoundError, RegistryError, RegistryFailure

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from datetime import datetime

    from agentguard.core.audit import AuditLog, VerifiedAuditSnapshot
    from agentguard.core.authentication import ControlPlanePrincipal
    from agentguard.models import AuditEvent

_SCHEMA_VERSION = 1
_SIGNING_DOMAIN = b"agentguard.registry.state.v1\0"
_CHECKPOINT_DOMAIN = b"agentguard.registry.checkpoint.v1\0"
_STATE_NAME = "registry-state.json"
_LOCK_NAME = ".registry-state.lock"
_CHECKPOINT_NAME = ".registry-state.checkpoint"
_MAXIMUM_STATE_BYTES = 64 * 1024 * 1024
_PROCESS_LOCKS: dict[str, threading.Lock] = {}


class _AuditHeadReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(min_length=1)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    chain_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    key_id: str = Field(min_length=1)

    @field_validator("event_id", "chain_id", "key_id")
    @classmethod
    def _canonical_text(cls, value: str) -> str:
        if value != value.strip() or not value.isprintable():
            raise ValueError("audit head identifiers must be canonical printable text")
        return value


class _RegistryCheckpoint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=_SCHEMA_VERSION)
    registry_id: str
    store_revision: int = Field(ge=0)
    state_signature: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_checkpoint_digest: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    key_id: str
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("schema_version")
    @classmethod
    def _supported_schema(cls, value: int) -> int:
        if value != _SCHEMA_VERSION:
            raise ValueError("unsupported registry checkpoint schema")
        return value


class _RegistryEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = Field(default=_SCHEMA_VERSION)
    registry_id: str
    store_revision: int = Field(ge=0)
    registry_revision: int = Field(ge=0)
    records: tuple[AgentRegistryRecord, ...] = ()
    operations: tuple[RegistryOperation, ...] = ()
    last_committed_audit_binding: SignedAuditReference | None = None
    audit_head_binding: _AuditHeadReference | None = None
    previous_checkpoint_digest: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    key_id: str
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("schema_version")
    @classmethod
    def _supported_schema(cls, value: int) -> int:
        if value != _SCHEMA_VERSION:
            raise ValueError("unsupported registry state schema")
        return value

    @field_validator("records")
    @classmethod
    def _unique_sorted_records(
        cls, value: tuple[AgentRegistryRecord, ...]
    ) -> tuple[AgentRegistryRecord, ...]:
        by_id = {record.agent_id: record for record in value}
        if len(by_id) != len(value):
            raise ValueError("registry state contains duplicate records")
        if tuple(by_id) != tuple(sorted(by_id)):
            raise ValueError("registry records must be canonically ordered")
        return value

    @field_validator("operations")
    @classmethod
    def _unique_sorted_operations(
        cls, value: tuple[RegistryOperation, ...]
    ) -> tuple[RegistryOperation, ...]:
        by_id = {operation.operation_id: operation for operation in value}
        if len(by_id) != len(value):
            raise ValueError("registry state contains duplicate operations")
        if tuple(by_id) != tuple(sorted(by_id)):
            raise ValueError("registry operations must be canonically ordered")
        return value

    @model_validator(mode="after")
    def _validate_revisions_and_binding(self) -> _RegistryEnvelope:
        if self.store_revision < self.registry_revision:
            raise ValueError("store revision cannot trail registry revision")
        if any(record.record_revision > self.registry_revision for record in self.records):
            raise ValueError("record revision cannot exceed registry revision")
        committed = [
            operation
            for operation in self.operations
            if operation.state is RegistryOperationState.COMMITTED
        ]
        if any(
            operation.target_registry_revision > self.registry_revision for operation in committed
        ):
            raise ValueError("committed operation exceeds registry revision")
        committed_by_revision = {
            operation.target_registry_revision: operation for operation in committed
        }
        if len(committed_by_revision) != len(committed) or tuple(
            sorted(committed_by_revision)
        ) != tuple(range(1, self.registry_revision + 1)):
            raise ValueError("committed registry revisions must be unique and contiguous")
        latest_by_agent: dict[str, RegistryOperation] = {}
        for operation in committed:
            previous = latest_by_agent.get(operation.target_agent_id)
            if (
                previous is None
                or operation.target_registry_revision > previous.target_registry_revision
            ):
                latest_by_agent[operation.target_agent_id] = operation
        records_by_agent = {record.agent_id: record for record in self.records}
        if set(records_by_agent) != set(latest_by_agent) or any(
            records_by_agent[agent_id] != operation.proposed_record
            for agent_id, operation in latest_by_agent.items()
        ):
            raise ValueError("registry records do not match committed operation history")
        expected = (
            max(committed, key=lambda operation: operation.target_registry_revision).audit_reference
            if committed
            else None
        )
        if self.last_committed_audit_binding != expected:
            raise ValueError("last committed audit binding is inconsistent")
        if expected is not None:
            head = self.audit_head_binding
            if (
                head is None
                or head.chain_id != expected.chain_id
                or head.sequence < expected.sequence
            ):
                raise ValueError("audit head cannot trail committed registry evidence")
        return self


class SignedFileAuthoritativeAgentRegistry(InMemoryAuthoritativeAgentRegistry):
    """Signed local registry with an independently retained monotonic checkpoint."""

    _MINIMUM_KEY_BYTES: ClassVar[int] = 32

    def __init__(
        self,
        directory: Path,
        *,
        trusted_checkpoint_path: Path,
        registry_id: str,
        signing_key: bytes,
        key_id: str,
        audit_log: AuditLog,
    ) -> None:
        if len(signing_key) < self._MINIMUM_KEY_BYTES:
            raise ValueError("registry signing key must contain at least 32 bytes")
        if not key_id or key_id != key_id.strip() or not key_id.isprintable():
            raise ValueError("registry signing key ID must be canonical printable text")
        super().__init__(registry_id, audit_log=audit_log)
        self._directory = Path(directory)
        self._state_path = self._directory / _STATE_NAME
        self._lock_path = self._directory / _LOCK_NAME
        self._checkpoint_path = self._directory / _CHECKPOINT_NAME
        self._trusted_checkpoint_path = Path(trusted_checkpoint_path)
        self._trusted_lock_path = self._trusted_checkpoint_path.with_name(
            f".{self._trusted_checkpoint_path.name}.lock"
        )
        self._signing_key = bytes(bytearray(signing_key))
        self._key_id = key_id
        self._store_revision = 0
        self._audit_head_binding: _AuditHeadReference | None = None
        self._registry_checkpoint: _RegistryCheckpoint | None = None
        lock_key = os.path.abspath(self._directory)
        self._process_lock = _PROCESS_LOCKS.setdefault(lock_key, threading.Lock())

    @classmethod
    async def open(
        cls,
        directory: str | os.PathLike[str],
        *,
        trusted_checkpoint_path: str | os.PathLike[str],
        registry_id: str,
        signing_key: bytes,
        key_id: str,
        audit_log: AuditLog,
    ) -> SignedFileAuthoritativeAgentRegistry:
        """Open and recover a store anchored outside its registry directory."""

        instance = cls(
            Path(directory),
            trusted_checkpoint_path=Path(trusted_checkpoint_path),
            registry_id=registry_id,
            signing_key=signing_key,
            key_id=key_id,
            audit_log=audit_log,
        )
        try:
            supports_checkpoints = audit_log.supports_durable_checkpoints
        except Exception as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        if supports_checkpoints is not True:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        await asyncio.to_thread(instance._ensure_directory)
        await asyncio.to_thread(instance._ensure_trusted_checkpoint_directory)
        for _attempt in range(8):
            envelope = await asyncio.to_thread(instance._load_transaction, True)
            snapshot = await instance._read_verified_audit()
            reconciled = await asyncio.to_thread(
                instance._reconcile_transaction,
                envelope.store_revision,
                snapshot,
            )
            if reconciled:
                return instance
        raise RegistryPreparationError(RegistryFailure.REVISION_CONFLICT)

    async def resolve(self, agent_id: str) -> AgentRegistryRecord:
        record = await asyncio.to_thread(self._record_transaction, agent_id)
        if record.status is AgentStatus.REVOKED:
            raise RegistryError(RegistryFailure.IDENTITY_INACTIVE)
        return record

    def _requires_attestable_audit(self) -> bool:
        return True

    async def get_record(self, agent_id: str) -> AgentRegistryRecord:
        return await asyncio.to_thread(self._record_transaction, agent_id)

    async def snapshot(self) -> AgentRegistrySnapshot:
        return await asyncio.to_thread(self._snapshot_transaction)

    async def _get_operation(
        self, authority: object, operation_id: str
    ) -> RegistryOperation | None:
        self._check_authority(authority)
        return await asyncio.to_thread(self._get_operation_transaction, operation_id)

    async def _prepare(
        self,
        authority: object,
        command: RegistryMutationCommand,
        principal: ControlPlanePrincipal,
        *,
        prepared_at: datetime,
        authorize: Callable[[RegistryMutationCommand, tuple[str, ...]], None],
    ) -> RegistryOperation:
        self._check_authority(authority)
        snapshot = await self._read_verified_audit()
        return await asyncio.to_thread(
            self._prepare_transaction,
            command,
            principal,
            prepared_at,
            authorize,
            snapshot,
        )

    async def _commit(
        self,
        authority: object,
        operation_id: str,
    ) -> AgentRegistryRecord:
        self._check_authority(authority)
        operation = await self._get_operation(authority, operation_id)
        if operation is None:
            raise RegistryPreparationError(RegistryFailure.OPERATION_CONFLICT)
        reference, snapshot = await self._verified_reference_for(
            operation,
            require_checkpoint=True,
        )
        return await asyncio.to_thread(
            self._commit_transaction,
            operation_id,
            reference,
            snapshot,
        )

    async def _anchor_verified_audit_snapshot(
        self,
        authority: object,
        snapshot: VerifiedAuditSnapshot,
    ) -> None:
        self._check_authority(authority)
        await asyncio.to_thread(self._anchor_audit_transaction, snapshot)

    def _with_file_lock(self, operation: Callable[[], object]) -> object:
        with self._process_lock, self._file_lock():
            return operation()

    def _load_transaction(self, create: bool) -> _RegistryEnvelope:
        return self._with_file_lock(lambda: self._load_locked(create=create))  # type: ignore[return-value]

    def _reconcile_transaction(
        self,
        expected_store_revision: int,
        snapshot: VerifiedAuditSnapshot,
    ) -> bool:
        def reconcile() -> bool:
            current = self._load_locked(create=False)
            if current.store_revision != expected_store_revision:
                return False
            self._reconcile_audit_locked(snapshot)
            return True

        return self._with_file_lock(reconcile)  # type: ignore[return-value]

    def _get_operation_transaction(self, operation_id: str) -> RegistryOperation | None:
        def read() -> RegistryOperation | None:
            self._load_locked(create=False)
            return self._get_operation_locked(operation_id)

        return self._with_file_lock(read)  # type: ignore[return-value]

    def _record_transaction(self, agent_id: str) -> AgentRegistryRecord:
        def read() -> AgentRegistryRecord:
            self._load_locked(create=False)
            record = self._records.get(agent_id)
            if record is None:
                raise IdentityNotFoundError(agent_id)
            return record.model_copy(deep=True)

        return self._with_file_lock(read)  # type: ignore[return-value]

    def _snapshot_transaction(self) -> AgentRegistrySnapshot:
        def read() -> AgentRegistrySnapshot:
            self._load_locked(create=False)
            return AgentRegistrySnapshot(
                registry_id=self.registry_id,
                registry_revision=self._registry_revision,
                records=tuple(record.model_copy(deep=True) for record in self._records.values()),
            )

        return self._with_file_lock(read)  # type: ignore[return-value]

    def _prepare_transaction(
        self,
        command: RegistryMutationCommand,
        principal: ControlPlanePrincipal,
        prepared_at: datetime,
        authorize: Callable[[RegistryMutationCommand, tuple[str, ...]], None],
        snapshot: VerifiedAuditSnapshot,
    ) -> RegistryOperation:
        def prepare() -> RegistryOperation:
            self._load_locked(create=False)
            self._validate_audit_prefix_locked(snapshot)
            existed = command.operation_id in self._operations
            operation = self._prepare_locked(
                command,
                principal,
                prepared_at=prepared_at,
                authorize=authorize,
            )
            head_changed = self._advance_audit_head_locked(snapshot)
            if not existed or head_changed:
                self._persist_locked()
            return operation

        return self._with_file_lock(prepare)  # type: ignore[return-value]

    def _commit_transaction(
        self,
        operation_id: str,
        reference: SignedAuditReference,
        snapshot: VerifiedAuditSnapshot,
    ) -> AgentRegistryRecord:
        def commit() -> AgentRegistryRecord:
            self._load_locked(create=False)
            self._validate_audit_prefix_locked(snapshot)
            head_changed = self._advance_audit_head_locked(snapshot)
            operation = self._operations.get(operation_id)
            if operation is None:
                raise RegistryPreparationError(RegistryFailure.OPERATION_CONFLICT)
            if operation.state is RegistryOperationState.COMMITTED:
                if head_changed:
                    self._persist_locked()
                return operation.proposed_record.model_copy(deep=True)
            if operation.state is RegistryOperationState.CONFLICTED:
                raise RegistryPreparationError(
                    RegistryFailure.REVISION_CONFLICT,
                    requested_revision=operation.base_registry_revision,
                    observed_revision=self._registry_revision,
                )
            if reference.event_id != operation.event_id:
                self._tamper()
            if operation.state is RegistryOperationState.PREPARED:
                operation = self._replace_operation(
                    operation,
                    state=RegistryOperationState.AUDITED,
                    audit_reference=reference,
                )
                self._operations[operation_id] = operation
                self._persist_locked()
            return self._commit_audited_locked(operation)

        return self._with_file_lock(commit)  # type: ignore[return-value]

    def _anchor_audit_transaction(self, snapshot: VerifiedAuditSnapshot) -> None:
        def anchor() -> None:
            self._load_locked(create=False)
            self._validate_audit_prefix_locked(snapshot)
            if self._advance_audit_head_locked(snapshot):
                self._persist_locked()

        self._with_file_lock(anchor)

    def _commit_audited_locked(self, operation: RegistryOperation) -> AgentRegistryRecord:
        if self._registry_revision != operation.base_registry_revision:
            conflicted = self._replace_operation(
                operation,
                state=RegistryOperationState.CONFLICTED,
                failure=RegistryFailure.REVISION_CONFLICT,
            )
            self._operations[operation.operation_id] = conflicted
            self._persist_locked()
            raise RegistryPreparationError(
                RegistryFailure.REVISION_CONFLICT,
                requested_revision=operation.base_registry_revision,
                observed_revision=self._registry_revision,
            )
        self._records[operation.target_agent_id] = operation.proposed_record
        self._registry_revision = operation.target_registry_revision
        committed = self._replace_operation(
            operation,
            state=RegistryOperationState.COMMITTED,
        )
        self._operations[operation.operation_id] = committed
        self._persist_locked()
        return committed.proposed_record.model_copy(deep=True)

    def _reconcile_audit_locked(self, snapshot: VerifiedAuditSnapshot) -> None:
        if not snapshot.verification.valid:
            self._tamper()
        self._validate_audit_prefix_locked(snapshot)
        changed = self._advance_audit_head_locked(snapshot)
        relevant: dict[str, AuditEvent] = {}
        for event in snapshot.events:
            evidence = event.registry_mutation_evidence
            if (
                event.event_type == "registry_mutation_authorized"
                and evidence is not None
                and evidence.registry_id == self.registry_id
            ):
                relevant[event.event_id] = event
        for event_id, event in relevant.items():
            evidence = event.registry_mutation_evidence
            assert evidence is not None
            operation = self._operations.get(evidence.operation_id)
            if operation is None or operation.event_id != event_id:
                self._tamper()
            reference = self._validate_recovered_signed_event(operation, event)
            if operation.state is RegistryOperationState.PREPARED:
                operation = self._replace_operation(
                    operation,
                    state=RegistryOperationState.AUDITED,
                    audit_reference=reference,
                )
                self._operations[operation.operation_id] = operation
                changed = True
            elif operation.audit_reference != reference:
                self._tamper()
        for operation in self._operations.values():
            if (
                operation.state is not RegistryOperationState.PREPARED
                and operation.event_id not in relevant
            ):
                self._tamper()
        if changed:
            self._persist_locked()
        for operation in tuple(self._operations.values()):
            if operation.state is RegistryOperationState.AUDITED:
                try:
                    self._commit_audited_locked(operation)
                except RegistryPreparationError as error:
                    if error.failure is not RegistryFailure.REVISION_CONFLICT:
                        raise

    def _validate_audit_prefix_locked(self, snapshot: VerifiedAuditSnapshot) -> None:
        binding = self._audit_head_binding
        if binding is None:
            return
        if (
            not snapshot.verification.valid
            or snapshot.verification.chain_id != binding.chain_id
            or len(snapshot.events) < binding.sequence
        ):
            self._tamper()
        event = snapshot.events[binding.sequence - 1]
        if (
            event.event_id != binding.event_id
            or event.event_hash != binding.event_hash
            or event.chain_id != binding.chain_id
            or event.sequence != binding.sequence
            or event.key_id != binding.key_id
        ):
            self._tamper()

    def _advance_audit_head_locked(self, snapshot: VerifiedAuditSnapshot) -> bool:
        if not snapshot.events:
            return False
        event = snapshot.events[-1]
        if event.sequence is None or not event.event_hash or not event.chain_id or not event.key_id:
            self._tamper()
        head = _AuditHeadReference(
            event_id=event.event_id,
            event_hash=event.event_hash,
            chain_id=event.chain_id,
            sequence=event.sequence,
            key_id=event.key_id,
        )
        current = self._audit_head_binding
        if current is not None:
            if head.chain_id != current.chain_id or head.sequence < current.sequence:
                self._tamper()
            if head.sequence == current.sequence:
                if head != current:
                    self._tamper()
                return False
        self._audit_head_binding = head
        return True

    def _load_locked(self, *, create: bool) -> _RegistryEnvelope:
        try:
            path_metadata = self._state_path.lstat()
        except FileNotFoundError:
            if not create:
                self._tamper()
            envelope = self._build_envelope(store_revision=0)
            checkpoint = self._checkpoint_for(envelope)
            try:
                existing_checkpoint = self._read_checkpoint_locked()
            except FileNotFoundError:
                self._write_checkpoint_locked(checkpoint)
            else:
                if existing_checkpoint != checkpoint:
                    self._tamper()
            self._registry_checkpoint = checkpoint
            self._initialize_trusted_checkpoint_locked(checkpoint)
            self._write_envelope_locked(envelope)
            self._apply_envelope(envelope)
            return envelope
        self._validate_file_metadata(path_metadata)
        try:
            descriptor = os.open(
                self._state_path,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
        except OSError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        try:
            self._validate_file_descriptor(descriptor)
            if os.fstat(descriptor).st_size > _MAXIMUM_STATE_BYTES:
                self._tamper()
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, 65536):
                total += len(chunk)
                if total > _MAXIMUM_STATE_BYTES:
                    self._tamper()
                chunks.append(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(descriptor)
        try:
            payload = json.loads(
                raw,
                parse_constant=lambda _value: self._tamper(),
            )
            envelope = _RegistryEnvelope.model_validate(payload)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        if envelope.registry_id != self.registry_id or envelope.key_id != self._key_id:
            self._tamper()
        expected = self._signature(envelope.model_dump(mode="json", exclude={"signature"}))
        if not hmac.compare_digest(envelope.signature, expected):
            self._tamper()
        if raw != self._canonical_json(envelope.model_dump(mode="json")):
            self._tamper()
        if envelope.store_revision < self._store_revision:
            self._tamper()
        self._validate_registry_checkpoint_locked(envelope)
        self._apply_envelope(envelope)
        return envelope

    def _apply_envelope(self, envelope: _RegistryEnvelope) -> None:
        self._store_revision = envelope.store_revision
        self._registry_revision = envelope.registry_revision
        self._records = {record.agent_id: record for record in envelope.records}
        self._operations = {operation.operation_id: operation for operation in envelope.operations}
        self._audit_head_binding = envelope.audit_head_binding

    def _persist_locked(self) -> None:
        previous = self._registry_checkpoint
        if previous is None:
            self._tamper()
        envelope = self._build_envelope(store_revision=self._store_revision + 1)
        self._write_envelope_locked(envelope)
        checkpoint = self._checkpoint_for(envelope)
        self._write_checkpoint_locked(checkpoint)
        self._advance_trusted_checkpoint_locked(previous, checkpoint)
        self._registry_checkpoint = checkpoint
        self._store_revision = envelope.store_revision

    def _build_envelope(self, *, store_revision: int) -> _RegistryEnvelope:
        committed = [
            operation
            for operation in self._operations.values()
            if operation.state is RegistryOperationState.COMMITTED
        ]
        binding = (
            max(committed, key=lambda operation: operation.target_registry_revision).audit_reference
            if committed
            else None
        )
        unsigned = {
            "schema_version": _SCHEMA_VERSION,
            "registry_id": self.registry_id,
            "store_revision": store_revision,
            "registry_revision": self._registry_revision,
            "records": [
                record.model_dump(mode="json") for _, record in sorted(self._records.items())
            ],
            "operations": [
                operation.model_dump(mode="json")
                for _, operation in sorted(self._operations.items())
            ],
            "last_committed_audit_binding": (
                binding.model_dump(mode="json") if binding is not None else None
            ),
            "audit_head_binding": (
                self._audit_head_binding.model_dump(mode="json")
                if self._audit_head_binding is not None
                else None
            ),
            "previous_checkpoint_digest": (
                self._checkpoint_digest(self._registry_checkpoint)
                if self._registry_checkpoint is not None
                else ""
            ),
            "key_id": self._key_id,
        }
        return _RegistryEnvelope.model_validate(
            {**unsigned, "signature": self._signature(unsigned)}
        )

    def _checkpoint_for(self, envelope: _RegistryEnvelope) -> _RegistryCheckpoint:
        unsigned = {
            "schema_version": _SCHEMA_VERSION,
            "registry_id": self.registry_id,
            "store_revision": envelope.store_revision,
            "state_signature": envelope.signature,
            "previous_checkpoint_digest": envelope.previous_checkpoint_digest,
            "key_id": self._key_id,
        }
        return _RegistryCheckpoint.model_validate(
            {**unsigned, "signature": self._checkpoint_signature(unsigned)}
        )

    def _validate_registry_checkpoint_locked(self, envelope: _RegistryEnvelope) -> None:
        try:
            checkpoint = self._read_checkpoint_locked()
        except FileNotFoundError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        if checkpoint.registry_id != self.registry_id or checkpoint.key_id != self._key_id:
            self._tamper()
        expected = self._checkpoint_signature(
            checkpoint.model_dump(mode="json", exclude={"signature"})
        )
        if not hmac.compare_digest(checkpoint.signature, expected):
            self._tamper()
        if checkpoint.store_revision == envelope.store_revision:
            if (
                checkpoint.state_signature != envelope.signature
                or checkpoint.previous_checkpoint_digest != envelope.previous_checkpoint_digest
            ):
                self._tamper()
            current = checkpoint
        else:
            if checkpoint.store_revision + 1 != envelope.store_revision:
                self._tamper()
            if envelope.previous_checkpoint_digest != self._checkpoint_digest(checkpoint):
                self._tamper()
            current = self._checkpoint_for(envelope)
            self._write_checkpoint_locked(current)
        self._validate_trusted_checkpoint_locked(current)
        self._registry_checkpoint = current

    def _validate_trusted_checkpoint_locked(self, current: _RegistryCheckpoint) -> None:
        try:
            trusted = self._read_trusted_checkpoint_locked()
        except FileNotFoundError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        self._validate_checkpoint_signature(trusted)
        if trusted == current:
            return
        if (
            trusted.store_revision + 1 != current.store_revision
            or current.previous_checkpoint_digest != self._checkpoint_digest(trusted)
        ):
            self._tamper()
        self._write_trusted_checkpoint_locked(current)

    def _initialize_trusted_checkpoint_locked(self, checkpoint: _RegistryCheckpoint) -> None:
        try:
            trusted = self._read_trusted_checkpoint_locked()
        except FileNotFoundError:
            self._write_trusted_checkpoint_locked(checkpoint)
            return
        self._validate_checkpoint_signature(trusted)
        if trusted != checkpoint:
            self._tamper()

    def _advance_trusted_checkpoint_locked(
        self,
        previous: _RegistryCheckpoint,
        current: _RegistryCheckpoint,
    ) -> None:
        try:
            trusted = self._read_trusted_checkpoint_locked()
        except FileNotFoundError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        self._validate_checkpoint_signature(trusted)
        if trusted != previous:
            self._tamper()
        if (
            current.store_revision != previous.store_revision + 1
            or current.previous_checkpoint_digest != self._checkpoint_digest(previous)
        ):
            self._tamper()
        self._write_trusted_checkpoint_locked(current)

    def _read_checkpoint_locked(self) -> _RegistryCheckpoint:
        return self._read_checkpoint_file_locked(self._checkpoint_path)

    def _read_trusted_checkpoint_locked(self) -> _RegistryCheckpoint:
        return self._read_checkpoint_file_locked(self._trusted_checkpoint_path)

    def _read_checkpoint_file_locked(self, path: Path) -> _RegistryCheckpoint:
        raw = self._read_secure_file(path)
        try:
            checkpoint = _RegistryCheckpoint.model_validate_json(raw)
        except ValueError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        if raw != self._canonical_json(checkpoint.model_dump(mode="json")):
            self._tamper()
        return checkpoint

    def _write_checkpoint_locked(self, checkpoint: _RegistryCheckpoint) -> None:
        self._atomic_write_file(
            self._checkpoint_path,
            self._canonical_json(checkpoint.model_dump(mode="json")),
            prefix=".registry-checkpoint.",
        )

    def _write_trusted_checkpoint_locked(self, checkpoint: _RegistryCheckpoint) -> None:
        self._atomic_write_file(
            self._trusted_checkpoint_path,
            self._canonical_json(checkpoint.model_dump(mode="json")),
            prefix=".registry-trusted-checkpoint.",
        )

    def _validate_checkpoint_signature(self, checkpoint: _RegistryCheckpoint) -> None:
        if checkpoint.registry_id != self.registry_id or checkpoint.key_id != self._key_id:
            self._tamper()
        expected = self._checkpoint_signature(
            checkpoint.model_dump(mode="json", exclude={"signature"})
        )
        if not hmac.compare_digest(checkpoint.signature, expected):
            self._tamper()

    def _checkpoint_signature(self, payload: object) -> str:
        return hmac.new(
            self._signing_key,
            _CHECKPOINT_DOMAIN + self._canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()

    def _checkpoint_digest(self, checkpoint: _RegistryCheckpoint) -> str:
        return hashlib.sha256(
            _CHECKPOINT_DOMAIN + self._canonical_json(checkpoint.model_dump(mode="json"))
        ).hexdigest()

    def _write_envelope_locked(self, envelope: _RegistryEnvelope) -> None:
        self._atomic_write_file(
            self._state_path,
            self._canonical_json(envelope.model_dump(mode="json")),
            prefix=".registry-state.",
        )

    def _read_secure_file(self, path: Path) -> bytes:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            raise
        self._validate_file_metadata(metadata)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        try:
            self._validate_file_descriptor(descriptor)
            if os.fstat(descriptor).st_size > _MAXIMUM_STATE_BYTES:
                self._tamper()
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, 65536):
                total += len(chunk)
                if total > _MAXIMUM_STATE_BYTES:
                    self._tamper()
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def _atomic_write_file(self, path: Path, encoded: bytes, *, prefix: str) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            pass
        else:
            self._validate_file_metadata(metadata)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                self._validate_file_descriptor(descriptor)
            finally:
                os.close(descriptor)
        descriptor, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
        temporary_path = Path(temporary)
        try:
            os.fchmod(descriptor, 0o600)
            self._validate_file_descriptor(descriptor)
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short registry state write")
                view = view[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary_path, path)
            directory_descriptor = os.open(
                path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with suppress(FileNotFoundError):
                temporary_path.unlink()

    def _signature(self, payload: object) -> str:
        return hmac.new(
            self._signing_key,
            _SIGNING_DOMAIN + self._canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _canonical_json(payload: object) -> bytes:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def _ensure_directory(self) -> None:
        try:
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        self._validate_directory()

    def _ensure_trusted_checkpoint_directory(self) -> None:
        directory = self._trusted_checkpoint_path.parent
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        self._validate_owner_directory(directory)
        registry_directory = self._directory.resolve(strict=True)
        trusted_path = Path(os.path.abspath(self._trusted_checkpoint_path))
        if trusted_path == registry_directory or trusted_path.is_relative_to(registry_directory):
            self._tamper()

    def _validate_directory(self) -> None:
        self._validate_owner_directory(self._directory)

    def _validate_owner_directory(self, directory: Path) -> None:
        try:
            metadata = directory.lstat()
        except OSError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            self._tamper()
        if directory.resolve(strict=True) != Path(os.path.abspath(directory)):
            self._tamper()

    @contextmanager
    def _file_lock(self) -> Iterator[None]:
        self._validate_directory()
        self._validate_owner_directory(self._trusted_checkpoint_path.parent)
        with self._exclusive_lock(self._lock_path), self._exclusive_lock(self._trusted_lock_path):
            yield

    @contextmanager
    def _exclusive_lock(self, path: Path) -> Iterator[None]:
        try:
            descriptor = os.open(
                path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except OSError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        try:
            self._validate_file_descriptor(descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _validate_file_metadata(metadata: os.stat_result) -> None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)

    @staticmethod
    def _validate_file_descriptor(descriptor: int) -> None:
        SignedFileAuthoritativeAgentRegistry._validate_file_metadata(os.fstat(descriptor))

    @staticmethod
    def _tamper() -> NoReturn:
        raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)


__all__ = ["SignedFileAuthoritativeAgentRegistry"]
