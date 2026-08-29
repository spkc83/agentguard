"""Authoritative in-memory registry state and prepare/audit/commit ledger."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping  # noqa: TC003 - Pydantic resolves this field at runtime
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from agentguard.core.registry import (
    AgentRegistryRecord,
    AgentRegistrySnapshot,
    AgentStatus,
    AuthoritativeAgentRegistry,
)
from agentguard.exceptions import IdentityNotFoundError, RegistryError, RegistryFailure
from agentguard.models import AuditEvent, RegistryMutationEvidence

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentguard.core.audit import AuditLog, VerifiedAuditSnapshot
    from agentguard.core.authentication import ControlPlanePrincipal


def _canonical(value: str) -> str:
    if value != value.strip() or not value.isprintable():
        raise ValueError("registry identifiers must be canonical printable text")
    return value


class _RegistryCommand(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation_id: str = Field(min_length=1, max_length=256)
    target_agent_id: str = Field(min_length=1, max_length=256)
    expected_registry_revision: int | None = Field(default=None, ge=0)

    @field_validator("operation_id", "target_agent_id")
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        return _canonical(value)


class RegisterAgentCommand(_RegistryCommand):
    mutation: Literal["register"] = "register"
    name: str = Field(min_length=1, max_length=256)
    roles: tuple[str, ...] = ()
    metadata: Mapping[str, str] = Field(default_factory=lambda: MappingProxyType({}))

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _canonical(value)

    @field_validator("roles")
    @classmethod
    def _validate_roles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_canonical(role) for role in value}))

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        return MappingProxyType({_canonical(key): _canonical(item) for key, item in value.items()})

    @field_serializer("metadata")
    def _serialize_metadata(self, value: Mapping[str, str]) -> dict[str, str]:
        return dict(value)


class ReplaceAgentRolesCommand(_RegistryCommand):
    mutation: Literal["replace_roles"] = "replace_roles"
    roles: tuple[str, ...] = ()

    @field_validator("roles")
    @classmethod
    def _validate_roles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({_canonical(role) for role in value}))


class RotateAgentCredentialsCommand(_RegistryCommand):
    mutation: Literal["rotate_credentials"] = "rotate_credentials"


class RevokeAgentCommand(_RegistryCommand):
    mutation: Literal["revoke"] = "revoke"


RegistryMutationCommand = Annotated[
    RegisterAgentCommand
    | ReplaceAgentRolesCommand
    | RotateAgentCredentialsCommand
    | RevokeAgentCommand,
    Field(discriminator="mutation"),
]


class RegistryOperationState(StrEnum):
    PREPARED = "prepared"
    AUDITED = "audited"
    COMMITTED = "committed"
    CONFLICTED = "conflicted"


class SignedAuditReference(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    chain_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    key_id: str = Field(min_length=1)

    @field_validator("chain_id", "key_id")
    @classmethod
    def _validate_descriptor(cls, value: str) -> str:
        return _canonical(value)


class RegistryOperation(BaseModel):
    """Immutable durable-shaped operation ledger entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    operation_id: str = Field(min_length=1, max_length=256)
    state: RegistryOperationState
    mutation: Literal["register", "replace_roles", "rotate_credentials", "revoke"]
    target_agent_id: str = Field(min_length=1, max_length=256)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal_id: str = Field(min_length=1, max_length=256)
    base_registry_revision: int = Field(ge=0)
    target_registry_revision: int = Field(ge=1)
    proposed_record: AgentRegistryRecord
    prepared_at: datetime
    trace_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence: RegistryMutationEvidence
    audit_reference: SignedAuditReference | None = None
    failure: RegistryFailure | None = None

    @field_validator("operation_id", "target_agent_id", "principal_id")
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        return _canonical(value)

    @field_validator("prepared_at")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("operation prepared_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_operation_binding(self) -> RegistryOperation:
        evidence = self.evidence
        if evidence.state != "authorized":
            raise ValueError("operation ledger requires authorized evidence")
        expected_ids = {
            "registry_id": evidence.registry_id,
            "operation_id": self.operation_id,
        }
        if (
            evidence.operation_id != self.operation_id
            or evidence.mutation != self.mutation
            or evidence.target_agent_id != self.target_agent_id
            or evidence.request_digest != self.request_digest
            or evidence.principal_id != self.principal_id
            or evidence.base_registry_revision != self.base_registry_revision
            or evidence.target_registry_revision != self.target_registry_revision
            or evidence.after_record_digest != record_digest(self.proposed_record)
            or evidence.target_credential_epoch != self.proposed_record.credential_epoch
            or evidence.prepared_at != self.prepared_at
            or self.proposed_record.agent_id != self.target_agent_id
            or self.trace_id
            != canonical_digest(expected_ids, domain="agentguard.registry.trace-id.v1")
            or self.event_id
            != canonical_digest(expected_ids, domain="agentguard.registry.event-id.v1")
        ):
            raise ValueError("operation ledger fields do not match signed evidence")
        if self.state is RegistryOperationState.PREPARED:
            if self.audit_reference is not None or self.failure is not None:
                raise ValueError("prepared operations cannot claim audit or terminal state")
            return self
        if self.audit_reference is None or self.audit_reference.event_id != self.event_id:
            raise ValueError("post-audit operations require the exact signed event reference")
        if self.state is RegistryOperationState.CONFLICTED:
            if self.failure is not RegistryFailure.REVISION_CONFLICT:
                raise ValueError("conflicted operations require a revision conflict")
        elif self.failure is not None:
            raise ValueError("non-conflicted operations cannot carry a failure")
        return self


class RegistryPreparationError(RegistryError):
    """Internal contextual rejection used to build secret-free evidence."""

    def __init__(
        self,
        failure: RegistryFailure,
        *,
        requested_revision: int | None = None,
        observed_revision: int | None = None,
    ) -> None:
        super().__init__(failure)
        self.requested_revision = requested_revision
        self.observed_revision = observed_revision


def canonical_digest(value: object, *, domain: str = "agentguard.registry.value.v1") -> str:
    """Hash canonical JSON with an explicit domain separator."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    encoded = domain.encode() + b"\0" + encoded
    return hashlib.sha256(encoded).hexdigest()


def principal_digest(principal: ControlPlanePrincipal) -> str:
    return canonical_digest(
        {
            "principal_id": principal.principal_id,
            "method": principal.method,
            "authority": principal.authority,
            "credential_digest": principal.credential_digest,
            "capabilities": sorted(principal.capabilities),
        },
        domain="agentguard.registry.principal-authorization.v1",
    )


def record_digest(record: AgentRegistryRecord) -> str:
    return canonical_digest(record, domain="agentguard.registry.record.v1")


class _RegistryMutationPort:
    """Private mutation capability held only by an authenticated control plane."""

    __slots__ = ("__authority", "__registry")

    def __init__(self, registry: InMemoryAuthoritativeAgentRegistry, authority: object) -> None:
        self.__registry = registry
        self.__authority = authority

    @property
    def requires_attestable_audit(self) -> bool:
        return self.__registry._requires_attestable_audit()

    async def get_operation(self, operation_id: str) -> RegistryOperation | None:
        return await self.__registry._get_operation(self.__authority, operation_id)

    async def prepare(
        self,
        command: RegistryMutationCommand,
        principal: ControlPlanePrincipal,
        *,
        prepared_at: datetime,
        authorize: Callable[[RegistryMutationCommand, tuple[str, ...]], None],
    ) -> RegistryOperation:
        return await self.__registry._prepare(
            self.__authority,
            command,
            principal,
            prepared_at=prepared_at,
            authorize=authorize,
        )

    async def commit(self, operation_id: str) -> AgentRegistryRecord:
        return await self.__registry._commit(self.__authority, operation_id)

    async def anchor_audit_event(self, event_id: str) -> None:
        await self.__registry._anchor_audit_event(self.__authority, event_id)


class InMemoryAuthoritativeAgentRegistry(AuthoritativeAgentRegistry):
    """Process-local authoritative registry with an atomic mutation ledger."""

    def __init__(self, registry_id: str = "default", *, audit_log: AuditLog) -> None:
        if not registry_id:
            raise ValueError("registry_id cannot be empty")
        self._registry_id = _canonical(registry_id)
        self._registry_revision = 0
        self._records: dict[str, AgentRegistryRecord] = {}
        self._operations: dict[str, RegistryOperation] = {}
        self._lock = asyncio.Lock()
        self._audit_log = audit_log
        self.__mutation_authority = object()

    @property
    def registry_id(self) -> str:
        return self._registry_id

    async def resolve(self, agent_id: str) -> AgentRegistryRecord:
        record = await self.get_record(agent_id)
        if record.status is AgentStatus.REVOKED:
            raise RegistryError(RegistryFailure.IDENTITY_INACTIVE)
        return record

    async def get_record(self, agent_id: str) -> AgentRegistryRecord:
        async with self._lock:
            record = self._records.get(agent_id)
            if record is None:
                raise IdentityNotFoundError(agent_id)
            return record.model_copy(deep=True)

    async def snapshot(self) -> AgentRegistrySnapshot:
        async with self._lock:
            return AgentRegistrySnapshot(
                registry_id=self._registry_id,
                registry_revision=self._registry_revision,
                records=tuple(record.model_copy(deep=True) for record in self._records.values()),
            )

    def _requires_attestable_audit(self) -> bool:
        return False

    async def _anchor_audit_event(
        self,
        authority: object,
        event_id: str,
    ) -> None:
        self._check_authority(authority)
        snapshot = await self._read_verified_audit(
            require_checkpoint=self._requires_attestable_audit()
        )
        matching = tuple(event for event in snapshot.events if event.event_id == event_id)
        if len(matching) != 1:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        evidence = matching[0].registry_mutation_evidence
        if (
            matching[0].event_type != "registry_mutation_rejected"
            or evidence is None
            or evidence.state != "rejected"
            or evidence.registry_id != self.registry_id
        ):
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        await self._anchor_verified_audit_snapshot(authority, snapshot)

    async def _anchor_verified_audit_snapshot(
        self,
        authority: object,
        _snapshot: VerifiedAuditSnapshot,
    ) -> None:
        self._check_authority(authority)

    def _check_authority(self, authority: object) -> None:
        if authority is not self.__mutation_authority:
            raise RegistryPreparationError(RegistryFailure.CAPABILITY_DENIED)

    async def _get_operation(
        self,
        authority: object,
        operation_id: str,
    ) -> RegistryOperation | None:
        self._check_authority(authority)
        async with self._lock:
            return self._get_operation_locked(operation_id)

    def _get_operation_locked(self, operation_id: str) -> RegistryOperation | None:
        operation = self._operations.get(operation_id)
        return operation.model_copy(deep=True) if operation is not None else None

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
        async with self._lock:
            return self._prepare_locked(
                command,
                principal,
                prepared_at=prepared_at,
                authorize=authorize,
            )

    def _prepare_locked(
        self,
        command: RegistryMutationCommand,
        principal: ControlPlanePrincipal,
        *,
        prepared_at: datetime,
        authorize: Callable[[RegistryMutationCommand, tuple[str, ...]], None],
    ) -> RegistryOperation:
        request_hash = canonical_digest(command, domain="agentguard.registry.command.v1")
        actor_hash = principal_digest(principal)
        existing = self._operations.get(command.operation_id)
        if existing is not None:
            if existing.request_digest != request_hash or existing.principal_digest != actor_hash:
                raise RegistryPreparationError(RegistryFailure.OPERATION_CONFLICT)
            return existing.model_copy(deep=True)

        observed = self._registry_revision
        if (
            command.expected_registry_revision is not None
            and command.expected_registry_revision != observed
        ):
            raise RegistryPreparationError(
                RegistryFailure.REVISION_CONFLICT,
                requested_revision=command.expected_registry_revision,
                observed_revision=observed,
            )
        before = self._records.get(command.target_agent_id)
        authorize(command, before.roles if before is not None else ())
        proposed = self._propose(command, before, prepared_at)
        target_revision = observed + 1
        stable_identity = {
            "registry_id": self._registry_id,
            "operation_id": command.operation_id,
        }
        trace_id = canonical_digest(
            stable_identity,
            domain="agentguard.registry.trace-id.v1",
        )
        event_id = canonical_digest(
            stable_identity,
            domain="agentguard.registry.event-id.v1",
        )
        evidence = RegistryMutationEvidence(
            state="authorized",
            operation_id=command.operation_id,
            registry_id=self._registry_id,
            mutation=command.mutation,
            principal_id=principal.principal_id,
            authentication_method=principal.method,
            authentication_authority=principal.authority,
            credential_digest=principal.credential_digest,
            capabilities_digest=canonical_digest(
                sorted(principal.capabilities),
                domain="agentguard.registry.capabilities.v1",
            ),
            target_agent_id=command.target_agent_id,
            request_digest=request_hash,
            base_registry_revision=observed,
            target_registry_revision=target_revision,
            before_record_digest=record_digest(before) if before is not None else None,
            after_record_digest=record_digest(proposed),
            base_credential_epoch=before.credential_epoch if before is not None else None,
            target_credential_epoch=proposed.credential_epoch,
            prepared_at=prepared_at,
        )
        operation = RegistryOperation(
            operation_id=command.operation_id,
            state=RegistryOperationState.PREPARED,
            mutation=command.mutation,
            target_agent_id=command.target_agent_id,
            request_digest=request_hash,
            principal_digest=actor_hash,
            principal_id=principal.principal_id,
            base_registry_revision=observed,
            target_registry_revision=target_revision,
            proposed_record=proposed,
            prepared_at=prepared_at,
            trace_id=trace_id,
            event_id=event_id,
            evidence=evidence,
        )
        self._operations[command.operation_id] = operation
        return operation.model_copy(deep=True)

    def _propose(
        self,
        command: RegistryMutationCommand,
        before: AgentRegistryRecord | None,
        now: datetime,
    ) -> AgentRegistryRecord:
        now = now.astimezone(UTC)
        if command.mutation == "register":
            if before is not None:
                raise RegistryPreparationError(RegistryFailure.OPERATION_CONFLICT)
            return AgentRegistryRecord.model_validate(
                {
                    "agent_id": command.target_agent_id,
                    "name": command.name,
                    "roles": command.roles,
                    "metadata": command.metadata,
                    "credential_epoch": 1,
                    "record_revision": 1,
                    "created_at": now,
                    "updated_at": now,
                }
            )
        if before is None:
            raise RegistryPreparationError(RegistryFailure.IDENTITY_NOT_FOUND)
        if before.status is AgentStatus.REVOKED:
            raise RegistryPreparationError(RegistryFailure.IDENTITY_INACTIVE)
        if command.mutation == "replace_roles":
            return self._replace_record(
                before,
                roles=command.roles,
                record_revision=before.record_revision + 1,
                updated_at=now,
            )
        if command.mutation == "rotate_credentials":
            return self._replace_record(
                before,
                credential_epoch=before.credential_epoch + 1,
                record_revision=before.record_revision + 1,
                updated_at=now,
            )
        return self._replace_record(
            before,
            status=AgentStatus.REVOKED,
            credential_epoch=before.credential_epoch + 1,
            record_revision=before.record_revision + 1,
            updated_at=now,
            revoked_at=now,
        )

    @staticmethod
    def _replace_record(
        record: AgentRegistryRecord,
        **updates: object,
    ) -> AgentRegistryRecord:
        """Rebuild through validation; ``model_copy(update=...)`` skips validators."""

        values = record.model_dump(mode="python")
        values.update(updates)
        return AgentRegistryRecord.model_validate(values)

    async def _commit(
        self,
        authority: object,
        operation_id: str,
    ) -> AgentRegistryRecord:
        self._check_authority(authority)
        async with self._lock:
            operation = self._operations.get(operation_id)
            if operation is None:
                raise RegistryPreparationError(RegistryFailure.OPERATION_CONFLICT)
            operation = operation.model_copy(deep=True)
        reference, _snapshot = await self._verified_reference_for(
            operation,
            require_checkpoint=False,
        )
        async with self._lock:
            return self._commit_locked(operation_id, reference)

    async def _verified_reference_for(
        self,
        operation: RegistryOperation,
        *,
        require_checkpoint: bool,
    ) -> tuple[SignedAuditReference, VerifiedAuditSnapshot]:
        snapshot = await self._read_verified_audit(require_checkpoint=require_checkpoint)
        matching = tuple(event for event in snapshot.events if event.event_id == operation.event_id)
        if len(matching) != 1:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        return self._validate_recovered_signed_event(operation, matching[0]), snapshot

    async def _read_verified_audit(
        self,
        *,
        require_checkpoint: bool = False,
    ) -> VerifiedAuditSnapshot:
        try:
            snapshot = await self._audit_log.read_verified(require_checkpoint=require_checkpoint)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        if not snapshot.verification.valid:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        if (
            self._requires_attestable_audit()
            and snapshot.events
            and snapshot.verification.checkpoint_valid is not True
        ):
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        return snapshot

    def _commit_locked(
        self,
        operation_id: str,
        reference: SignedAuditReference,
    ) -> AgentRegistryRecord:
        operation = self._operations.get(operation_id)
        if operation is None:
            raise RegistryPreparationError(RegistryFailure.OPERATION_CONFLICT)
        if operation.state is RegistryOperationState.COMMITTED:
            return operation.proposed_record.model_copy(deep=True)
        if operation.state is RegistryOperationState.CONFLICTED:
            raise RegistryPreparationError(
                RegistryFailure.REVISION_CONFLICT,
                requested_revision=operation.base_registry_revision,
                observed_revision=self._registry_revision,
            )
        if reference.event_id != operation.event_id:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        audited = self._replace_operation(
            operation,
            state=RegistryOperationState.AUDITED,
            audit_reference=reference,
        )
        self._operations[operation_id] = audited
        if self._registry_revision != audited.base_registry_revision:
            conflicted = self._replace_operation(
                audited,
                state=RegistryOperationState.CONFLICTED,
                failure=RegistryFailure.REVISION_CONFLICT,
            )
            self._operations[operation_id] = conflicted
            raise RegistryPreparationError(
                RegistryFailure.REVISION_CONFLICT,
                requested_revision=audited.base_registry_revision,
                observed_revision=self._registry_revision,
            )
        self._records[audited.target_agent_id] = audited.proposed_record
        self._registry_revision = audited.target_registry_revision
        committed = self._replace_operation(
            audited,
            state=RegistryOperationState.COMMITTED,
        )
        self._operations[operation_id] = committed
        return committed.proposed_record.model_copy(deep=True)

    def _validate_signed_event(
        self,
        authority: object,
        operation: RegistryOperation,
        event: AuditEvent,
    ) -> SignedAuditReference:
        self._check_authority(authority)
        try:
            validated = AuditEvent.model_validate(event.model_dump(mode="python"))
        except ValueError as error:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED) from error
        if (
            validated.event_id != operation.event_id
            or validated.timestamp != operation.prepared_at
            or validated.trace_id != operation.trace_id
            or validated.invocation_id != operation.operation_id
            or validated.event_type != "registry_mutation_authorized"
            or validated.registry_mutation_evidence != operation.evidence
            or not validated.event_hash
            or not validated.chain_id
            or validated.sequence is None
            or not validated.key_id
            or validated.hash_schema_version != 8
        ):
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        assert validated.sequence is not None
        return SignedAuditReference(
            event_id=validated.event_id,
            event_hash=validated.event_hash,
            chain_id=validated.chain_id,
            sequence=validated.sequence,
            key_id=validated.key_id,
        )

    def _validate_recovered_signed_event(
        self,
        operation: RegistryOperation,
        event: AuditEvent,
    ) -> SignedAuditReference:
        """Validate recovery evidence inside a trusted registry implementation."""

        return self._validate_signed_event(self.__mutation_authority, operation, event)

    @staticmethod
    def _replace_operation(
        operation: RegistryOperation,
        **updates: object,
    ) -> RegistryOperation:
        values = operation.model_dump(mode="python")
        values.update(updates)
        return RegistryOperation.model_validate(values)


def _bind_registry_control_plane(
    registry: InMemoryAuthoritativeAgentRegistry,
) -> _RegistryMutationPort:
    """Bind the internal mutation capability to the authenticated control plane."""

    authority = cast(
        "object",
        object.__getattribute__(
            registry,
            "_InMemoryAuthoritativeAgentRegistry__mutation_authority",
        ),
    )
    return _RegistryMutationPort(registry, authority)


__all__ = [
    "InMemoryAuthoritativeAgentRegistry",
    "RegisterAgentCommand",
    "RegistryMutationCommand",
    "RegistryOperation",
    "RegistryOperationState",
    "ReplaceAgentRolesCommand",
    "RevokeAgentCommand",
    "RotateAgentCredentialsCommand",
    "SignedAuditReference",
]
