"""Immutable, HMAC-chained append-only audit log.

Design principle: log-first, act-second. If the audit write fails,
the action MUST be blocked. The HMAC chain provides tamper evidence —
modifying any past event breaks the chain, detectable via verify_chain().

By default the audit key is read from ``AGENTGUARD_AUDIT_KEY``. Collectors may
instead install an immutable sequence-bound keyring for online rotation.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import hmac
import json
import os
import tempfile
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 — used at runtime in FileAuditBackend
from types import MappingProxyType
from typing import Literal, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, ConfigDict, ValidationError

from agentguard.exceptions import (
    AuditError,
    AuditEventConflictError,
    AuditKeyMissingError,
    AuditKeyUnavailableError,
    AuditKeyWeakError,
    AuditTamperDetectedError,
)
from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    AuditLink,
    AuthenticationEvidence,
    EvidenceRef,
    GuardrailEvaluation,
    HitlEvidence,
    PermissionContext,
    PolicyResult,
    ReconciliationEvidence,
    RegistryMutationEvidence,
)


class _AgentIdentityV1(BaseModel):
    agent_id: str
    name: str
    roles: list[str]
    metadata: dict[str, str] = {}


class _PermissionContextV1(BaseModel):
    agent: _AgentIdentityV1
    requested_action: str
    resource: str
    context: dict[str, object] = {}
    granted: bool = False
    reason: str = ""


class _PolicyResultV1(BaseModel):
    """Exact pre-v2 policy-result shape used for historical HMAC bytes."""

    rule_id: str
    rule_name: str
    passed: bool
    severity: str
    evidence: dict[str, object]
    remediation: str


class _PolicyResultV2(_PolicyResultV1):
    effect: str | None = None


class _AuditEventV1(BaseModel):
    """Exact pre-v2 audit-event shape used for historical HMAC bytes."""

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: _PermissionContextV1
    result: str
    policy_results: list[_PolicyResultV1] = []
    duration_ms: float
    trace_id: str
    event_hash: str = ""
    prev_hash: str = ""


class _AuditEventV2(BaseModel):
    """Exact Phase 1 v2 shape, frozen before Phase 2 extended the envelope."""

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: _PermissionContextV1
    result: str
    policy_results: list[_PolicyResultV2] = []
    duration_ms: float
    trace_id: str
    invocation_id: str = ""
    event_type: str = "legacy"
    reason_codes: tuple[str, ...] = ()
    payload_digest: str = ""
    payload_redacted: dict[str, object] = {}
    hash_schema_version: int = 2
    event_hash: str = ""
    prev_hash: str = ""


class _AuditEventV3(BaseModel):
    """Frozen Phase 2 event envelope; changes require a new hash schema."""

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: _PermissionContextV1
    result: str
    policy_results: list[_PolicyResultV2] = []
    duration_ms: float
    trace_id: str
    invocation_id: str = ""
    event_type: str = "legacy"
    reason_codes: tuple[str, ...] = ()
    payload_digest: str = ""
    payload_redacted: dict[str, object] = {}
    subject_ref: EvidenceRef | None = None
    policy_bundle_version: str = ""
    chain_mode: str = "enforce"
    links: tuple[AuditLink, ...] = ()
    sequence: int
    key_id: str
    chain_id: str
    hash_schema_version: int = 3
    event_hash: str = ""
    prev_hash: str = ""


class _GuardrailEvaluationV4(BaseModel):
    """Frozen v4 guardrail-evaluation evidence included in signed bytes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    guardrail_id: str
    guardrail_version: str
    stage: str
    effect: str
    reason_codes: tuple[str, ...]
    duration_ms: float
    enforced: bool


class _AuditEventV4(BaseModel):
    """Frozen Phase 3 evidence envelope; changes require a new hash schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: _PermissionContextV1
    result: str
    policy_results: list[_PolicyResultV2] = []
    guardrail_evaluations: tuple[_GuardrailEvaluationV4, ...] = ()
    duration_ms: float
    trace_id: str
    invocation_id: str = ""
    event_type: str = "legacy"
    reason_codes: tuple[str, ...] = ()
    payload_digest: str = ""
    payload_redacted: dict[str, object] = {}
    subject_ref: EvidenceRef | None = None
    policy_bundle_version: str = ""
    chain_mode: str = "enforce"
    links: tuple[AuditLink, ...] = ()
    sequence: int
    key_id: str
    chain_id: str
    hash_schema_version: int = 4
    event_hash: str = ""
    prev_hash: str = ""


class _HitlEvidenceV5(BaseModel):
    """Frozen v5 HITL lifecycle evidence included in signed bytes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    escalation_id: str
    decision_id: str
    state: str
    approver_id: str
    reason_redacted: str
    decided_at: datetime | None
    expires_at: datetime | None


class _AuditEventV5(BaseModel):
    """Frozen Phase 3 HITL evidence envelope; changes require a new hash schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: _PermissionContextV1
    result: str
    policy_results: list[_PolicyResultV2] = []
    guardrail_evaluations: tuple[_GuardrailEvaluationV4, ...] = ()
    hitl_evidence: _HitlEvidenceV5 | None = None
    duration_ms: float
    trace_id: str
    invocation_id: str = ""
    event_type: str = "legacy"
    reason_codes: tuple[str, ...] = ()
    payload_digest: str = ""
    payload_redacted: dict[str, object] = {}
    subject_ref: EvidenceRef | None = None
    policy_bundle_version: str = ""
    chain_mode: str = "enforce"
    links: tuple[AuditLink, ...] = ()
    sequence: int
    key_id: str
    chain_id: str
    hash_schema_version: int = 5
    event_hash: str = ""
    prev_hash: str = ""


class _ReconciliationEvidenceV6(BaseModel):
    """Frozen v6 reconciliation evidence included in signed bytes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    escalation_id: str
    claim_id: str
    reconciliation_id: str
    classification: str
    state: str
    reconciler_id: str
    reason_digest: str
    assessed_at: datetime
    audit_chain_id: str
    audit_head_sequence: int
    audit_head_event_hash: str
    journal_revision: int
    journal_digest: str


class _AuditEventV6(BaseModel):
    """Frozen Phase 3 reconciliation envelope; changes require a new schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: _PermissionContextV1
    result: str
    policy_results: list[_PolicyResultV2] = []
    guardrail_evaluations: tuple[_GuardrailEvaluationV4, ...] = ()
    hitl_evidence: _HitlEvidenceV5 | None = None
    reconciliation_evidence: _ReconciliationEvidenceV6 | None = None
    duration_ms: float
    trace_id: str
    invocation_id: str = ""
    event_type: str = "legacy"
    reason_codes: tuple[str, ...] = ()
    payload_digest: str = ""
    payload_redacted: dict[str, object] = {}
    subject_ref: EvidenceRef | None = None
    policy_bundle_version: str = ""
    chain_mode: str = "enforce"
    links: tuple[AuditLink, ...] = ()
    sequence: int
    key_id: str
    chain_id: str
    hash_schema_version: int = 6
    event_hash: str = ""
    prev_hash: str = ""


class _AuthenticationEvidenceV7(BaseModel):
    """Frozen v7 authentication evidence included in signed bytes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: str
    method: str
    authority: str
    agent_id: str
    credential_digest: str
    authenticated_at: datetime
    issued_at: datetime | None
    not_before: datetime | None
    expires_at: datetime | None
    registry_revision: int | None
    failure_reason: str | None


class _AuditEventV7(BaseModel):
    """Frozen Phase 3 authentication envelope; changes require a new schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: _PermissionContextV1
    result: str
    policy_results: list[_PolicyResultV2] = []
    guardrail_evaluations: tuple[_GuardrailEvaluationV4, ...] = ()
    hitl_evidence: _HitlEvidenceV5 | None = None
    reconciliation_evidence: _ReconciliationEvidenceV6 | None = None
    authentication_evidence: _AuthenticationEvidenceV7 | None = None
    duration_ms: float
    trace_id: str
    invocation_id: str = ""
    event_type: str = "legacy"
    reason_codes: tuple[str, ...] = ()
    payload_digest: str = ""
    payload_redacted: dict[str, object] = {}
    subject_ref: EvidenceRef | None = None
    policy_bundle_version: str = ""
    chain_mode: str = "enforce"
    links: tuple[AuditLink, ...] = ()
    sequence: int
    key_id: str
    chain_id: str
    hash_schema_version: int = 7
    event_hash: str = ""
    prev_hash: str = ""


class _RegistryMutationEvidenceV8(BaseModel):
    """Frozen v8 registry mutation evidence included in signed bytes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: str
    operation_id: str
    registry_id: str
    mutation: str
    principal_id: str
    authentication_method: str
    authentication_authority: str
    credential_digest: str
    capabilities_digest: str
    target_agent_id: str
    request_digest: str
    base_registry_revision: int | None
    target_registry_revision: int | None
    requested_registry_revision: int | None
    observed_registry_revision: int | None
    before_record_digest: str | None
    after_record_digest: str | None
    base_credential_epoch: int | None
    target_credential_epoch: int | None
    prepared_at: datetime
    failure_reason: str | None


class _AuditEventV8(_AuditEventV7):
    """Frozen authoritative-registry envelope; changes require a new schema."""

    registry_mutation_evidence: _RegistryMutationEvidenceV8 | None = None
    hash_schema_version: int = 8


logger = structlog.get_logger()

_MIN_AUDIT_KEY_BYTES = 32
"""Minimum AGENTGUARD_AUDIT_KEY length, matching the sibling signed stores."""


def _event_fingerprint(event: AuditEvent) -> bytes:
    """Canonical unsigned content used to make stable event IDs idempotent."""

    unsigned = event.model_copy(
        update={
            "event_hash": "",
            "prev_hash": "",
            "sequence": None,
            "key_id": "",
            "chain_id": "",
            "hash_schema_version": 8,
        }
    )
    return json.dumps(
        unsigned.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class ChainVerificationResult(BaseModel):
    """Result of verifying the HMAC chain integrity."""

    valid: bool
    event_count: int
    error_index: int | None = None
    error_event_id: str | None = None
    checkpoint_valid: bool | None = None
    checkpoint_status: Literal[
        "verified",
        "verified_unanchored",
        "legacy_uncheckpointed",
        "unsupported_backend",
        "empty",
    ] = "empty"
    attestable: bool = False
    chain_id: str = ""
    head_sequence: int | None = None
    head_event_hash: str = ""


class VerifiedAuditSnapshot(BaseModel):
    """One lock-consistent event snapshot and its integrity verdict."""

    events: tuple[AuditEvent, ...]
    verification: ChainVerificationResult


class AuditCheckpoint(BaseModel):
    """Signed durable commitment to the current audit-chain head."""

    checkpoint_schema_version: int = 1
    chain_id: str
    head_sequence: int
    head_event_hash: str
    event_count: int
    signing_key_id: str
    previous_checkpoint_digest: str = ""
    signed_at: datetime
    signature: str = ""


@dataclass(frozen=True, slots=True)
class AuditKeyEpoch:
    """Public non-secret commitment to one sequence-bound signing-key epoch."""

    key_id: str
    activation_sequence: int
    key_fingerprint: str

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("audit key epoch key_id must not be empty")
        if self.activation_sequence < 1:
            raise ValueError("audit key epoch activation_sequence must be positive")
        if len(self.key_fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in self.key_fingerprint
        ):
            raise ValueError("audit key epoch fingerprint must be lowercase SHA-256 hex")


class AuditKeyring:
    """Immutable key material and strictly ordered activation epochs."""

    __slots__ = ("_epochs", "_keys", "_legacy_key_id")

    def __init__(
        self,
        *,
        keys: Mapping[str, bytes],
        epochs: Iterable[AuditKeyEpoch],
        legacy_key_id: str,
    ) -> None:
        copied_keys = {
            key_id: bytes(bytearray(key)) for key_id, key in keys.items() if key_id and key
        }
        if len(copied_keys) != len(keys):
            raise ValueError("audit key IDs and key bytes must not be empty")
        epoch_tuple = tuple(epochs)
        if not epoch_tuple or epoch_tuple[0].activation_sequence != 1:
            raise ValueError("first audit key epoch must be usable at sequence 1")
        epoch_ids = [epoch.key_id for epoch in epoch_tuple]
        activations = [epoch.activation_sequence for epoch in epoch_tuple]
        if len(set(epoch_ids)) != len(epoch_ids):
            raise ValueError("audit key epoch IDs must be unique")
        if len(set(activations)) != len(activations) or activations != sorted(activations):
            raise ValueError("audit key epoch activation sequences must strictly increase")
        if legacy_key_id not in copied_keys:
            raise ValueError("legacy audit key ID must resolve to key bytes")
        for epoch in epoch_tuple:
            key = copied_keys.get(epoch.key_id)
            if key is None:
                raise ValueError(f"audit key epoch {epoch.key_id!r} has no key bytes")
            if not hmac.compare_digest(epoch.key_fingerprint, hashlib.sha256(key).hexdigest()):
                raise ValueError(f"audit key epoch {epoch.key_id!r} fingerprint mismatch")
        self._keys = MappingProxyType(copied_keys)
        self._epochs = epoch_tuple
        self._legacy_key_id = legacy_key_id

    @property
    def keys(self) -> Mapping[str, bytes]:
        return self._keys

    @property
    def epochs(self) -> tuple[AuditKeyEpoch, ...]:
        return self._epochs

    @property
    def legacy_key_id(self) -> str:
        return self._legacy_key_id

    @classmethod
    def from_environment(cls) -> AuditKeyring:
        """Build the backward-compatible single-epoch environment keyring."""

        key_text = os.environ.get("AGENTGUARD_AUDIT_KEY", "")
        if not key_text:
            raise AuditKeyMissingError()
        key = key_text.encode("utf-8")
        # The audit chain is the root of trust for every downstream integrity
        # gate, so its key gets the same >=32-byte floor the escalation store,
        # execution journal, and registry store already enforce — a weak key
        # (e.g. "dev-key") is recoverable from a single signed log line.
        if len(key) < _MIN_AUDIT_KEY_BYTES:
            raise AuditKeyWeakError(minimum_bytes=_MIN_AUDIT_KEY_BYTES)
        # key_id defaults to a truncated digest for backward compatibility with
        # logs already signed under it; with a >=32-byte key this is not a
        # practical oracle. Set AGENTGUARD_AUDIT_KEY_ID to decouple the label.
        key_id = os.environ.get("AGENTGUARD_AUDIT_KEY_ID") or hashlib.sha256(key).hexdigest()[:16]
        return cls(
            keys={key_id: key},
            epochs=(
                AuditKeyEpoch(
                    key_id=key_id,
                    activation_sequence=1,
                    key_fingerprint=hashlib.sha256(key).hexdigest(),
                ),
            ),
            legacy_key_id=key_id,
        )

    def key_for_id(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise AuditKeyUnavailableError(key_id=key_id) from exc

    def epoch_for_sequence(self, sequence: int) -> AuditKeyEpoch:
        if sequence < 1:
            raise ValueError("audit sequence must be positive")
        for epoch in reversed(self._epochs):
            if epoch.activation_sequence <= sequence:
                return epoch
        raise AuditKeyUnavailableError(key_id="<no-active-epoch>")

    def with_rotation(self, *, key_id: str, key: bytes, activation_sequence: int) -> AuditKeyring:
        """Return a new keyring with one non-rebinding future epoch."""

        if key_id in self._keys:
            raise ValueError(f"audit key ID {key_id!r} cannot be rebound")
        replaces_unused_legacy = (
            len(self._epochs) == 1
            and self._epochs[0].key_id == self._legacy_key_id
            and activation_sequence == 1
        )
        if (
            activation_sequence <= self._epochs[-1].activation_sequence
            and not replaces_unused_legacy
        ):
            raise ValueError("audit key epoch activation must strictly increase")
        copied = bytes(bytearray(key))
        if not copied:
            raise ValueError("audit key bytes must not be empty")
        epoch = AuditKeyEpoch(
            key_id=key_id,
            activation_sequence=activation_sequence,
            key_fingerprint=hashlib.sha256(copied).hexdigest(),
        )
        return AuditKeyring(
            keys={**self._keys, key_id: copied},
            epochs=(epoch,) if replaces_unused_legacy else (*self._epochs, epoch),
            legacy_key_id=self._legacy_key_id,
        )


@runtime_checkable
class AuditLog(Protocol):
    """Stable audit sink and verified-evidence boundary."""

    async def write(self, event: AuditEvent) -> AuditEvent: ...
    async def write_once(self, event: AuditEvent) -> AuditEvent: ...
    async def verify_chain(self) -> ChainVerificationResult: ...
    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot: ...
    async def export_checkpoint(self) -> AuditCheckpoint | None: ...

    @property
    def supports_durable_checkpoints(self) -> bool: ...


ChainBuilder = Callable[
    [AuditEvent, AuditEvent | None, int, AuditCheckpoint | None],
    tuple[AuditEvent, AuditCheckpoint],
]
RecoveryValidator = Callable[
    [list[AuditEvent], AuditCheckpoint | None, AuditCheckpoint],
    Literal["discard", "promote"],
]


@runtime_checkable
class AuditBackend(Protocol):
    """Protocol for pluggable audit log storage backends."""

    async def append(self, event: AuditEvent) -> None: ...
    async def read_all(self) -> list[AuditEvent]: ...


class FileAuditBackend:
    """JSONL file-based audit storage.

    Events are written one-per-line to a date-stamped JSONL file
    in the configured directory. Files are named audit-YYYY-MM-DD.jsonl.

    Args:
        directory: Path to the directory where audit log files are stored.
    """

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._directory.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        """Return the configured audit directory for collector coordination."""

        return self._directory

    def _log_file(self) -> Path:
        # UTC, matching event timestamps: files are read back ordered by name,
        # and a local-timezone date could move backwards on reconfiguration.
        return self._directory / f"audit-{datetime.now(UTC).date().isoformat()}.jsonl"

    def _lock_file(self) -> Path:
        return self._directory / ".audit.lock"

    def _checkpoint_file(self) -> Path:
        return self._directory / "audit-head.json"

    def _pending_checkpoint_file(self) -> Path:
        return self._directory / ".audit-head.pending.json"

    async def append(self, event: AuditEvent) -> None:
        """Append one event under an inter-process lock and fsync it."""

        await asyncio.to_thread(self._append_sync, event)

    def _append_sync(self, event: AuditEvent) -> None:
        with self._lock_file().open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                self._append_line_sync(event)
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _append_line_sync(self, event: AuditEvent) -> None:
        log_file = self._log_file()
        payload = (event.model_dump_json() + "\n").encode("utf-8")
        descriptor = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("audit append made no forward progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        logger.debug("audit_event_written", event_id=event.event_id, file=str(log_file))

    async def append_chained(
        self, event: AuditEvent, build: ChainBuilder
    ) -> tuple[AuditEvent, AuditCheckpoint]:
        """Atomically allocate, sign, append, and checkpoint a chain event."""

        return await asyncio.to_thread(self._append_chained_sync, event, build)

    async def append_chained_once(
        self, event: AuditEvent, build: ChainBuilder
    ) -> tuple[AuditEvent, AuditCheckpoint]:
        """Atomically append once by stable event ID, rejecting content conflicts."""

        return await asyncio.to_thread(self._append_chained_once_sync, event, build)

    def _append_chained_sync(
        self, event: AuditEvent, build: ChainBuilder
    ) -> tuple[AuditEvent, AuditCheckpoint]:
        with self._lock_file().open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                if self._pending_checkpoint_file().exists():
                    raise AuditError("audit append requires pending-commit recovery")
                checkpoint = self._read_checkpoint_sync()
                if checkpoint is None:
                    events = self._read_all_sync()
                    tail = events[-1] if events else None
                    next_sequence = len(events) + 1
                else:
                    tail = self._read_tail_sync()
                    next_sequence = checkpoint.head_sequence + 1
                chained, new_checkpoint = build(
                    event,
                    tail,
                    next_sequence,
                    checkpoint,
                )
                self._write_checkpoint_path_sync(new_checkpoint, self._pending_checkpoint_file())
                self._append_line_sync(chained)
                self._promote_pending_checkpoint_sync()
                return chained, new_checkpoint
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _append_chained_once_sync(
        self, event: AuditEvent, build: ChainBuilder
    ) -> tuple[AuditEvent, AuditCheckpoint]:
        with self._lock_file().open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                if self._pending_checkpoint_file().exists():
                    raise AuditError("audit append requires pending-commit recovery")
                events = self._read_all_sync()
                existing = next(
                    (item for item in events if item.event_id == event.event_id),
                    None,
                )
                checkpoint = self._read_checkpoint_sync()
                if existing is not None:
                    if not hmac.compare_digest(
                        _event_fingerprint(existing), _event_fingerprint(event)
                    ):
                        raise AuditEventConflictError(event.event_id)
                    if checkpoint is None:
                        raise AuditError("idempotent audit event has no signed checkpoint")
                    return existing, checkpoint
                tail = events[-1] if events else None
                chained, new_checkpoint = build(
                    event,
                    tail,
                    len(events) + 1,
                    checkpoint,
                )
                self._write_checkpoint_path_sync(new_checkpoint, self._pending_checkpoint_file())
                self._append_line_sync(chained)
                self._promote_pending_checkpoint_sync()
                return chained, new_checkpoint
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _read_tail_sync(self) -> AuditEvent | None:
        """Read only the final durable JSONL record, without parsing history."""

        for log_file in sorted(self._directory.glob("audit-*.jsonl"), reverse=True):
            with log_file.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                position = stream.tell()
                buffer = b""
                while position > 0:
                    size = min(8192, position)
                    position -= size
                    stream.seek(position)
                    buffer = stream.read(size) + buffer
                    stripped = buffer.rstrip(b"\r\n")
                    newline = stripped.rfind(b"\n")
                    if newline >= 0 or position == 0:
                        line = stripped[newline + 1 :]
                        if line:
                            return AuditEvent.model_validate_json(line)
                        break
        return None

    def _write_checkpoint_sync(self, checkpoint: AuditCheckpoint) -> None:
        self._write_checkpoint_path_sync(checkpoint, self._checkpoint_file())

    def _write_checkpoint_path_sync(self, checkpoint: AuditCheckpoint, destination: Path) -> None:
        temporary_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self._directory,
                prefix=".audit-head-",
                delete=False,
            ) as stream:
                temporary_name = stream.name
                stream.write(checkpoint.model_dump_json())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
            directory_fd = os.open(self._directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)

    def _promote_pending_checkpoint_sync(self) -> None:
        os.replace(self._pending_checkpoint_file(), self._checkpoint_file())
        directory_fd = os.open(self._directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    async def recover_pending(
        self, validate: RecoveryValidator
    ) -> Literal["none", "discarded", "promoted"]:
        """Resolve one prepared append under the directory-wide writer lock."""

        return await asyncio.to_thread(self._recover_pending_sync, validate)

    def _recover_pending_sync(
        self, validate: RecoveryValidator
    ) -> Literal["none", "discarded", "promoted"]:
        with self._lock_file().open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                pending_path = self._pending_checkpoint_file()
                if not pending_path.exists():
                    return "none"
                pending = AuditCheckpoint.model_validate_json(
                    pending_path.read_text(encoding="utf-8")
                )
                action = validate(self._read_all_sync(), self._read_checkpoint_sync(), pending)
                if action == "promote":
                    self._promote_pending_checkpoint_sync()
                    return "promoted"
                pending_path.unlink()
                directory_fd = os.open(self._directory, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                return "discarded"
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _read_checkpoint_sync(self) -> AuditCheckpoint | None:
        checkpoint_file = self._checkpoint_file()
        if not checkpoint_file.exists():
            return None
        return AuditCheckpoint.model_validate_json(checkpoint_file.read_text(encoding="utf-8"))

    async def read_checkpoint(self) -> AuditCheckpoint | None:
        """Read the durable signed chain-head checkpoint, if one exists."""

        return await asyncio.to_thread(self._read_checkpoint_sync)

    async def read_state(self) -> tuple[list[AuditEvent], AuditCheckpoint | None]:
        """Read events and checkpoint under one directory-wide shared lock."""

        return await asyncio.to_thread(self._read_state_sync)

    def _read_state_sync(self) -> tuple[list[AuditEvent], AuditCheckpoint | None]:
        with self._lock_file().open("a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
            try:
                return self._read_all_sync(), self._read_checkpoint_sync()
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    async def read_all(self) -> list[AuditEvent]:
        """Read all events from all JSONL files in the directory, sorted by filename."""
        return await asyncio.to_thread(self._read_all_sync)

    def _read_all_sync(self) -> list[AuditEvent]:
        events: list[AuditEvent] = []
        for log_file in sorted(self._directory.glob("audit-*.jsonl")):
            with log_file.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            event = AuditEvent.model_validate_json(line)
                        except (ValidationError, ValueError) as exc:
                            event_id = "<invalid-event>"
                            try:
                                raw = json.loads(line)
                                if isinstance(raw, dict) and isinstance(raw.get("event_id"), str):
                                    event_id = raw["event_id"]
                            except (json.JSONDecodeError, TypeError):
                                pass
                            raise AuditTamperDetectedError(
                                event_index=len(events), event_id=event_id
                            ) from exc
                        events.append(event)
        return events


class AppendOnlyAuditLog:
    """HMAC-chained immutable audit log.

    Each event's hash covers its content + the hash of the previous event,
    forming a tamper-evident chain. Modifying any event invalidates all
    subsequent hashes.

    Args:
        backend: Storage backend (default: FileAuditBackend).

    Raises:
        AuditKeyMissingError: If AGENTGUARD_AUDIT_KEY env var is not set.
    """

    def __init__(
        self,
        backend: AuditBackend,
        *,
        trusted_checkpoint: AuditCheckpoint | None = None,
        keyring: AuditKeyring | None = None,
    ) -> None:
        self._keyring = keyring or AuditKeyring.from_environment()
        self._chain_id = str(uuid.uuid4())
        self._backend = backend
        self._trusted_checkpoint = trusted_checkpoint
        self._prev_hash = ""
        self._event_count = 0
        self._chain_initialized = False
        self._write_lock = asyncio.Lock()

    @property
    def backend(self) -> AuditBackend:
        """Return the configured backend for first-party collector coordination."""

        return self._backend

    @property
    def supports_durable_checkpoints(self) -> bool:
        """Whether verified snapshots can be bound to durable checkpoints."""

        return isinstance(self._backend, FileAuditBackend)

    @property
    def keyring(self) -> AuditKeyring:
        """Return the immutable currently installed signing keyring."""

        return self._keyring

    def install_keyring(self, keyring: AuditKeyring) -> None:
        """Install an immutable extension under the caller's write serialization."""

        current = self._keyring
        if keyring.legacy_key_id != current.legacy_key_id:
            raise ValueError("audit keyring cannot rebind the legacy key")
        replaces_unused_legacy = (
            self._event_count == 0
            and self._trusted_checkpoint is None
            and len(current.epochs) == len(keyring.epochs) == 1
            and current.epochs[0].key_id == current.legacy_key_id
            and keyring.epochs[0].activation_sequence == 1
        )
        if keyring.epochs[: len(current.epochs)] != current.epochs and not replaces_unused_legacy:
            raise ValueError("audit keyring cannot remove or rebind existing epochs")
        for key_id, key in current.keys.items():
            candidate = keyring.keys.get(key_id)
            if candidate is None or not hmac.compare_digest(key, candidate):
                raise ValueError("audit keyring cannot remove or rebind existing keys")
        committed_sequence = (
            self._trusted_checkpoint.head_sequence
            if self._trusted_checkpoint is not None
            else self._event_count
        )
        if any(
            epoch.activation_sequence <= committed_sequence
            for epoch in (
                keyring.epochs if replaces_unused_legacy else keyring.epochs[len(current.epochs) :]
            )
        ):
            raise ValueError("audit key rotation cannot rewrite a committed sequence")
        self._keyring = keyring

    async def recover_interrupted_append(
        self,
    ) -> Literal["none", "discarded", "promoted"]:
        """Recover only the two valid states of the prepared append protocol."""

        if not isinstance(self._backend, FileAuditBackend):
            return "none"
        outcome = await self._backend.recover_pending(self._validate_pending_recovery)
        if outcome == "promoted":
            checkpoint = await self._backend.read_checkpoint()
            self._trusted_checkpoint = checkpoint
            self._event_count = checkpoint.head_sequence if checkpoint is not None else 0
        return outcome

    def _validate_pending_recovery(
        self,
        events: list[AuditEvent],
        current: AuditCheckpoint | None,
        pending: AuditCheckpoint,
    ) -> Literal["discard", "promote"]:
        index = max(pending.head_sequence - 1, 0)
        expected_epoch = self._keyring.epoch_for_sequence(pending.head_sequence)
        expected_signature = self._compute_checkpoint_hash(pending)
        if (
            pending.head_sequence < 1
            or pending.event_count != pending.head_sequence
            or not pending.chain_id
            or not pending.head_event_hash
            or pending.signing_key_id != expected_epoch.key_id
            or not hmac.compare_digest(pending.signature, expected_signature)
        ):
            raise AuditTamperDetectedError(index, "<pending-checkpoint>")

        if current is not None:
            current_index = current.head_sequence - 1
            if current_index < 0 or current_index >= len(events):
                raise AuditTamperDetectedError(index, "<pending-checkpoint>")
            self._validate_checkpoint(events[current_index], current)
            if (
                pending.head_sequence != current.head_sequence + 1
                or pending.previous_checkpoint_digest != current.signature
                or pending.chain_id != current.chain_id
            ):
                raise AuditTamperDetectedError(index, "<pending-checkpoint>")
        elif pending.previous_checkpoint_digest:
            raise AuditTamperDetectedError(index, "<pending-checkpoint>")

        if len(events) == pending.head_sequence:
            self._verify_state(events, pending, checkpoint_supported=True)
            return "promote"
        if len(events) == pending.head_sequence - 1:
            if current is None and any(event.hash_schema_version >= 3 for event in events):
                raise AuditTamperDetectedError(index, "<pending-checkpoint>")
            return "discard"
        raise AuditTamperDetectedError(index, "<pending-checkpoint>")

    def _compute_hash(self, event: AuditEvent) -> str:
        """Compute HMAC-SHA256 using the event's declared hash schema."""
        data = event.model_copy(update={"event_hash": "", "prev_hash": event.prev_hash})
        if data.hash_schema_version == 1:
            key = self._keyring.key_for_id(self._keyring.legacy_key_id)
            legacy = _AuditEventV1(
                event_id=data.event_id,
                timestamp=data.timestamp,
                agent_id=data.agent_id,
                action=data.action,
                resource=data.resource,
                permission_context=self._permission_v1(data.permission_context),
                result=data.result,
                policy_results=[
                    _PolicyResultV1(
                        rule_id=result.rule_id,
                        rule_name=result.rule_name,
                        passed=result.passed,
                        severity=result.severity,
                        evidence=result.evidence,
                        remediation=result.remediation,
                    )
                    for result in data.policy_results
                ],
                duration_ms=data.duration_ms,
                trace_id=data.trace_id,
                event_hash="",
                prev_hash=data.prev_hash,
            )
            payload = legacy.model_dump_json().encode("utf-8")
        elif data.hash_schema_version == 2:
            key = self._keyring.key_for_id(self._keyring.legacy_key_id)
            legacy_v2 = _AuditEventV2(
                event_id=data.event_id,
                timestamp=data.timestamp,
                agent_id=data.agent_id,
                action=data.action,
                resource=data.resource,
                permission_context=self._permission_v1(data.permission_context),
                result=data.result,
                policy_results=[self._policy_v2(result) for result in data.policy_results],
                duration_ms=data.duration_ms,
                trace_id=data.trace_id,
                invocation_id=data.invocation_id,
                event_type=data.event_type,
                reason_codes=data.reason_codes,
                payload_digest=data.payload_digest,
                payload_redacted=data.payload_redacted,
                hash_schema_version=2,
                event_hash="",
                prev_hash=data.prev_hash,
            )
            payload = legacy_v2.model_dump_json().encode("utf-8")
        elif data.hash_schema_version == 3:
            assert data.sequence is not None
            epoch = self._keyring.epoch_for_sequence(data.sequence)
            key = self._keyring.key_for_id(epoch.key_id)
            current = _AuditEventV3(
                event_id=data.event_id,
                timestamp=data.timestamp,
                agent_id=data.agent_id,
                action=data.action,
                resource=data.resource,
                permission_context=self._permission_v1(data.permission_context),
                result=data.result,
                policy_results=[self._policy_v2(result) for result in data.policy_results],
                duration_ms=data.duration_ms,
                trace_id=data.trace_id,
                invocation_id=data.invocation_id,
                event_type=data.event_type,
                reason_codes=data.reason_codes,
                payload_digest=data.payload_digest,
                payload_redacted=data.payload_redacted,
                subject_ref=data.subject_ref,
                policy_bundle_version=data.policy_bundle_version,
                chain_mode=data.chain_mode,
                links=data.links,
                sequence=data.sequence,
                key_id=data.key_id,
                chain_id=data.chain_id,
                hash_schema_version=3,
                event_hash="",
                prev_hash=data.prev_hash,
            )
            payload = b"agentguard.audit.event.v3\0" + self._canonical_json(current)
        elif data.hash_schema_version == 4:
            assert data.sequence is not None
            epoch = self._keyring.epoch_for_sequence(data.sequence)
            key = self._keyring.key_for_id(epoch.key_id)
            current_v4 = _AuditEventV4(
                event_id=data.event_id,
                timestamp=data.timestamp,
                agent_id=data.agent_id,
                action=data.action,
                resource=data.resource,
                permission_context=self._permission_v1(data.permission_context),
                result=data.result,
                policy_results=[self._policy_v2(result) for result in data.policy_results],
                guardrail_evaluations=tuple(
                    self._guardrail_evaluation_v4(evaluation)
                    for evaluation in data.guardrail_evaluations
                ),
                duration_ms=data.duration_ms,
                trace_id=data.trace_id,
                invocation_id=data.invocation_id,
                event_type=data.event_type,
                reason_codes=data.reason_codes,
                payload_digest=data.payload_digest,
                payload_redacted=data.payload_redacted,
                subject_ref=data.subject_ref,
                policy_bundle_version=data.policy_bundle_version,
                chain_mode=data.chain_mode,
                links=data.links,
                sequence=data.sequence,
                key_id=data.key_id,
                chain_id=data.chain_id,
                hash_schema_version=4,
                event_hash="",
                prev_hash=data.prev_hash,
            )
            payload = b"agentguard.audit.event.v4\0" + self._canonical_json(current_v4)
        elif data.hash_schema_version == 5:
            assert data.sequence is not None
            epoch = self._keyring.epoch_for_sequence(data.sequence)
            key = self._keyring.key_for_id(epoch.key_id)
            current_v5 = _AuditEventV5(
                event_id=data.event_id,
                timestamp=data.timestamp,
                agent_id=data.agent_id,
                action=data.action,
                resource=data.resource,
                permission_context=self._permission_v1(data.permission_context),
                result=data.result,
                policy_results=[self._policy_v2(result) for result in data.policy_results],
                guardrail_evaluations=tuple(
                    self._guardrail_evaluation_v4(evaluation)
                    for evaluation in data.guardrail_evaluations
                ),
                hitl_evidence=(
                    self._hitl_evidence_v5(data.hitl_evidence)
                    if data.hitl_evidence is not None
                    else None
                ),
                duration_ms=data.duration_ms,
                trace_id=data.trace_id,
                invocation_id=data.invocation_id,
                event_type=data.event_type,
                reason_codes=data.reason_codes,
                payload_digest=data.payload_digest,
                payload_redacted=data.payload_redacted,
                subject_ref=data.subject_ref,
                policy_bundle_version=data.policy_bundle_version,
                chain_mode=data.chain_mode,
                links=data.links,
                sequence=data.sequence,
                key_id=data.key_id,
                chain_id=data.chain_id,
                hash_schema_version=5,
                event_hash="",
                prev_hash=data.prev_hash,
            )
            payload = b"agentguard.audit.event.v5\0" + self._canonical_json(current_v5)
        elif data.hash_schema_version == 6:
            assert data.sequence is not None
            epoch = self._keyring.epoch_for_sequence(data.sequence)
            key = self._keyring.key_for_id(epoch.key_id)
            current_v6 = _AuditEventV6(
                event_id=data.event_id,
                timestamp=data.timestamp,
                agent_id=data.agent_id,
                action=data.action,
                resource=data.resource,
                permission_context=self._permission_v1(data.permission_context),
                result=data.result,
                policy_results=[self._policy_v2(result) for result in data.policy_results],
                guardrail_evaluations=tuple(
                    self._guardrail_evaluation_v4(evaluation)
                    for evaluation in data.guardrail_evaluations
                ),
                hitl_evidence=(
                    self._hitl_evidence_v5(data.hitl_evidence)
                    if data.hitl_evidence is not None
                    else None
                ),
                reconciliation_evidence=(
                    self._reconciliation_evidence_v6(data.reconciliation_evidence)
                    if data.reconciliation_evidence is not None
                    else None
                ),
                duration_ms=data.duration_ms,
                trace_id=data.trace_id,
                invocation_id=data.invocation_id,
                event_type=data.event_type,
                reason_codes=data.reason_codes,
                payload_digest=data.payload_digest,
                payload_redacted=data.payload_redacted,
                subject_ref=data.subject_ref,
                policy_bundle_version=data.policy_bundle_version,
                chain_mode=data.chain_mode,
                links=data.links,
                sequence=data.sequence,
                key_id=data.key_id,
                chain_id=data.chain_id,
                hash_schema_version=6,
                event_hash="",
                prev_hash=data.prev_hash,
            )
            payload = b"agentguard.audit.event.v6\0" + self._canonical_json(current_v6)
        elif data.hash_schema_version == 7:
            assert data.sequence is not None
            epoch = self._keyring.epoch_for_sequence(data.sequence)
            key = self._keyring.key_for_id(epoch.key_id)
            current_v7 = _AuditEventV7(
                event_id=data.event_id,
                timestamp=data.timestamp,
                agent_id=data.agent_id,
                action=data.action,
                resource=data.resource,
                permission_context=self._permission_v1(data.permission_context),
                result=data.result,
                policy_results=[self._policy_v2(result) for result in data.policy_results],
                guardrail_evaluations=tuple(
                    self._guardrail_evaluation_v4(evaluation)
                    for evaluation in data.guardrail_evaluations
                ),
                hitl_evidence=(
                    self._hitl_evidence_v5(data.hitl_evidence)
                    if data.hitl_evidence is not None
                    else None
                ),
                reconciliation_evidence=(
                    self._reconciliation_evidence_v6(data.reconciliation_evidence)
                    if data.reconciliation_evidence is not None
                    else None
                ),
                authentication_evidence=(
                    self._authentication_evidence_v7(data.authentication_evidence)
                    if data.authentication_evidence is not None
                    else None
                ),
                duration_ms=data.duration_ms,
                trace_id=data.trace_id,
                invocation_id=data.invocation_id,
                event_type=data.event_type,
                reason_codes=data.reason_codes,
                payload_digest=data.payload_digest,
                payload_redacted=data.payload_redacted,
                subject_ref=data.subject_ref,
                policy_bundle_version=data.policy_bundle_version,
                chain_mode=data.chain_mode,
                links=data.links,
                sequence=data.sequence,
                key_id=data.key_id,
                chain_id=data.chain_id,
                hash_schema_version=7,
                event_hash="",
                prev_hash=data.prev_hash,
            )
            payload = b"agentguard.audit.event.v7\0" + self._canonical_json(current_v7)
        else:
            assert data.sequence is not None
            epoch = self._keyring.epoch_for_sequence(data.sequence)
            key = self._keyring.key_for_id(epoch.key_id)
            current_v8 = _AuditEventV8(
                event_id=data.event_id,
                timestamp=data.timestamp,
                agent_id=data.agent_id,
                action=data.action,
                resource=data.resource,
                permission_context=self._permission_v1(data.permission_context),
                result=data.result,
                policy_results=[self._policy_v2(result) for result in data.policy_results],
                guardrail_evaluations=tuple(
                    self._guardrail_evaluation_v4(evaluation)
                    for evaluation in data.guardrail_evaluations
                ),
                hitl_evidence=(
                    self._hitl_evidence_v5(data.hitl_evidence)
                    if data.hitl_evidence is not None
                    else None
                ),
                reconciliation_evidence=(
                    self._reconciliation_evidence_v6(data.reconciliation_evidence)
                    if data.reconciliation_evidence is not None
                    else None
                ),
                authentication_evidence=(
                    self._authentication_evidence_v7(data.authentication_evidence)
                    if data.authentication_evidence is not None
                    else None
                ),
                registry_mutation_evidence=(
                    self._registry_mutation_evidence_v8(data.registry_mutation_evidence)
                    if data.registry_mutation_evidence is not None
                    else None
                ),
                duration_ms=data.duration_ms,
                trace_id=data.trace_id,
                invocation_id=data.invocation_id,
                event_type=data.event_type,
                reason_codes=data.reason_codes,
                payload_digest=data.payload_digest,
                payload_redacted=data.payload_redacted,
                subject_ref=data.subject_ref,
                policy_bundle_version=data.policy_bundle_version,
                chain_mode=data.chain_mode,
                links=data.links,
                sequence=data.sequence,
                key_id=data.key_id,
                chain_id=data.chain_id,
                hash_schema_version=8,
                event_hash="",
                prev_hash=data.prev_hash,
            )
            payload = b"agentguard.audit.event.v8\0" + self._canonical_json(current_v8)
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _permission_v1(permission: PermissionContext) -> _PermissionContextV1:
        identity: AgentIdentity = permission.agent
        return _PermissionContextV1(
            agent=_AgentIdentityV1(
                agent_id=identity.agent_id,
                name=identity.name,
                roles=identity.roles,
                metadata=identity.metadata,
            ),
            requested_action=permission.requested_action,
            resource=permission.resource,
            context=permission.context,
            granted=permission.granted,
            reason=permission.reason,
        )

    @staticmethod
    def _policy_v2(result: PolicyResult) -> _PolicyResultV2:
        return _PolicyResultV2(
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            passed=result.passed,
            severity=result.severity,
            evidence=result.evidence,
            remediation=result.remediation,
            effect=result.effect,
        )

    @staticmethod
    def _guardrail_evaluation_v4(
        evaluation: GuardrailEvaluation,
    ) -> _GuardrailEvaluationV4:
        return _GuardrailEvaluationV4(
            guardrail_id=evaluation.guardrail_id,
            guardrail_version=evaluation.guardrail_version,
            stage=evaluation.stage,
            effect=evaluation.effect,
            reason_codes=evaluation.reason_codes,
            duration_ms=evaluation.duration_ms,
            enforced=evaluation.enforced,
        )

    @staticmethod
    def _hitl_evidence_v5(evidence: HitlEvidence) -> _HitlEvidenceV5:
        return _HitlEvidenceV5(
            escalation_id=evidence.escalation_id,
            decision_id=evidence.decision_id,
            state=evidence.state,
            approver_id=evidence.approver_id,
            reason_redacted=evidence.reason_redacted,
            decided_at=evidence.decided_at,
            expires_at=evidence.expires_at,
        )

    @staticmethod
    def _reconciliation_evidence_v6(
        evidence: ReconciliationEvidence,
    ) -> _ReconciliationEvidenceV6:
        return _ReconciliationEvidenceV6(**evidence.model_dump())

    @staticmethod
    def _authentication_evidence_v7(
        evidence: AuthenticationEvidence,
    ) -> _AuthenticationEvidenceV7:
        return _AuthenticationEvidenceV7(**evidence.model_dump())

    @staticmethod
    def _registry_mutation_evidence_v8(
        evidence: RegistryMutationEvidence,
    ) -> _RegistryMutationEvidenceV8:
        return _RegistryMutationEvidenceV8(**evidence.model_dump())

    @staticmethod
    def _canonical_json(model: BaseModel) -> bytes:
        return json.dumps(
            model.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def _compute_checkpoint_hash(self, checkpoint: AuditCheckpoint) -> str:
        unsigned = checkpoint.model_copy(update={"signature": ""})
        key = self._keyring.key_for_id(checkpoint.signing_key_id)
        return hmac.new(
            key,
            b"agentguard.audit.checkpoint.v1\0" + self._canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()

    def _checkpoint_for(
        self,
        event: AuditEvent,
        previous: AuditCheckpoint | None = None,
    ) -> AuditCheckpoint:
        assert event.sequence is not None
        unsigned = AuditCheckpoint(
            chain_id=event.chain_id,
            head_sequence=event.sequence,
            head_event_hash=event.event_hash,
            event_count=event.sequence,
            signing_key_id=event.key_id,
            previous_checkpoint_digest=previous.signature if previous is not None else "",
            signed_at=datetime.now(UTC),
        )
        return unsigned.model_copy(update={"signature": self._compute_checkpoint_hash(unsigned)})

    def _validate_checkpoint(
        self,
        tail: AuditEvent | None,
        checkpoint: AuditCheckpoint | None,
    ) -> None:
        if tail is None:
            if checkpoint is not None:
                raise AuditTamperDetectedError(event_index=0, event_id="<checkpoint>")
            return
        if tail.hash_schema_version < 3 and checkpoint is None:
            return
        if checkpoint is None or tail.sequence is None:
            raise AuditTamperDetectedError(event_index=0, event_id=tail.event_id)
        self._keyring.key_for_id(tail.key_id)
        expected_epoch = self._keyring.epoch_for_sequence(tail.sequence)
        if tail.key_id != expected_epoch.key_id:
            raise AuditTamperDetectedError(event_index=0, event_id=tail.event_id)
        expected = self._compute_checkpoint_hash(checkpoint)
        if (
            not hmac.compare_digest(checkpoint.signature, expected)
            or checkpoint.head_sequence != tail.sequence
            or checkpoint.event_count != tail.sequence
            or not hmac.compare_digest(checkpoint.head_event_hash, tail.event_hash)
            or checkpoint.signing_key_id != tail.key_id
            or checkpoint.chain_id != tail.chain_id
        ):
            raise AuditTamperDetectedError(event_index=0, event_id=tail.event_id)

    def _build_chained(
        self,
        event: AuditEvent,
        tail: AuditEvent | None,
        next_sequence: int,
        checkpoint: AuditCheckpoint | None,
    ) -> tuple[AuditEvent, AuditCheckpoint]:
        event = AuditEvent.model_validate(event.model_dump())
        self._validate_checkpoint(tail, checkpoint)
        if self._trusted_checkpoint is not None:
            trusted = self._trusted_checkpoint
            if (
                checkpoint is None
                or checkpoint.head_sequence < trusted.head_sequence
                or (
                    checkpoint.head_sequence == trusted.head_sequence
                    and checkpoint.head_event_hash != trusted.head_event_hash
                )
            ):
                raise AuditTamperDetectedError(
                    event_index=max(trusted.head_sequence - 1, 0),
                    event_id=tail.event_id if tail is not None else "<checkpoint>",
                )
        chain_id = (
            checkpoint.chain_id
            if checkpoint is not None
            else tail.chain_id
            if tail is not None and tail.chain_id
            else self._chain_id
        )
        epoch = self._keyring.epoch_for_sequence(next_sequence)
        chained = event.model_copy(
            update={
                "hash_schema_version": 8,
                "sequence": next_sequence,
                "key_id": epoch.key_id,
                "chain_id": chain_id,
                "prev_hash": tail.event_hash if tail is not None else "",
                "event_hash": "",
            }
        )
        chained = chained.model_copy(update={"event_hash": self._compute_hash(chained)})
        return chained, self._checkpoint_for(chained, checkpoint)

    async def _ensure_chain_initialized(self) -> None:
        """Restore _prev_hash from the last event on disk, if any."""
        if self._chain_initialized:
            return
        self._chain_initialized = True
        events = await self._backend.read_all()
        if events:
            self._prev_hash = events[-1].event_hash
            self._event_count = len(events)
            logger.debug(
                "audit_chain_restored",
                prev_hash=self._prev_hash,
                event_count=len(events),
            )

    async def write(self, event: AuditEvent) -> AuditEvent:
        """Write an event to the audit log with HMAC chain linking.

        Args:
            event: The audit event to write. event_hash and prev_hash
                   will be set automatically.

        Returns:
            The event with event_hash and prev_hash populated.
        """
        if (
            event.event_hash
            or event.prev_hash
            or event.sequence is not None
            or event.key_id
            or event.chain_id
        ):
            raise ValueError("audit chain integrity fields are assigned by the audit sink")
        if isinstance(self._backend, FileAuditBackend):
            chained, checkpoint = await self._backend.append_chained(event, self._build_chained)
            self._trusted_checkpoint = checkpoint
        else:
            async with self._write_lock:
                events = await self._backend.read_all()
                chained, checkpoint = self._build_chained(
                    event,
                    events[-1] if events else None,
                    len(events) + 1,
                    self._checkpoint_for(events[-1])
                    if events and events[-1].hash_schema_version >= 3
                    else None,
                )
                await self._backend.append(chained)
                self._trusted_checkpoint = checkpoint
        self._prev_hash = chained.event_hash
        self._event_count = chained.sequence or self._event_count + 1
        self._chain_initialized = True

        logger.info(
            "audit_event_logged",
            event_id=chained.event_id,
            action=chained.action,
            result=chained.result,
        )
        return chained

    async def write_once(self, event: AuditEvent) -> AuditEvent:
        """Commit one stable event ID once; reject a conflicting retry."""

        if (
            event.event_hash
            or event.prev_hash
            or event.sequence is not None
            or event.key_id
            or event.chain_id
        ):
            raise ValueError("audit chain integrity fields are assigned by the audit sink")
        if isinstance(self._backend, FileAuditBackend):
            chained, checkpoint = await self._backend.append_chained_once(
                event, self._build_chained
            )
            self._trusted_checkpoint = checkpoint
        else:
            async with self._write_lock:
                events = await self._backend.read_all()
                existing = next(
                    (item for item in events if item.event_id == event.event_id),
                    None,
                )
                if existing is not None:
                    if not hmac.compare_digest(
                        _event_fingerprint(existing), _event_fingerprint(event)
                    ):
                        raise AuditEventConflictError(event.event_id)
                    return existing
                chained, checkpoint = self._build_chained(
                    event,
                    events[-1] if events else None,
                    len(events) + 1,
                    self._checkpoint_for(events[-1])
                    if events and events[-1].hash_schema_version >= 3
                    else None,
                )
                await self._backend.append(chained)
                self._trusted_checkpoint = checkpoint
        self._prev_hash = chained.event_hash
        self._event_count = chained.sequence or self._event_count + 1
        self._chain_initialized = True
        logger.info(
            "audit_event_logged",
            event_id=chained.event_id,
            action=chained.action,
            result=chained.result,
        )
        return chained

    async def export_checkpoint(self) -> AuditCheckpoint | None:
        """Return the latest trusted head for out-of-band durable storage."""

        if self._trusted_checkpoint is not None:
            return self._trusted_checkpoint
        if isinstance(self._backend, FileAuditBackend):
            return await self._backend.read_checkpoint()
        return None

    async def verify_chain(self) -> ChainVerificationResult:
        """Verify the HMAC chain integrity of the entire audit log.

        Returns:
            ChainVerificationResult with valid=True if chain is intact.

        Raises:
            AuditTamperDetectedError: If tampering is detected.
        """
        if isinstance(self._backend, FileAuditBackend):
            events, checkpoint = await self._backend.read_state()
            return self._verify_state(events, checkpoint, checkpoint_supported=True)
        events = await self._backend.read_all()
        return self._verify_state(events, None, checkpoint_supported=False)

    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot:
        """Return one lock-consistent verified snapshot for reports and replay."""

        if isinstance(self._backend, FileAuditBackend):
            events, checkpoint = await self._backend.read_state()
            verification = self._verify_state(events, checkpoint, checkpoint_supported=True)
        else:
            events = await self._backend.read_all()
            verification = self._verify_state(events, None, checkpoint_supported=False)
        if require_checkpoint and not verification.attestable:
            event = events[-1] if events else None
            raise AuditTamperDetectedError(
                event_index=max(len(events) - 1, 0),
                event_id=event.event_id if event is not None else "<no-evidence>",
            )
        return VerifiedAuditSnapshot(events=tuple(events), verification=verification)

    def _verify_state(
        self,
        events: list[AuditEvent],
        checkpoint: AuditCheckpoint | None,
        *,
        checkpoint_supported: bool,
    ) -> ChainVerificationResult:
        if not events:
            if checkpoint is not None:
                raise AuditTamperDetectedError(event_index=0, event_id="<checkpoint>")
            return ChainVerificationResult(
                valid=True,
                event_count=0,
                checkpoint_status="empty",
            )

        prev_hash = ""
        seen_sequenced = False
        chain_id = ""
        for i, event in enumerate(events):
            self._reject_unsigned_schema_extensions(event, i)
            if event.hash_schema_version >= 3:
                assert event.sequence is not None
                self._keyring.key_for_id(event.key_id)
                expected_epoch = self._keyring.epoch_for_sequence(event.sequence)
                if event.key_id != expected_epoch.key_id:
                    raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)
            check_event = event.model_copy(update={"event_hash": "", "prev_hash": prev_hash})
            expected_hash = self._compute_hash(check_event)

            if not hmac.compare_digest(event.prev_hash, prev_hash):
                raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)

            if not hmac.compare_digest(event.event_hash, expected_hash):
                raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)

            if event.hash_schema_version >= 3:
                seen_sequenced = True
                if event.sequence != i + 1 or not event.chain_id:
                    raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)
                if chain_id and event.chain_id != chain_id:
                    raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)
                chain_id = event.chain_id
            elif seen_sequenced or event.sequence is not None or event.key_id or event.chain_id:
                raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)

            prev_hash = event.event_hash

        checkpoint_valid: bool | None = None
        checkpoint_status: Literal[
            "verified",
            "verified_unanchored",
            "legacy_uncheckpointed",
            "unsupported_backend",
            "empty",
        ]
        attestable = False
        if checkpoint_supported:
            self._validate_checkpoint(events[-1], checkpoint)
            checkpoint_valid = (
                checkpoint is not None if events[-1].hash_schema_version >= 3 else None
            )
            if checkpoint_valid:
                if self._trusted_checkpoint is None:
                    checkpoint_status = "verified_unanchored"
                else:
                    self._validate_trusted_checkpoint(events, self._trusted_checkpoint)
                    checkpoint_status = "verified"
                    attestable = True
            else:
                checkpoint_status = "legacy_uncheckpointed"
        else:
            checkpoint_status = "unsupported_backend"

        return ChainVerificationResult(
            valid=True,
            event_count=len(events),
            checkpoint_valid=checkpoint_valid,
            checkpoint_status=checkpoint_status,
            attestable=attestable,
            chain_id=chain_id,
            head_sequence=events[-1].sequence,
            head_event_hash=events[-1].event_hash,
        )

    def _validate_trusted_checkpoint(
        self,
        events: list[AuditEvent],
        trusted: AuditCheckpoint,
    ) -> None:
        """Verify an out-of-band checkpoint and its committed event in this history."""

        index = trusted.head_sequence - 1
        self._keyring.key_for_id(trusted.signing_key_id)
        if (
            trusted.head_sequence < 1
            or trusted.event_count != trusted.head_sequence
            or not hmac.compare_digest(
                trusted.signature,
                self._compute_checkpoint_hash(trusted),
            )
            or index >= len(events)
        ):
            raise AuditTamperDetectedError(
                event_index=max(index, 0),
                event_id="<trusted-checkpoint>",
            )
        anchored = events[index]
        if (
            anchored.hash_schema_version < 3
            or anchored.sequence != trusted.head_sequence
            or trusted.signing_key_id != anchored.key_id
            or anchored.event_hash != trusted.head_event_hash
            or anchored.chain_id != trusted.chain_id
        ):
            raise AuditTamperDetectedError(event_index=index, event_id=anchored.event_id)

    @staticmethod
    def _reject_unsigned_schema_extensions(event: AuditEvent, index: int) -> None:
        """Reject populated fields that are outside a legacy signed envelope."""

        if event.hash_schema_version < 4 and event.guardrail_evaluations:
            raise AuditTamperDetectedError(event_index=index, event_id=event.event_id)

        if event.hash_schema_version < 5 and event.hitl_evidence is not None:
            raise AuditTamperDetectedError(event_index=index, event_id=event.event_id)

        if event.hash_schema_version < 6 and event.reconciliation_evidence is not None:
            raise AuditTamperDetectedError(event_index=index, event_id=event.event_id)

        if event.hash_schema_version < 7 and event.authentication_evidence is not None:
            raise AuditTamperDetectedError(event_index=index, event_id=event.event_id)

        if event.hash_schema_version < 8 and event.registry_mutation_evidence is not None:
            raise AuditTamperDetectedError(event_index=index, event_id=event.event_id)

        if event.hash_schema_version == 1 and (
            event.invocation_id
            or event.event_type != "legacy"
            or event.reason_codes
            or event.payload_digest
            or event.payload_redacted
            or any(result.effect is not None for result in event.policy_results)
        ):
            raise AuditTamperDetectedError(event_index=index, event_id=event.event_id)

        if event.hash_schema_version in {1, 2} and (
            event.subject_ref is not None
            or event.policy_bundle_version
            or event.chain_mode != "enforce"
            or event.links
            or event.sequence is not None
            or event.key_id
            or event.chain_id
        ):
            raise AuditTamperDetectedError(event_index=index, event_id=event.event_id)
