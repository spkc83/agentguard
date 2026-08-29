"""Durable, tamper-evident state for human approval escalations.

The store persists only control-plane metadata and opaque, authenticated
continuation envelopes. Raw runtime payloads, results, credentials, and tokens
never belong here. Every public operation delegates blocking filesystem work
to a worker thread.
"""

from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_serializer,
    field_validator,
    model_validator,
)

from agentguard.compliance.continuation import ApprovalDisposition, SealedContinuation
from agentguard.exceptions import AgentGuardError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_SIGNATURE_DOMAIN = b"agentguard.escalation-store.v1\x00"


class EscalationStoreError(AgentGuardError):
    """Base error for durable escalation state."""


class EscalationNotFoundError(EscalationStoreError):
    """Raised when an escalation ID is unknown."""


class EscalationAlreadyExistsError(EscalationStoreError):
    """Raised when an escalation ID already exists."""


class EscalationTamperError(EscalationStoreError):
    """Raised when persisted escalation state is malformed or unauthenticated."""


class EscalationConflictError(EscalationStoreError):
    """Raised when a durable transition conflicts with an existing transition."""


class EscalationExpiredError(EscalationStoreError):
    """Raised when a token is presented at or after its expiration boundary."""


class EscalationStateError(EscalationStoreError):
    """Raised when an operation is invalid for the current durable state."""


class EscalationStatus(StrEnum):
    """Durable escalation lifecycle states."""

    PENDING = "pending"
    DECISION_PREPARED = "decision_prepared"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRY_PREPARED = "expiry_prepared"
    EXPIRED = "expired"
    CLAIMED = "claimed"
    DELIVERY_CLAIMED = "delivery_claimed"
    DELIVERED = "delivered"
    DELIVERY_DENIED = "delivery_denied"
    HANDED_OFF = "handed_off"


_TERMINAL_STATUSES = frozenset(
    {
        EscalationStatus.DENIED,
        EscalationStatus.EXPIRED,
        EscalationStatus.DELIVERED,
        EscalationStatus.DELIVERY_DENIED,
        EscalationStatus.HANDED_OFF,
    }
)
"""States no further transition can leave; everything else is still in flight."""


class ContinuationKind(StrEnum):
    """Execution boundary represented by an opaque continuation."""

    PRE_EXECUTION = "pre_execution"
    POST_DELIVERY = "post_delivery"


DecisionDisposition = ApprovalDisposition


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


class EscalationRecord(BaseModel):
    """Public durable state; it never exposes the token verifier or HMAC."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    escalation_id: Annotated[str, Field(min_length=1, max_length=256)]
    status: EscalationStatus
    revision: Annotated[int, Field(ge=0)]
    created_at: datetime
    expires_at: datetime
    continuation_kind: ContinuationKind | None = None

    _normalize_created_at = field_validator("created_at")(_utc)
    _normalize_expires_at = field_validator("expires_at")(_utc)


class CreatedEscalation(BaseModel):
    """One-time creation result containing the raw opaque token."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    record: EscalationRecord
    token: Annotated[str, Field(min_length=43, max_length=43)]


class PreparedDecision(BaseModel):
    """Stable transition material used to write idempotent decision evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    record: EscalationRecord
    decision_id: Annotated[str, Field(min_length=1, max_length=256)]
    disposition: ApprovalDisposition
    approver_id: Annotated[str, Field(min_length=1, max_length=256)]
    reason_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    decided_at: datetime
    sealed_continuation: SealedContinuation

    _normalize_decided_at = field_validator("decided_at")(_utc)


class ApprovedEscalation(BaseModel):
    """Approved opaque continuation returned before or during one-time claim."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    record: EscalationRecord
    sealed_continuation: SealedContinuation
    decision_id: Annotated[str, Field(min_length=1, max_length=256)]
    approver_id: Annotated[str, Field(min_length=1, max_length=256)]
    reason_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    decided_at: datetime
    claim_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    claimed_at: datetime | None = None

    _normalize_decided_at = field_validator("decided_at")(_utc)
    _normalize_claimed_at = field_validator("claimed_at")(
        lambda value: _utc(value) if value is not None else None
    )


class PostDeliveryEscalation(ApprovedEscalation):
    """Approved post-delivery continuation returned to its sole claimant."""


class _DecisionMetadata(BaseModel):
    """Redacted decision fields included in the signed v2 schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: Annotated[str, Field(min_length=1, max_length=256)]
    disposition: ApprovalDisposition
    approver_id: Annotated[str, Field(min_length=1, max_length=256)]
    reason_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    decided_at: datetime

    _normalize_decided_at = field_validator("decided_at")(_utc)


class _StoredEscalationV1(BaseModel):
    """Frozen Phase 3.4a signed on-disk schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    escalation_id: Annotated[str, Field(min_length=1, max_length=256)]
    token_verifier: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    status: EscalationStatus
    revision: Annotated[int, Field(ge=0)]
    created_at: datetime
    expires_at: datetime
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    _normalize_created_at = field_validator("created_at")(_utc)
    _normalize_expires_at = field_validator("expires_at")(_utc)

    def public(self) -> EscalationRecord:
        """Return the non-secret public view."""

        return EscalationRecord.model_validate(
            self.model_dump(exclude={"schema_version", "token_verifier", "signature"})
        )


class _StoredEscalationV2(BaseModel):
    """Exact resumable escalation schema; continuation content remains opaque."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[2] = 2
    escalation_id: Annotated[str, Field(min_length=1, max_length=256)]
    token_verifier: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    status: EscalationStatus
    revision: Annotated[int, Field(ge=0)]
    created_at: datetime
    expires_at: datetime
    continuation_kind: ContinuationKind = ContinuationKind.PRE_EXECUTION
    sealed_continuation: SealedContinuation
    decision: _DecisionMetadata | None = None
    claim_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    claimed_at: datetime | None = None
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    _normalize_created_at = field_validator("created_at")(_utc)
    _normalize_expires_at = field_validator("expires_at")(_utc)
    _normalize_claimed_at = field_validator("claimed_at")(
        lambda value: _utc(value) if value is not None else None
    )

    @field_validator("sealed_continuation", mode="before")
    @classmethod
    def _decode_sealed_continuation(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        decoded = dict(value)
        for field in ("nonce", "ciphertext"):
            encoded = decoded.get(field)
            if isinstance(encoded, str):
                try:
                    decoded[field] = base64.b64decode(encoded, altchars=b"-_", validate=True)
                except ValueError as exc:
                    raise ValueError(f"invalid sealed continuation {field}") from exc
        return decoded

    @field_serializer("sealed_continuation")
    def _encode_sealed_continuation(self, value: SealedContinuation) -> dict[str, object]:
        return EscalationStore._sealed_json(value)

    @model_validator(mode="after")
    def _validate_transition_shape(self) -> _StoredEscalationV2:
        decision_states = {
            EscalationStatus.DECISION_PREPARED,
            EscalationStatus.APPROVED,
            EscalationStatus.DENIED,
            EscalationStatus.CLAIMED,
            EscalationStatus.DELIVERY_CLAIMED,
            EscalationStatus.DELIVERED,
            EscalationStatus.DELIVERY_DENIED,
            EscalationStatus.HANDED_OFF,
        }
        if (self.status in decision_states) != (self.decision is not None):
            raise ValueError("decision metadata must match the durable state")
        if self.status is EscalationStatus.APPROVED and (
            self.decision is None or self.decision.disposition is not ApprovalDisposition.APPROVE
        ):
            raise ValueError("approved state requires an approval decision")
        if self.status is EscalationStatus.DENIED and (
            self.decision is None or self.decision.disposition is not ApprovalDisposition.DENY
        ):
            raise ValueError("denied state requires a denial decision")
        claimed_states = {
            EscalationStatus.CLAIMED,
            EscalationStatus.DELIVERY_CLAIMED,
            EscalationStatus.DELIVERED,
            EscalationStatus.DELIVERY_DENIED,
            EscalationStatus.HANDED_OFF,
        }
        if self.status in claimed_states and (
            self.decision is None or self.decision.disposition is not ApprovalDisposition.APPROVE
        ):
            raise ValueError("claimed state requires an approval decision")
        if (
            self.status is EscalationStatus.CLAIMED
            and self.continuation_kind is not ContinuationKind.PRE_EXECUTION
        ):
            raise ValueError("execution claims require a pre-execution continuation")
        if (
            self.status in claimed_states - {EscalationStatus.CLAIMED}
            and self.continuation_kind is not ContinuationKind.POST_DELIVERY
        ):
            raise ValueError("delivery states require a post-delivery continuation")
        claimed = self.status in claimed_states
        if claimed != (self.claim_id is not None and self.claimed_at is not None):
            raise ValueError("claim metadata must match the claimed state")
        if not claimed and (self.claim_id is not None or self.claimed_at is not None):
            raise ValueError("claim metadata is only valid for claimed state")
        return self

    def public(self) -> EscalationRecord:
        """Return the non-secret public view."""

        return EscalationRecord(
            escalation_id=self.escalation_id,
            status=self.status,
            revision=self.revision,
            created_at=self.created_at,
            expires_at=self.expires_at,
            continuation_kind=self.continuation_kind,
        )


_StoredEscalation = _StoredEscalationV1 | _StoredEscalationV2


class EscalationStore:
    """File-backed pending-request state with process-safe TTL materialization.

    Args:
        directory: Dedicated state directory. It is forced to mode ``0700``.
        signing_key: Explicit HMAC-SHA256 key of at least 256 bits.
        clock: Trusted UTC clock dependency; intended for deterministic tests.
    """

    def __init__(
        self,
        directory: Path,
        *,
        signing_key: bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 256 bits")
        self._directory = directory
        self._signing_key = bytes(signing_key)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._prepare_directory()

    async def create(
        self,
        escalation_id: str,
        *,
        ttl: timedelta,
        sealed_continuation: SealedContinuation | None = None,
        continuation_kind: ContinuationKind = ContinuationKind.PRE_EXECUTION,
    ) -> CreatedEscalation:
        """Create pending state and return its non-recoverable opaque token."""

        if sealed_continuation is None:
            return await asyncio.to_thread(self._create_sync, escalation_id, ttl)
        return await asyncio.to_thread(
            self._create_sync,
            escalation_id,
            ttl,
            sealed_continuation,
            continuation_kind,
        )

    async def get(self, escalation_id: str) -> EscalationRecord:
        """Read authenticated state, materializing expiry when necessary."""

        return await asyncio.to_thread(self._get_sync, escalation_id)

    async def attach_continuation(
        self,
        escalation_id: str,
        *,
        token: str,
        sealed_continuation: SealedContinuation,
        continuation_kind: ContinuationKind = ContinuationKind.PRE_EXECUTION,
    ) -> EscalationRecord:
        """Upgrade a reserved pending request to resumable schema v2.

        The kernel reserves the request first so the protected continuation can
        bind the store's exact creation and expiry timestamps. The raw token is
        still process-local and has not escaped to a caller at this point.
        """

        return await asyncio.to_thread(
            self._attach_continuation_sync,
            escalation_id,
            token,
            sealed_continuation,
            continuation_kind,
        )

    async def list_records(self) -> tuple[EscalationRecord, ...]:
        """Read all authenticated records in deterministic escalation-ID order."""

        return await asyncio.to_thread(self._list_sync)

    async def prune_terminal(self, older_than: datetime) -> int:
        """Delete terminal escalation records last touched before a cutoff.

        Operator-invoked only; nothing prunes in the background. A record is
        removed only when its durable state is terminal — a decided denial, a
        committed expiry, or a committed delivery outcome — and every timestamp
        it carries predates the cutoff. Pending, approved, prepared, and claimed
        records are in flight and are never removed, regardless of age.

        Args:
            older_than: Timezone-aware UTC cutoff; records at or after it stay.

        Returns:
            The number of records deleted.

        Raises:
            ValueError: If the cutoff is not timezone-aware.
            EscalationTamperError: If a record in the directory is unauthentic.
        """

        return await asyncio.to_thread(self._prune_terminal_sync, older_than)

    async def prepare_decision(
        self,
        escalation_id: str,
        *,
        token: str,
        decision_id: str,
        disposition: ApprovalDisposition,
        approver_id: str,
        reason_digest: str,
    ) -> PreparedDecision:
        """Persist authenticated decision metadata before its audit event."""

        return await asyncio.to_thread(
            self._prepare_decision_sync,
            escalation_id,
            token,
            decision_id,
            disposition,
            approver_id,
            reason_digest,
        )

    async def commit_decision(self, escalation_id: str, *, decision_id: str) -> EscalationRecord:
        """Make a prepared decision effective after its signed audit event exists."""

        return await asyncio.to_thread(self._commit_decision_sync, escalation_id, decision_id)

    async def inspect_approved(self, escalation_id: str, *, token: str) -> ApprovedEscalation:
        """Read an approved continuation without claiming execution ownership."""

        return await asyncio.to_thread(self._inspect_approved_sync, escalation_id, token)

    async def get_sealed_continuation(self, escalation_id: str) -> SealedContinuation:
        """Return only the opaque envelope for trusted lifecycle reconciliation."""

        return await asyncio.to_thread(self._get_sealed_continuation_sync, escalation_id)

    async def inspect_claimed(self, escalation_id: str) -> ApprovedEscalation:
        """Return authenticated claim metadata for trusted reconciliation only."""

        return await asyncio.to_thread(self._inspect_claimed_sync, escalation_id)

    async def claim_approved(self, escalation_id: str, *, token: str) -> ApprovedEscalation:
        """Atomically claim an approved continuation exactly once."""

        return await asyncio.to_thread(self._claim_approved_sync, escalation_id, token)

    async def claim_post_delivery(
        self, escalation_id: str, *, token: str
    ) -> PostDeliveryEscalation:
        """Atomically claim approved post-delivery work exactly once."""

        return await asyncio.to_thread(self._claim_post_delivery_sync, escalation_id, token)

    async def commit_delivered(self, escalation_id: str, *, claim_id: str) -> EscalationRecord:
        """Commit a successfully audited delivery terminal."""

        return await asyncio.to_thread(
            self._commit_delivery_sync,
            escalation_id,
            claim_id,
            EscalationStatus.DELIVERED,
        )

    async def commit_delivery_denied(
        self, escalation_id: str, *, claim_id: str
    ) -> EscalationRecord:
        """Commit an audited denial of delivery."""

        return await asyncio.to_thread(
            self._commit_delivery_sync,
            escalation_id,
            claim_id,
            EscalationStatus.DELIVERY_DENIED,
        )

    async def commit_handoff(self, escalation_id: str, *, claim_id: str) -> EscalationRecord:
        """Commit an audited handoff to external reconciliation."""

        return await asyncio.to_thread(
            self._commit_delivery_sync,
            escalation_id,
            claim_id,
            EscalationStatus.HANDED_OFF,
        )

    async def prepare_expiry(self, escalation_id: str) -> EscalationRecord:
        """Persist resumable expiry intent before its signed audit event."""

        return await asyncio.to_thread(self._prepare_expiry_sync, escalation_id)

    async def commit_expiry(self, escalation_id: str) -> EscalationRecord:
        """Make a prepared resumable expiry effective after audit."""

        return await asyncio.to_thread(self._commit_expiry_sync, escalation_id)

    def _prepare_directory(self) -> None:
        try:
            metadata = self._directory.lstat()
        except FileNotFoundError:
            self._directory.mkdir(parents=True, mode=0o700)
            metadata = self._directory.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise EscalationStoreError("escalation directory must be a real directory")
        os.chmod(self._directory, 0o700, follow_symlinks=False)

    def _create_sync(
        self,
        escalation_id: str,
        ttl: timedelta,
        sealed_continuation: SealedContinuation | None = None,
        continuation_kind: ContinuationKind = ContinuationKind.PRE_EXECUTION,
    ) -> CreatedEscalation:
        self._validate_identifier(escalation_id, "escalation_id")
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        created_at = self._now()
        token = secrets.token_urlsafe(32)
        unsigned: dict[str, object] = {
            "schema_version": 1 if sealed_continuation is None else 2,
            "escalation_id": escalation_id,
            "token_verifier": self._token_verifier(token),
            "status": EscalationStatus.PENDING,
            "revision": 0,
            "created_at": created_at,
            "expires_at": created_at + ttl,
        }
        if sealed_continuation is not None:
            unsigned["continuation_kind"] = continuation_kind
            unsigned["sealed_continuation"] = self._sealed_json(sealed_continuation)
            unsigned["decision"] = None
        record = self._sign(unsigned)
        with self._locked():
            try:
                self._record_path(escalation_id).lstat()
            except FileNotFoundError:
                pass
            else:
                raise EscalationAlreadyExistsError(escalation_id)
            self._write_record(record)
        return CreatedEscalation(record=record.public(), token=token)

    def _get_sync(self, escalation_id: str) -> EscalationRecord:
        self._validate_identifier(escalation_id, "escalation_id")
        current_time = self._now()
        with self._locked():
            record = self._read_record(escalation_id)
            if isinstance(record, _StoredEscalationV1):
                record = self._expire_v1_if_due(record, current_time)
            return record.public()

    def _attach_continuation_sync(
        self,
        escalation_id: str,
        token: str,
        sealed_continuation: SealedContinuation,
        continuation_kind: ContinuationKind,
    ) -> EscalationRecord:
        self._validate_identifier(escalation_id, "escalation_id")
        with self._locked():
            record = self._read_record(escalation_id)
            self._verify_token(record, token)
            if isinstance(record, _StoredEscalationV2):
                if (
                    record.sealed_continuation != sealed_continuation
                    or record.continuation_kind is not continuation_kind
                ):
                    raise EscalationConflictError(
                        f"conflicting continuation for escalation {escalation_id}"
                    )
                return record.public()
            if record.status is not EscalationStatus.PENDING:
                raise EscalationStateError(
                    f"continuation cannot be attached from state {record.status.value}"
                )
            if self._now() >= record.expires_at:
                raise EscalationExpiredError(escalation_id)
            upgraded = self._sign(
                {
                    "schema_version": 2,
                    "escalation_id": record.escalation_id,
                    "token_verifier": record.token_verifier,
                    "status": EscalationStatus.PENDING,
                    "revision": record.revision + 1,
                    "created_at": record.created_at,
                    "expires_at": record.expires_at,
                    "continuation_kind": continuation_kind,
                    "sealed_continuation": self._sealed_json(sealed_continuation),
                    "decision": None,
                }
            )
            assert isinstance(upgraded, _StoredEscalationV2)
            self._write_record(upgraded)
            return upgraded.public()

    def _list_sync(self) -> tuple[EscalationRecord, ...]:
        current_time = self._now()
        records: list[EscalationRecord] = []
        with self._locked():
            for path in sorted(self._directory.glob("*.json")):
                if path.is_symlink():
                    raise EscalationTamperError(f"symlinked escalation record: {path.name}")
                record = self._read_path(path)
                if isinstance(record, _StoredEscalationV1):
                    record = self._expire_v1_if_due(record, current_time)
                records.append(record.public())
        return tuple(sorted(records, key=lambda record: record.escalation_id))

    def _prune_terminal_sync(self, older_than: datetime) -> int:
        cutoff = _utc(older_than)
        removed = 0
        with self._locked():
            try:
                for path in sorted(self._directory.glob("*.json")):
                    if path.is_symlink():
                        raise EscalationTamperError(f"symlinked escalation record: {path.name}")
                    record = self._read_path(path)
                    if record.status not in _TERMINAL_STATUSES:
                        continue
                    if self._last_touched(record) >= cutoff:
                        continue
                    path.unlink()
                    removed += 1
            finally:
                # An unauthentic record aborts the sweep; whatever was already
                # unlinked still has to reach the disk.
                if removed:
                    directory_fd = os.open(self._directory, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
        return removed

    @staticmethod
    def _last_touched(record: _StoredEscalation) -> datetime:
        """Latest timestamp the signed record carries.

        The schema stamps creation, expiry, decision, and claim times but not
        delivery, so a record delivered long after it expired reports the expiry
        as its last touch. Retention windows are therefore measured from the
        approval lifecycle, not from delivery.
        """

        timestamps = [record.created_at, record.expires_at]
        if isinstance(record, _StoredEscalationV2):
            if record.decision is not None:
                timestamps.append(record.decision.decided_at)
            if record.claimed_at is not None:
                timestamps.append(record.claimed_at)
        return max(timestamps)

    def _expire_v1_if_due(self, record: _StoredEscalationV1, now: datetime) -> _StoredEscalationV1:
        if record.status is not EscalationStatus.PENDING:
            return record
        if now < record.expires_at:
            return record
        expired = self._replace(record, status=EscalationStatus.EXPIRED)
        assert isinstance(expired, _StoredEscalationV1)
        self._write_record(expired)
        return expired

    def _prepare_decision_sync(
        self,
        escalation_id: str,
        token: str,
        decision_id: str,
        disposition: ApprovalDisposition,
        approver_id: str,
        reason_digest: str,
    ) -> PreparedDecision:
        self._validate_identifier(escalation_id, "escalation_id")
        self._validate_identifier(decision_id, "decision_id")
        self._validate_identifier(approver_id, "approver_id")
        metadata = _DecisionMetadata(
            decision_id=decision_id,
            disposition=disposition,
            approver_id=approver_id,
            reason_digest=reason_digest,
            decided_at=self._now(),
        )
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            self._verify_token(record, token)
            if record.decision is not None:
                if not self._same_decision(record.decision, metadata):
                    raise EscalationConflictError(
                        f"conflicting decision for escalation {escalation_id}"
                    )
                if record.status not in {
                    EscalationStatus.DECISION_PREPARED,
                    EscalationStatus.APPROVED,
                    EscalationStatus.DENIED,
                }:
                    raise EscalationStateError(
                        f"decision cannot be retried from state {record.status.value}"
                    )
                return self._prepared(record)
            if record.status is not EscalationStatus.PENDING:
                raise EscalationStateError(
                    f"decision cannot be prepared from state {record.status.value}"
                )
            if metadata.decided_at >= record.expires_at:
                raise EscalationExpiredError(escalation_id)
            prepared = self._replace(
                record,
                status=EscalationStatus.DECISION_PREPARED,
                decision=metadata,
            )
            assert isinstance(prepared, _StoredEscalationV2)
            self._write_record(prepared)
            return self._prepared(prepared)

    def _commit_decision_sync(self, escalation_id: str, decision_id: str) -> EscalationRecord:
        self._validate_identifier(escalation_id, "escalation_id")
        self._validate_identifier(decision_id, "decision_id")
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            decision = record.decision
            if decision is None or not hmac.compare_digest(decision.decision_id, decision_id):
                raise EscalationConflictError(
                    f"decision ID does not match escalation {escalation_id}"
                )
            target = (
                EscalationStatus.APPROVED
                if decision.disposition is ApprovalDisposition.APPROVE
                else EscalationStatus.DENIED
            )
            if record.status is target:
                return record.public()
            if record.status is not EscalationStatus.DECISION_PREPARED:
                raise EscalationStateError(
                    f"decision cannot be committed from state {record.status.value}"
                )
            committed = self._replace(record, status=target)
            assert isinstance(committed, _StoredEscalationV2)
            self._write_record(committed)
            return committed.public()

    def _inspect_approved_sync(self, escalation_id: str, token: str) -> ApprovedEscalation:
        self._validate_identifier(escalation_id, "escalation_id")
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            self._verify_token(record, token)
            if self._now() >= record.expires_at:
                raise EscalationExpiredError(escalation_id)
            if record.status is not EscalationStatus.APPROVED:
                raise EscalationStateError(f"continuation is not approved: {record.status.value}")
            return self._approved(record)

    def _get_sealed_continuation_sync(self, escalation_id: str) -> SealedContinuation:
        self._validate_identifier(escalation_id, "escalation_id")
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            return record.sealed_continuation

    def _inspect_claimed_sync(self, escalation_id: str) -> ApprovedEscalation:
        self._validate_identifier(escalation_id, "escalation_id")
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            if record.status not in {
                EscalationStatus.CLAIMED,
                EscalationStatus.DELIVERY_CLAIMED,
                EscalationStatus.DELIVERED,
                EscalationStatus.DELIVERY_DENIED,
                EscalationStatus.HANDED_OFF,
            }:
                raise EscalationStateError(f"continuation is not claimed: {record.status.value}")
            return self._approved(record)

    def _claim_approved_sync(self, escalation_id: str, token: str) -> ApprovedEscalation:
        self._validate_identifier(escalation_id, "escalation_id")
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            self._verify_token(record, token)
            if record.continuation_kind is not ContinuationKind.PRE_EXECUTION:
                raise EscalationStateError(
                    "post-delivery continuations require claim_post_delivery"
                )
            if self._now() >= record.expires_at:
                raise EscalationExpiredError(escalation_id)
            if record.status is not EscalationStatus.APPROVED:
                raise EscalationStateError(
                    f"continuation cannot be claimed from state {record.status.value}"
                )
            assert record.decision is not None
            claim_digest = hashlib.sha256(
                f"{record.escalation_id}\0{record.decision.decision_id}".encode()
            ).hexdigest()
            claimed = self._replace(
                record,
                status=EscalationStatus.CLAIMED,
                claim_id=f"claim:{claim_digest}",
                claimed_at=self._now(),
            )
            assert isinstance(claimed, _StoredEscalationV2)
            self._write_record(claimed)
            return self._approved(claimed)

    def _claim_post_delivery_sync(self, escalation_id: str, token: str) -> PostDeliveryEscalation:
        self._validate_identifier(escalation_id, "escalation_id")
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            self._verify_token(record, token)
            if record.continuation_kind is not ContinuationKind.POST_DELIVERY:
                raise EscalationStateError("pre-execution continuations require claim_approved")
            if self._now() >= record.expires_at:
                raise EscalationExpiredError(escalation_id)
            if record.status is not EscalationStatus.APPROVED:
                raise EscalationStateError(
                    f"post-delivery continuation cannot be claimed from state {record.status.value}"
                )
            assert record.decision is not None
            claim_digest = hashlib.sha256(
                f"delivery\0{record.escalation_id}\0{record.decision.decision_id}".encode()
            ).hexdigest()
            claimed = self._replace(
                record,
                status=EscalationStatus.DELIVERY_CLAIMED,
                claim_id=f"delivery-claim:{claim_digest}",
                claimed_at=self._now(),
            )
            assert isinstance(claimed, _StoredEscalationV2)
            self._write_record(claimed)
            return self._post_delivery(claimed)

    def _commit_delivery_sync(
        self,
        escalation_id: str,
        claim_id: str,
        target: EscalationStatus,
    ) -> EscalationRecord:
        self._validate_identifier(escalation_id, "escalation_id")
        self._validate_identifier(claim_id, "claim_id")
        if target not in {
            EscalationStatus.DELIVERED,
            EscalationStatus.DELIVERY_DENIED,
            EscalationStatus.HANDED_OFF,
        }:
            raise ValueError("invalid post-delivery terminal state")
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            if record.continuation_kind is not ContinuationKind.POST_DELIVERY:
                raise EscalationStateError("continuation is not post-delivery work")
            if record.claim_id is None or not hmac.compare_digest(record.claim_id, claim_id):
                raise EscalationConflictError(f"claim ID does not match escalation {escalation_id}")
            if record.status is target:
                return record.public()
            if record.status in {
                EscalationStatus.DELIVERED,
                EscalationStatus.DELIVERY_DENIED,
                EscalationStatus.HANDED_OFF,
            }:
                raise EscalationConflictError(
                    f"conflicting delivery terminal for escalation {escalation_id}"
                )
            if record.status is not EscalationStatus.DELIVERY_CLAIMED:
                raise EscalationStateError(
                    f"delivery cannot be committed from state {record.status.value}"
                )
            committed = self._replace(record, status=target)
            assert isinstance(committed, _StoredEscalationV2)
            self._write_record(committed)
            return committed.public()

    def _prepare_expiry_sync(self, escalation_id: str) -> EscalationRecord:
        self._validate_identifier(escalation_id, "escalation_id")
        now = self._now()
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            if record.status in {
                EscalationStatus.EXPIRY_PREPARED,
                EscalationStatus.EXPIRED,
            }:
                return record.public()
            if record.status not in {
                EscalationStatus.PENDING,
                EscalationStatus.APPROVED,
            }:
                raise EscalationStateError(
                    f"expiry cannot be prepared from state {record.status.value}"
                )
            if now < record.expires_at:
                raise EscalationStateError("escalation has not expired")
            prepared = self._replace(
                record,
                status=EscalationStatus.EXPIRY_PREPARED,
                decision=None,
            )
            assert isinstance(prepared, _StoredEscalationV2)
            self._write_record(prepared)
            return prepared.public()

    def _commit_expiry_sync(self, escalation_id: str) -> EscalationRecord:
        self._validate_identifier(escalation_id, "escalation_id")
        with self._locked():
            record = self._require_v2(self._read_record(escalation_id))
            if record.status is EscalationStatus.EXPIRED:
                return record.public()
            if record.status is not EscalationStatus.EXPIRY_PREPARED:
                raise EscalationStateError(
                    f"expiry cannot be committed from state {record.status.value}"
                )
            expired = self._replace(record, status=EscalationStatus.EXPIRED)
            assert isinstance(expired, _StoredEscalationV2)
            self._write_record(expired)
            return expired.public()

    @staticmethod
    def _require_v2(record: _StoredEscalation) -> _StoredEscalationV2:
        if not isinstance(record, _StoredEscalationV2):
            raise EscalationStateError("legacy escalation is not resumable")
        return record

    @staticmethod
    def _same_decision(existing: _DecisionMetadata, requested: _DecisionMetadata) -> bool:
        return (
            existing.decision_id == requested.decision_id
            and existing.disposition is requested.disposition
            and existing.approver_id == requested.approver_id
            and existing.reason_digest == requested.reason_digest
        )

    @staticmethod
    def _prepared(record: _StoredEscalationV2) -> PreparedDecision:
        decision = record.decision
        assert decision is not None
        return PreparedDecision(
            record=record.public(),
            **decision.model_dump(),
            sealed_continuation=record.sealed_continuation,
        )

    @staticmethod
    def _approved(record: _StoredEscalationV2) -> ApprovedEscalation:
        decision = record.decision
        assert decision is not None
        return ApprovedEscalation(
            record=record.public(),
            sealed_continuation=record.sealed_continuation,
            decision_id=decision.decision_id,
            approver_id=decision.approver_id,
            reason_digest=decision.reason_digest,
            decided_at=decision.decided_at,
            claim_id=record.claim_id,
            claimed_at=record.claimed_at,
        )

    @staticmethod
    def _post_delivery(record: _StoredEscalationV2) -> PostDeliveryEscalation:
        return PostDeliveryEscalation.model_validate(EscalationStore._approved(record).model_dump())

    @staticmethod
    def _verify_token(record: _StoredEscalation, token: str) -> None:
        presented = EscalationStore._token_verifier(token)
        if not hmac.compare_digest(record.token_verifier, presented):
            raise EscalationStateError("invalid escalation token")

    def _replace(self, record: _StoredEscalation, **updates: object) -> _StoredEscalation:
        mode = "python" if isinstance(record, _StoredEscalationV1) else "json"
        payload = record.model_dump(mode=mode, exclude={"signature"})
        payload.update(updates)
        payload["revision"] = record.revision + 1
        return self._sign(payload)

    @staticmethod
    def _validate_identifier(value: str, field: str) -> None:
        if not value or len(value) > 256:
            raise ValueError(f"{field} must contain between 1 and 256 characters")

    def _read_record(self, escalation_id: str) -> _StoredEscalation:
        path = self._record_path(escalation_id)
        try:
            return self._read_path(path)
        except EscalationNotFoundError as exc:
            raise EscalationNotFoundError(escalation_id) from exc

    def _read_path(self, path: Path) -> _StoredEscalation:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError as exc:
            raise EscalationNotFoundError(path.name) from exc
        except OSError as exc:
            raise EscalationTamperError(f"unsafe escalation record: {path.name}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise EscalationTamperError(f"unsafe escalation record mode: {path.name}")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read()
        finally:
            os.close(descriptor)
        try:
            raw = json.loads(payload)
            if not isinstance(raw, dict):
                raise ValueError("record must be an object")
            schema_version = raw.get("schema_version")
            if schema_version == 1:
                record: _StoredEscalation = _StoredEscalationV1.model_validate(raw)
            elif schema_version == 2:
                record = _StoredEscalationV2.model_validate(raw)
            else:
                raise ValueError("unsupported escalation schema")
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise EscalationTamperError(f"invalid escalation record: {path.name}") from exc
        mode = "python" if isinstance(record, _StoredEscalationV1) else "json"
        signed_payload = record.model_dump(mode=mode, exclude={"signature"})
        expected = self._signature(signed_payload)
        if (
            not hmac.compare_digest(expected, record.signature)
            and isinstance(record, _StoredEscalationV2)
            and "continuation_kind" not in raw
        ):
            # Phase 3.4b v2 records predate the signed discriminator. They are
            # unambiguously pre-execution records and become explicitly tagged
            # on their next transition.
            signed_payload.pop("continuation_kind")
            expected = self._signature(signed_payload)
        if not hmac.compare_digest(expected, record.signature):
            raise EscalationTamperError(f"invalid escalation signature: {path.name}")
        expected_path = self._record_path(record.escalation_id)
        if expected_path.name != path.name:
            raise EscalationTamperError(f"escalation ID/path mismatch: {path.name}")
        return record

    def _write_record(self, record: _StoredEscalation) -> None:
        destination = self._record_path(record.escalation_id)
        payload = record.model_dump_json().encode("utf-8")
        temporary_path = ""
        try:
            descriptor, temporary_path = tempfile.mkstemp(
                prefix=".escalation-", dir=self._directory
            )
            os.fchmod(descriptor, 0o600)
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("escalation write made no forward progress")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary_path, destination)
            temporary_path = ""
            directory_fd = os.open(self._directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary_path:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_path)

    def _record_path(self, escalation_id: str) -> Path:
        digest = hashlib.sha256(escalation_id.encode("utf-8")).hexdigest()
        return self._directory / f"{digest}.json"

    def _now(self) -> datetime:
        return _utc(self._clock())

    def _sign(self, payload: dict[str, object]) -> _StoredEscalation:
        if payload.get("schema_version") == 1:
            signed = dict(payload)
            signed["signature"] = self._signature(payload)
            return _StoredEscalationV1.model_validate(signed)
        if payload.get("schema_version") == 2:
            draft = _StoredEscalationV2.model_validate({**payload, "signature": "0" * 64})
            canonical = draft.model_dump(mode="json", exclude={"signature"})
            return _StoredEscalationV2.model_validate(
                {**canonical, "signature": self._signature(canonical)}
            )
        raise ValueError("unsupported escalation schema")

    def _signature(self, payload: dict[str, object]) -> str:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=self._json_default,
        ).encode("utf-8")
        # Domain-separated so a record signed here can never verify as an
        # execution-journal record (or vice versa) under a shared key.
        return hmac.new(
            self._signing_key, _SIGNATURE_DOMAIN + canonical, hashlib.sha256
        ).hexdigest()

    @staticmethod
    def _json_default(value: object) -> object:
        if isinstance(value, BaseModel):
            return value.model_dump(mode="json")
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Enum):
            return str(value.value)
        raise TypeError(f"not JSON serializable: {type(value).__name__}")

    @staticmethod
    def _token_verifier(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _sealed_json(sealed: SealedContinuation) -> dict[str, object]:
        return {
            "schema_version": sealed.schema_version,
            "kind": sealed.kind,
            "algorithm": sealed.algorithm,
            "key_id": sealed.key_id,
            "nonce": base64.urlsafe_b64encode(sealed.nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(sealed.ciphertext).decode("ascii"),
        }

    class _Lock:
        def __init__(self, directory: Path) -> None:
            self._path = directory / ".escalations.lock"
            self._descriptor = -1

        def __enter__(self) -> None:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            try:
                self._descriptor = os.open(self._path, flags, 0o600)
            except OSError as exc:
                raise EscalationStoreError("could not open escalation lock safely") from exc
            try:
                os.fchmod(self._descriptor, 0o600)
                fcntl.flock(self._descriptor, fcntl.LOCK_EX)
            except BaseException:
                os.close(self._descriptor)
                self._descriptor = -1
                raise

        def __exit__(self, *args: object) -> None:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._descriptor)

    def _locked(self) -> EscalationStore._Lock:
        return self._Lock(self._directory)


__all__ = [
    "ApprovedEscalation",
    "ContinuationKind",
    "CreatedEscalation",
    "DecisionDisposition",
    "EscalationAlreadyExistsError",
    "EscalationConflictError",
    "EscalationExpiredError",
    "EscalationNotFoundError",
    "EscalationRecord",
    "EscalationStateError",
    "EscalationStatus",
    "EscalationStore",
    "EscalationStoreError",
    "EscalationTamperError",
    "PreparedDecision",
    "PostDeliveryEscalation",
]
