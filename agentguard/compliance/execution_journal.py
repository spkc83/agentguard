"""Durable protected outcomes for resumable governed executions.

The journal records the control-plane boundary around an already-claimed HITL
continuation. Exact executor output is stored only inside an application-
protected authenticated-encryption envelope; executor references and raw
payloads never belong in the journal.
"""

from __future__ import annotations

import asyncio
import base64
import fcntl
import hashlib
import hmac
import json
import os
import stat
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
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

from agentguard.compliance.continuation import (
    ContinuationProtector,
    PostExecutionContinuation,
    SealedContinuation,
)
from agentguard.exceptions import AgentGuardError
from agentguard.guardrails.normalization import canonical_json_bytes

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_SIGNATURE_DOMAIN = b"agentguard.execution-journal.v1\x00"


class ExecutionJournalError(AgentGuardError):
    """Base error for protected execution-journal state."""


class ExecutionJournalNotFoundError(ExecutionJournalError):
    """Raised when a journal key is unknown."""


class ExecutionJournalAlreadyExistsError(ExecutionJournalError):
    """Raised when a journal key is reused with different bindings."""


class ExecutionJournalConflictError(ExecutionJournalError):
    """Raised when a retry conflicts with a durable transition."""


class ExecutionJournalStateError(ExecutionJournalError):
    """Raised when a transition is illegal from the durable state."""


class ExecutionJournalTamperError(ExecutionJournalError):
    """Raised when persisted state or protected outcome is unauthenticated."""


class ExecutionJournalStatus(StrEnum):
    """Durable lifecycle of a claimed governed execution."""

    CLAIMED = "claimed"
    ADMITTED = "admitted"
    OUTCOME_PROTECTED = "outcome_protected"
    COMPLETION_AUDITED = "completion_audited"
    POST_PROCESSING_CLAIMED = "post_processing_claimed"
    IN_DOUBT_PREPARED = "in_doubt_prepared"
    IN_DOUBT = "in_doubt"
    RECONCILIATION_PREPARED = "reconciliation_prepared"
    RECONCILED_DENIED = "reconciled_denied"
    DELIVERED = "delivered"
    DELIVERY_DENIED = "delivery_denied"
    HANDED_OFF = "handed_off"


_TERMINAL_STATUSES = frozenset(
    {
        ExecutionJournalStatus.DELIVERED,
        ExecutionJournalStatus.DELIVERY_DENIED,
        ExecutionJournalStatus.HANDED_OFF,
        ExecutionJournalStatus.RECONCILED_DENIED,
    }
)
"""Resolved states; claimed, admitted, prepared, and in-doubt entries are live."""


class InDoubtClassification(StrEnum):
    """Verified missing-boundary classification used for reconciliation."""

    CLAIMED_WITHOUT_TERMINAL = "claimed_without_terminal"
    ADMISSION_WITHOUT_COMPLETION = "admission_without_completion"
    COMPLETION_WITHOUT_PROTECTED_RESULT = "completion_without_protected_result"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


class ProtectedExecutionOutcome(BaseModel):
    """Complete protected state needed to resume post-processing without an executor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    kind: Literal["protected_execution_outcome"] = "protected_execution_outcome"
    escalation_id: Annotated[str, Field(min_length=1, max_length=256)]
    claim_id: Annotated[str, Field(min_length=1, max_length=256)]
    invocation_id: Annotated[str, Field(min_length=1, max_length=256)]
    admission_payload_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    policy_bundle_version: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    chain_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    continuation: PostExecutionContinuation

    @model_validator(mode="after")
    def _validate_bound_continuation(self) -> ProtectedExecutionOutcome:
        if (
            self.continuation.escalation_id != self.escalation_id
            or self.continuation.invocation_id != self.invocation_id
        ):
            raise ValueError("post-execution continuation does not match journal key")
        if self.continuation.guardrail_cursor is not None:
            raise ValueError("journal outcomes must resume post-processing from its start")
        if (
            self.continuation.policy_bundle_version != self.policy_bundle_version
            or self.continuation.chain_fingerprint != self.chain_fingerprint
        ):
            raise ValueError("post-execution continuation does not match journal bindings")
        return self


class ExecutionJournalRecord(BaseModel):
    """Authenticated public metadata for one journal entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    escalation_id: Annotated[str, Field(min_length=1, max_length=256)]
    claim_id: Annotated[str, Field(min_length=1, max_length=256)]
    invocation_id: Annotated[str, Field(min_length=1, max_length=256)]
    status: ExecutionJournalStatus
    revision: Annotated[int, Field(ge=0)]
    payload_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    policy_bundle_version: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    chain_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    created_at: datetime
    admitted_at: datetime | None = None
    outcome_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    execution_completed_at: datetime | None = None
    completion_audited_at: datetime | None = None
    in_doubt_classification: InDoubtClassification | None = None
    in_doubt_at: datetime | None = None
    reconciliation_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    reconciler_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    reason_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    reconciled_at: datetime | None = None

    _normalize_created_at = field_validator("created_at")(_utc)
    _normalize_admitted_at = field_validator("admitted_at")(
        lambda value: _utc(value) if value is not None else None
    )
    _normalize_execution_completed_at = field_validator("execution_completed_at")(
        lambda value: _utc(value) if value is not None else None
    )
    _normalize_completion_audited_at = field_validator("completion_audited_at")(
        lambda value: _utc(value) if value is not None else None
    )
    _normalize_in_doubt_at = field_validator("in_doubt_at")(
        lambda value: _utc(value) if value is not None else None
    )
    _normalize_reconciled_at = field_validator("reconciled_at")(
        lambda value: _utc(value) if value is not None else None
    )


class _StoredExecutionJournal(BaseModel):
    """Frozen signed v1 on-disk schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    escalation_id: Annotated[str, Field(min_length=1, max_length=256)]
    claim_id: Annotated[str, Field(min_length=1, max_length=256)]
    invocation_id: Annotated[str, Field(min_length=1, max_length=256)]
    status: ExecutionJournalStatus
    revision: Annotated[int, Field(ge=0)]
    payload_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    policy_bundle_version: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    chain_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    created_at: datetime
    admitted_at: datetime | None = None
    sealed_outcome: SealedContinuation | None = None
    outcome_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    execution_completed_at: datetime | None = None
    completion_audited_at: datetime | None = None
    in_doubt_classification: InDoubtClassification | None = None
    in_doubt_at: datetime | None = None
    reconciliation_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    reconciler_id: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    reason_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    reconciled_at: datetime | None = None
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    _normalize_created_at = field_validator("created_at")(_utc)
    _normalize_admitted_at = field_validator("admitted_at")(
        lambda value: _utc(value) if value is not None else None
    )
    _normalize_execution_completed_at = field_validator("execution_completed_at")(
        lambda value: _utc(value) if value is not None else None
    )
    _normalize_completion_audited_at = field_validator("completion_audited_at")(
        lambda value: _utc(value) if value is not None else None
    )
    _normalize_in_doubt_at = field_validator("in_doubt_at")(
        lambda value: _utc(value) if value is not None else None
    )
    _normalize_reconciled_at = field_validator("reconciled_at")(
        lambda value: _utc(value) if value is not None else None
    )

    @field_validator("sealed_outcome", mode="before")
    @classmethod
    def _decode_sealed_outcome(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        decoded = dict(value)
        for field in ("nonce", "ciphertext"):
            encoded = decoded.get(field)
            if isinstance(encoded, str):
                try:
                    decoded[field] = base64.b64decode(encoded, altchars=b"-_", validate=True)
                except ValueError as exc:
                    raise ValueError(f"invalid sealed outcome {field}") from exc
        return decoded

    @field_serializer("sealed_outcome")
    def _encode_sealed_outcome(self, value: SealedContinuation | None) -> object:
        return None if value is None else ExecutionJournal._sealed_json(value)

    @model_validator(mode="after")
    def _validate_transition_shape(self) -> _StoredExecutionJournal:
        required_outcome_states = {
            ExecutionJournalStatus.OUTCOME_PROTECTED,
            ExecutionJournalStatus.COMPLETION_AUDITED,
            ExecutionJournalStatus.POST_PROCESSING_CLAIMED,
            ExecutionJournalStatus.DELIVERED,
            ExecutionJournalStatus.HANDED_OFF,
        }
        allowed_outcome_states = {
            *required_outcome_states,
            ExecutionJournalStatus.DELIVERY_DENIED,
        }
        has_outcome = self.sealed_outcome is not None and self.outcome_digest is not None
        if self.status in required_outcome_states and not has_outcome:
            raise ValueError("protected outcome must match the durable state")
        if has_outcome and self.status not in allowed_outcome_states:
            raise ValueError("protected outcome must match the durable state")
        if has_outcome != (self.execution_completed_at is not None):
            raise ValueError("protected outcome requires execution completion time")
        if has_outcome and self.admitted_at is None:
            raise ValueError("protected outcome requires prior admission")
        required_audited_states = {
            ExecutionJournalStatus.COMPLETION_AUDITED,
            ExecutionJournalStatus.POST_PROCESSING_CLAIMED,
            ExecutionJournalStatus.DELIVERED,
            ExecutionJournalStatus.HANDED_OFF,
        }
        if has_outcome and self.status is ExecutionJournalStatus.DELIVERY_DENIED:
            required_audited_states.add(ExecutionJournalStatus.DELIVERY_DENIED)
        if self.status in required_audited_states and self.completion_audited_at is None:
            raise ValueError("completion audit time must match the durable state")
        if (
            self.completion_audited_at is not None
            and self.status not in required_audited_states
            and self.status is not ExecutionJournalStatus.DELIVERY_DENIED
        ):
            raise ValueError("completion audit time must match the durable state")
        doubt_states = {
            ExecutionJournalStatus.IN_DOUBT_PREPARED,
            ExecutionJournalStatus.IN_DOUBT,
            ExecutionJournalStatus.RECONCILIATION_PREPARED,
            ExecutionJournalStatus.RECONCILED_DENIED,
        }
        if (self.status in doubt_states) != (
            self.in_doubt_classification is not None and self.in_doubt_at is not None
        ):
            raise ValueError("in-doubt evidence must match the durable state")
        reconciliation_states = {
            ExecutionJournalStatus.RECONCILIATION_PREPARED,
            ExecutionJournalStatus.RECONCILED_DENIED,
        }
        reconciliation_complete = all(
            value is not None
            for value in (self.reconciliation_id, self.reconciler_id, self.reason_digest)
        )
        if (self.status in reconciliation_states) != reconciliation_complete:
            raise ValueError("reconciliation metadata must match the durable state")
        if (self.status is ExecutionJournalStatus.RECONCILED_DENIED) != (
            self.reconciled_at is not None
        ):
            raise ValueError("reconciled_at must match the terminal state")
        return self

    def public(self) -> ExecutionJournalRecord:
        return ExecutionJournalRecord.model_validate(
            self.model_dump(exclude={"schema_version", "sealed_outcome", "signature"})
        )


def canonical_execution_outcome_aad(escalation_id: str, claim_id: str, invocation_id: str) -> bytes:
    """Bind a sealed outcome to its exact journal key and schema."""

    for value, field in (
        (escalation_id, "escalation_id"),
        (claim_id, "claim_id"),
        (invocation_id, "invocation_id"),
    ):
        ExecutionJournal._validate_identifier(value, field)
    return canonical_json_bytes(
        {
            "schema_version": 1,
            "kind": "protected_execution_outcome",
            "escalation_id": escalation_id,
            "claim_id": claim_id,
            "invocation_id": invocation_id,
        }
    )


class ExecutionJournal:
    """Process-safe signed JSON journal with AEAD-protected exact outcomes."""

    def __init__(
        self,
        directory: Path,
        *,
        signing_key: bytes,
        protector: ContinuationProtector,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 256 bits")
        self._directory = directory
        self._signing_key = bytes(signing_key)
        self._protector = protector
        self._clock = clock or (lambda: datetime.now(UTC))
        self._prepare_directory()

    async def create_claim(
        self,
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
        payload_digest: str,
        policy_bundle_version: str,
        chain_fingerprint: str,
    ) -> ExecutionJournalRecord:
        """Create or idempotently inspect the journal entry for a durable claim."""

        return await asyncio.to_thread(
            self._create_claim_sync,
            escalation_id,
            claim_id,
            invocation_id,
            payload_digest,
            policy_bundle_version,
            chain_fingerprint,
        )

    async def get(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        """Read authenticated journal metadata without exposing protected output."""

        return await asyncio.to_thread(self._get_sync, escalation_id, claim_id, invocation_id)

    async def find(self, escalation_id: str) -> ExecutionJournalRecord:
        """Find the sole authenticated journal entry for an escalation ID."""

        return await asyncio.to_thread(self._find_sync, escalation_id)

    async def prune_terminal(self, older_than: datetime) -> int:
        """Delete terminal journal entries last touched before a cutoff.

        Operator-invoked only; nothing prunes in the background. An entry is
        removed only when it reached a resolved terminal state and every
        timestamp it carries predates the cutoff. Claimed, admitted, prepared,
        and in-doubt entries describe an unresolved execution window and are
        never removed, regardless of age.

        A pruned entry is absent, not tombstoned, and :meth:`create_claim`
        recreates an absent entry as a fresh claim. Reconciliation for a pruned
        invocation therefore reports ``CLAIMED`` rather than its true terminal
        outcome. This cannot re-execute the work — the escalation store's
        ``CLAIMED`` state is the one-time execution anchor and is never terminal,
        so it is never pruned — but it does mean the cutoff must sit outside any
        window in which reconciliation could still be asked about the entry.

        Args:
            older_than: Timezone-aware UTC cutoff; entries at or after it stay.

        Returns:
            The number of entries deleted.

        Raises:
            ValueError: If the cutoff is not timezone-aware.
            ExecutionJournalTamperError: If an entry in the directory is
                unauthentic.
        """

        return await asyncio.to_thread(self._prune_terminal_sync, older_than)

    async def mark_admitted(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        """Persist that the stable admission audit exists before executor entry."""

        return await asyncio.to_thread(
            self._transition_simple_sync,
            escalation_id,
            claim_id,
            invocation_id,
            ExecutionJournalStatus.CLAIMED,
            ExecutionJournalStatus.ADMITTED,
            {"admitted_at": self._now()},
        )

    async def protect_outcome(
        self,
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
        outcome: ProtectedExecutionOutcome,
    ) -> ExecutionJournalRecord:
        """Seal exact executor output before any post-execution processing."""

        current = await self.get(escalation_id, claim_id=claim_id, invocation_id=invocation_id)
        if (outcome.escalation_id, outcome.claim_id, outcome.invocation_id) != (
            escalation_id,
            claim_id,
            invocation_id,
        ):
            raise ExecutionJournalConflictError("protected outcome does not match journal key")
        continuation = outcome.continuation
        if (
            outcome.admission_payload_digest != current.payload_digest
            or outcome.policy_bundle_version != current.policy_bundle_version
            or outcome.chain_fingerprint != current.chain_fingerprint
        ):
            raise ExecutionJournalConflictError("protected outcome does not match journal bindings")
        plaintext = outcome.model_dump_json().encode("utf-8")
        outcome_digest = hashlib.sha256(plaintext).hexdigest()
        sealed = await self._protector.seal(
            plaintext,
            aad=canonical_execution_outcome_aad(escalation_id, claim_id, invocation_id),
        )
        return await asyncio.to_thread(
            self._protect_outcome_sync,
            escalation_id,
            claim_id,
            invocation_id,
            outcome_digest,
            sealed,
            continuation.execution_completed_at,
        )

    async def open_outcome(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ProtectedExecutionOutcome:
        """Open and validate the exact outcome against authenticated journal bindings."""

        stored = await asyncio.to_thread(
            self._get_stored_sync, escalation_id, claim_id, invocation_id
        )
        if stored.sealed_outcome is None or stored.outcome_digest is None:
            raise ExecutionJournalStateError("journal entry has no protected outcome")
        try:
            plaintext = await self._protector.open(
                stored.sealed_outcome,
                aad=canonical_execution_outcome_aad(escalation_id, claim_id, invocation_id),
            )
            plaintext_digest = hashlib.sha256(plaintext).hexdigest()
            if not hmac.compare_digest(plaintext_digest, stored.outcome_digest):
                raise ValueError("protected outcome digest mismatch")
            outcome = ProtectedExecutionOutcome.model_validate_json(plaintext)
        except Exception as exc:
            raise ExecutionJournalTamperError("protected execution outcome is invalid") from exc
        expected = (
            stored.escalation_id,
            stored.claim_id,
            stored.invocation_id,
            stored.payload_digest,
            stored.policy_bundle_version,
            stored.chain_fingerprint,
            stored.execution_completed_at,
        )
        actual = (
            outcome.escalation_id,
            outcome.claim_id,
            outcome.invocation_id,
            outcome.admission_payload_digest,
            outcome.policy_bundle_version,
            outcome.chain_fingerprint,
            outcome.continuation.execution_completed_at,
        )
        if actual != expected:
            raise ExecutionJournalTamperError("protected outcome does not match journal bindings")
        return outcome

    async def mark_completion_audited(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        """Commit that the stable execution-completed audit event exists."""

        return await asyncio.to_thread(
            self._transition_simple_sync,
            escalation_id,
            claim_id,
            invocation_id,
            ExecutionJournalStatus.OUTCOME_PROTECTED,
            ExecutionJournalStatus.COMPLETION_AUDITED,
            {"completion_audited_at": self._now()},
        )

    async def claim_post_processing(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        """Claim known-result post-processing exactly once after completion audit."""

        return await asyncio.to_thread(
            self._transition_simple_sync,
            escalation_id,
            claim_id,
            invocation_id,
            ExecutionJournalStatus.COMPLETION_AUDITED,
            ExecutionJournalStatus.POST_PROCESSING_CLAIMED,
            {},
        )

    async def mark_in_doubt(
        self,
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
        classification: InDoubtClassification,
    ) -> ExecutionJournalRecord:
        """Prepare and commit an in-doubt classification.

        Audit-integrated callers should use :meth:`prepare_in_doubt`, append the
        stable audit event, then use :meth:`commit_in_doubt`.
        """

        await self.prepare_in_doubt(
            escalation_id,
            claim_id=claim_id,
            invocation_id=invocation_id,
            classification=classification,
        )
        return await self.commit_in_doubt(
            escalation_id,
            claim_id=claim_id,
            invocation_id=invocation_id,
            classification=classification,
        )

    async def prepare_in_doubt(
        self,
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
        classification: InDoubtClassification,
    ) -> ExecutionJournalRecord:
        """Persist an uncertain-window classification before its stable audit event."""

        return await asyncio.to_thread(
            self._prepare_in_doubt_sync,
            escalation_id,
            claim_id,
            invocation_id,
            classification,
        )

    async def commit_in_doubt(
        self,
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
        classification: InDoubtClassification,
    ) -> ExecutionJournalRecord:
        """Make a prepared in-doubt classification effective after audit."""

        return await asyncio.to_thread(
            self._commit_in_doubt_sync,
            escalation_id,
            claim_id,
            invocation_id,
            classification,
        )

    async def prepare_reconciliation(
        self,
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
        reconciliation_id: str,
        reconciler_id: str,
        reason_digest: str,
    ) -> ExecutionJournalRecord:
        """Persist authenticated deny-only reconciliation intent before audit."""

        return await asyncio.to_thread(
            self._prepare_reconciliation_sync,
            escalation_id,
            claim_id,
            invocation_id,
            reconciliation_id,
            reconciler_id,
            reason_digest,
        )

    async def commit_reconciled_denied(
        self,
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
        reconciliation_id: str,
    ) -> ExecutionJournalRecord:
        """Commit the only generic terminal resolution for an in-doubt execution."""

        return await asyncio.to_thread(
            self._commit_reconciled_denied_sync,
            escalation_id,
            claim_id,
            invocation_id,
            reconciliation_id,
        )

    async def commit_delivered(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        """Commit successful audited delivery of a protected known result."""

        return await asyncio.to_thread(
            self._transition_simple_sync,
            escalation_id,
            claim_id,
            invocation_id,
            ExecutionJournalStatus.POST_PROCESSING_CLAIMED,
            ExecutionJournalStatus.DELIVERED,
            {},
        )

    async def commit_delivery_denied(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        """Commit an audited delivery denial after known-result post-processing."""

        return await asyncio.to_thread(
            self._transition_simple_sync,
            escalation_id,
            claim_id,
            invocation_id,
            ExecutionJournalStatus.POST_PROCESSING_CLAIMED,
            ExecutionJournalStatus.DELIVERY_DENIED,
            {},
        )

    async def commit_execution_denied(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        """Commit a stable denial after an admitted executor failed or was cancelled."""

        return await asyncio.to_thread(
            self._transition_simple_sync,
            escalation_id,
            claim_id,
            invocation_id,
            ExecutionJournalStatus.ADMITTED,
            ExecutionJournalStatus.DELIVERY_DENIED,
            {"completion_audited_at": self._now()},
        )

    async def converge_audited_terminal(
        self,
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
        delivered: bool,
    ) -> ExecutionJournalRecord:
        """Repair a lagging or rolled-back journal from verified terminal evidence."""

        return await asyncio.to_thread(
            self._converge_audited_terminal_sync,
            escalation_id,
            claim_id,
            invocation_id,
            delivered,
        )

    async def commit_handoff(
        self, escalation_id: str, *, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        """Commit transfer to a separately protected downstream escalation."""

        return await asyncio.to_thread(
            self._transition_simple_sync,
            escalation_id,
            claim_id,
            invocation_id,
            ExecutionJournalStatus.POST_PROCESSING_CLAIMED,
            ExecutionJournalStatus.HANDED_OFF,
            {},
        )

    def _prepare_directory(self) -> None:
        try:
            metadata = self._directory.lstat()
        except FileNotFoundError:
            self._directory.mkdir(parents=True, mode=0o700)
            metadata = self._directory.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ExecutionJournalError("execution journal directory must be a real directory")
        os.chmod(self._directory, 0o700, follow_symlinks=False)

    def _create_claim_sync(
        self,
        escalation_id: str,
        claim_id: str,
        invocation_id: str,
        payload_digest: str,
        policy_bundle_version: str,
        chain_fingerprint: str,
    ) -> ExecutionJournalRecord:
        for value, field in (
            (escalation_id, "escalation_id"),
            (claim_id, "claim_id"),
            (invocation_id, "invocation_id"),
        ):
            self._validate_identifier(value, field)
        record = self._sign(
            {
                "schema_version": 1,
                "escalation_id": escalation_id,
                "claim_id": claim_id,
                "invocation_id": invocation_id,
                "status": ExecutionJournalStatus.CLAIMED,
                "revision": 0,
                "payload_digest": payload_digest,
                "policy_bundle_version": policy_bundle_version,
                "chain_fingerprint": chain_fingerprint,
                "created_at": self._now(),
            }
        )
        with self._locked():
            try:
                existing = self._read_record(escalation_id, claim_id, invocation_id)
            except ExecutionJournalNotFoundError:
                self._write_record(record)
                return record.public()
            requested_bindings = (
                payload_digest,
                policy_bundle_version,
                chain_fingerprint,
            )
            existing_bindings = (
                existing.payload_digest,
                existing.policy_bundle_version,
                existing.chain_fingerprint,
            )
            if requested_bindings != existing_bindings:
                raise ExecutionJournalAlreadyExistsError(escalation_id)
            return existing.public()

    def _get_sync(
        self, escalation_id: str, claim_id: str, invocation_id: str
    ) -> ExecutionJournalRecord:
        return self._get_stored_sync(escalation_id, claim_id, invocation_id).public()

    def _find_sync(self, escalation_id: str) -> ExecutionJournalRecord:
        self._validate_identifier(escalation_id, "escalation_id")
        matches: list[_StoredExecutionJournal] = []
        with self._locked():
            for path in sorted(self._directory.glob("*.json")):
                record = self._read_path(path)
                if record.escalation_id == escalation_id:
                    matches.append(record)
        if not matches:
            raise ExecutionJournalNotFoundError(escalation_id)
        if len(matches) > 1:
            raise ExecutionJournalConflictError(
                f"multiple journal entries exist for escalation {escalation_id}"
            )
        return matches[0].public()

    def _prune_terminal_sync(self, older_than: datetime) -> int:
        cutoff = _utc(older_than)
        removed = 0
        with self._locked():
            try:
                for path in sorted(self._directory.glob("*.json")):
                    record = self._read_path(path)
                    if record.status not in _TERMINAL_STATUSES:
                        continue
                    if self._last_touched(record) >= cutoff:
                        continue
                    path.unlink()
                    removed += 1
            finally:
                # An unauthentic entry aborts the sweep; whatever was already
                # unlinked still has to reach the disk.
                if removed:
                    directory_fd = os.open(self._directory, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
        return removed

    @staticmethod
    def _last_touched(record: _StoredExecutionJournal) -> datetime:
        """Latest timestamp the entry carries, so no live window is pruned early."""

        candidates = (
            record.created_at,
            record.admitted_at,
            record.execution_completed_at,
            record.completion_audited_at,
            record.in_doubt_at,
            record.reconciled_at,
        )
        return max(value for value in candidates if value is not None)

    def _get_stored_sync(
        self, escalation_id: str, claim_id: str, invocation_id: str
    ) -> _StoredExecutionJournal:
        with self._locked():
            return self._read_record(escalation_id, claim_id, invocation_id)

    def _transition_simple_sync(
        self,
        escalation_id: str,
        claim_id: str,
        invocation_id: str,
        source: ExecutionJournalStatus,
        target: ExecutionJournalStatus,
        updates: dict[str, object],
    ) -> ExecutionJournalRecord:
        with self._locked():
            record = self._read_record(escalation_id, claim_id, invocation_id)
            if record.status is target:
                return record.public()
            if record.status is not source:
                raise ExecutionJournalStateError(
                    f"journal transition {source.value}->{target.value} is invalid "
                    f"from {record.status.value}"
                )
            updated = self._replace(record, status=target, **updates)
            self._write_record(updated)
            return updated.public()

    def _protect_outcome_sync(
        self,
        escalation_id: str,
        claim_id: str,
        invocation_id: str,
        outcome_digest: str,
        sealed_outcome: SealedContinuation,
        execution_completed_at: datetime,
    ) -> ExecutionJournalRecord:
        with self._locked():
            record = self._read_record(escalation_id, claim_id, invocation_id)
            if record.status in {
                ExecutionJournalStatus.OUTCOME_PROTECTED,
                ExecutionJournalStatus.COMPLETION_AUDITED,
                ExecutionJournalStatus.POST_PROCESSING_CLAIMED,
                ExecutionJournalStatus.DELIVERED,
                ExecutionJournalStatus.DELIVERY_DENIED,
                ExecutionJournalStatus.HANDED_OFF,
            }:
                if record.outcome_digest != outcome_digest:
                    raise ExecutionJournalConflictError("conflicting protected outcome")
                return record.public()
            if record.status is not ExecutionJournalStatus.ADMITTED:
                raise ExecutionJournalStateError(
                    f"outcome cannot be protected from state {record.status.value}"
                )
            updated = self._replace(
                record,
                status=ExecutionJournalStatus.OUTCOME_PROTECTED,
                sealed_outcome=sealed_outcome,
                outcome_digest=outcome_digest,
                execution_completed_at=execution_completed_at,
            )
            self._write_record(updated)
            return updated.public()

    def _converge_audited_terminal_sync(
        self,
        escalation_id: str,
        claim_id: str,
        invocation_id: str,
        delivered: bool,
    ) -> ExecutionJournalRecord:
        target = (
            ExecutionJournalStatus.DELIVERED
            if delivered
            else ExecutionJournalStatus.DELIVERY_DENIED
        )
        with self._locked():
            record = self._read_record(escalation_id, claim_id, invocation_id)
            if record.status is target:
                return record.public()
            if record.status in {
                ExecutionJournalStatus.DELIVERED,
                ExecutionJournalStatus.DELIVERY_DENIED,
                ExecutionJournalStatus.HANDED_OFF,
                ExecutionJournalStatus.IN_DOUBT_PREPARED,
                ExecutionJournalStatus.IN_DOUBT,
                ExecutionJournalStatus.RECONCILIATION_PREPARED,
                ExecutionJournalStatus.RECONCILED_DENIED,
            }:
                raise ExecutionJournalStateError(
                    f"audited terminal conflicts with journal state {record.status.value}"
                )
            has_outcome = record.sealed_outcome is not None and record.outcome_digest is not None
            if delivered and not has_outcome:
                raise ExecutionJournalStateError(
                    "successful delivery cannot be repaired without a protected outcome"
                )
            if record.status is ExecutionJournalStatus.CLAIMED and delivered:
                raise ExecutionJournalStateError(
                    "successful delivery cannot precede execution admission"
                )
            updates: dict[str, object] = {}
            if record.status is not ExecutionJournalStatus.CLAIMED:
                updates["completion_audited_at"] = record.completion_audited_at or self._now()
            updated = self._replace(record, status=target, **updates)
            self._write_record(updated)
            return updated.public()

    def _prepare_in_doubt_sync(
        self,
        escalation_id: str,
        claim_id: str,
        invocation_id: str,
        classification: InDoubtClassification,
    ) -> ExecutionJournalRecord:
        with self._locked():
            record = self._read_record(escalation_id, claim_id, invocation_id)
            if record.status in {
                ExecutionJournalStatus.IN_DOUBT_PREPARED,
                ExecutionJournalStatus.IN_DOUBT,
                ExecutionJournalStatus.RECONCILIATION_PREPARED,
                ExecutionJournalStatus.RECONCILED_DENIED,
            }:
                if record.in_doubt_classification is not classification:
                    raise ExecutionJournalConflictError("conflicting in-doubt classification")
                return record.public()
            if record.status not in {
                ExecutionJournalStatus.CLAIMED,
                ExecutionJournalStatus.ADMITTED,
                ExecutionJournalStatus.POST_PROCESSING_CLAIMED,
            }:
                raise ExecutionJournalStateError(
                    f"in-doubt state cannot be entered from {record.status.value}"
                )
            updated = self._replace(
                record,
                status=ExecutionJournalStatus.IN_DOUBT_PREPARED,
                in_doubt_classification=classification,
                in_doubt_at=self._now(),
                sealed_outcome=None,
                outcome_digest=None,
                execution_completed_at=None,
                completion_audited_at=None,
            )
            self._write_record(updated)
            return updated.public()

    def _commit_in_doubt_sync(
        self,
        escalation_id: str,
        claim_id: str,
        invocation_id: str,
        classification: InDoubtClassification,
    ) -> ExecutionJournalRecord:
        with self._locked():
            record = self._read_record(escalation_id, claim_id, invocation_id)
            if record.in_doubt_classification is not classification:
                raise ExecutionJournalConflictError("conflicting in-doubt classification")
            if record.status in {
                ExecutionJournalStatus.IN_DOUBT,
                ExecutionJournalStatus.RECONCILIATION_PREPARED,
                ExecutionJournalStatus.RECONCILED_DENIED,
            }:
                return record.public()
            if record.status is not ExecutionJournalStatus.IN_DOUBT_PREPARED:
                raise ExecutionJournalStateError(
                    f"in-doubt state cannot be committed from {record.status.value}"
                )
            updated = self._replace(record, status=ExecutionJournalStatus.IN_DOUBT)
            self._write_record(updated)
            return updated.public()

    def _prepare_reconciliation_sync(
        self,
        escalation_id: str,
        claim_id: str,
        invocation_id: str,
        reconciliation_id: str,
        reconciler_id: str,
        reason_digest: str,
    ) -> ExecutionJournalRecord:
        self._validate_identifier(reconciliation_id, "reconciliation_id")
        self._validate_identifier(reconciler_id, "reconciler_id")
        with self._locked():
            record = self._read_record(escalation_id, claim_id, invocation_id)
            if record.status in {
                ExecutionJournalStatus.RECONCILIATION_PREPARED,
                ExecutionJournalStatus.RECONCILED_DENIED,
            }:
                existing = (record.reconciliation_id, record.reconciler_id, record.reason_digest)
                requested = (reconciliation_id, reconciler_id, reason_digest)
                if existing != requested:
                    raise ExecutionJournalConflictError("conflicting reconciliation")
                return record.public()
            if record.status is not ExecutionJournalStatus.IN_DOUBT:
                raise ExecutionJournalStateError(
                    f"reconciliation cannot be prepared from {record.status.value}"
                )
            updated = self._replace(
                record,
                status=ExecutionJournalStatus.RECONCILIATION_PREPARED,
                reconciliation_id=reconciliation_id,
                reconciler_id=reconciler_id,
                reason_digest=reason_digest,
            )
            self._write_record(updated)
            return updated.public()

    def _commit_reconciled_denied_sync(
        self,
        escalation_id: str,
        claim_id: str,
        invocation_id: str,
        reconciliation_id: str,
    ) -> ExecutionJournalRecord:
        with self._locked():
            record = self._read_record(escalation_id, claim_id, invocation_id)
            if record.reconciliation_id is None or not hmac.compare_digest(
                record.reconciliation_id, reconciliation_id
            ):
                raise ExecutionJournalConflictError("reconciliation ID does not match")
            if record.status is ExecutionJournalStatus.RECONCILED_DENIED:
                return record.public()
            if record.status is not ExecutionJournalStatus.RECONCILIATION_PREPARED:
                raise ExecutionJournalStateError(
                    f"reconciliation cannot be committed from {record.status.value}"
                )
            updated = self._replace(
                record,
                status=ExecutionJournalStatus.RECONCILED_DENIED,
                reconciled_at=self._now(),
            )
            self._write_record(updated)
            return updated.public()

    def _read_record(
        self, escalation_id: str, claim_id: str, invocation_id: str
    ) -> _StoredExecutionJournal:
        path = self._record_path(escalation_id, claim_id, invocation_id)
        return self._read_path(path)

    def _read_path(self, path: Path) -> _StoredExecutionJournal:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError as exc:
            raise ExecutionJournalNotFoundError(path.name) from exc
        except OSError as exc:
            raise ExecutionJournalTamperError(f"unsafe journal record: {path.name}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ExecutionJournalTamperError(f"unsafe journal record mode: {path.name}")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read()
        finally:
            os.close(descriptor)
        try:
            raw = json.loads(payload)
            record = _StoredExecutionJournal.model_validate(raw)
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            raise ExecutionJournalTamperError(f"invalid journal record: {path.name}") from exc
        canonical = record.model_dump(mode="json", exclude={"signature"})
        if not hmac.compare_digest(self._signature(canonical), record.signature):
            raise ExecutionJournalTamperError(f"invalid journal signature: {path.name}")
        if self._record_path(record.escalation_id, record.claim_id, record.invocation_id) != path:
            raise ExecutionJournalTamperError(f"journal key/path mismatch: {path.name}")
        return record

    def _write_record(self, record: _StoredExecutionJournal) -> None:
        destination = self._record_path(record.escalation_id, record.claim_id, record.invocation_id)
        payload = record.model_dump_json().encode("utf-8")
        temporary_path = ""
        try:
            descriptor, temporary_path = tempfile.mkstemp(prefix=".journal-", dir=self._directory)
            os.fchmod(descriptor, 0o600)
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("journal write made no forward progress")
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

    def _replace(
        self, record: _StoredExecutionJournal, **updates: object
    ) -> _StoredExecutionJournal:
        payload = record.model_dump(mode="json", exclude={"signature"})
        payload.update(updates)
        payload["revision"] = record.revision + 1
        return self._sign(payload)

    def _sign(self, payload: dict[str, object]) -> _StoredExecutionJournal:
        draft = _StoredExecutionJournal.model_validate({**payload, "signature": "0" * 64})
        canonical = draft.model_dump(mode="json", exclude={"signature"})
        return _StoredExecutionJournal.model_validate(
            {**canonical, "signature": self._signature(canonical)}
        )

    def _signature(self, payload: dict[str, object]) -> str:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=self._json_default,
        ).encode("utf-8")
        # Domain-separated so a record signed here can never verify as an
        # escalation-store record (or vice versa) under a shared key.
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
            return value.value
        raise TypeError(f"not JSON serializable: {type(value).__name__}")

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

    @staticmethod
    def _validate_identifier(value: str, field: str) -> None:
        if not value or len(value) > 256:
            raise ValueError(f"{field} must contain between 1 and 256 characters")

    def _record_path(self, escalation_id: str, claim_id: str, invocation_id: str) -> Path:
        digest = hashlib.sha256(
            f"{escalation_id}\0{claim_id}\0{invocation_id}".encode()
        ).hexdigest()
        return self._directory / f"{digest}.json"

    def _now(self) -> datetime:
        return _utc(self._clock())

    class _Lock:
        def __init__(self, directory: Path) -> None:
            self._path = directory / ".execution-journal.lock"
            self._descriptor = -1

        def __enter__(self) -> None:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            try:
                self._descriptor = os.open(self._path, flags, 0o600)
            except OSError as exc:
                raise ExecutionJournalError("could not open journal lock safely") from exc
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

    def _locked(self) -> ExecutionJournal._Lock:
        return self._Lock(self._directory)


__all__ = [
    "ExecutionJournal",
    "ExecutionJournalAlreadyExistsError",
    "ExecutionJournalConflictError",
    "ExecutionJournalError",
    "ExecutionJournalNotFoundError",
    "ExecutionJournalRecord",
    "ExecutionJournalStateError",
    "ExecutionJournalStatus",
    "ExecutionJournalTamperError",
    "InDoubtClassification",
    "ProtectedExecutionOutcome",
    "canonical_execution_outcome_aad",
]
