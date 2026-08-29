"""Checkpoint-attested, privacy-preserving rolling credit fairness monitoring."""

from __future__ import annotations

import math
from collections import Counter
from datetime import UTC, datetime, timedelta  # noqa: TC003 - Pydantic runtime types
from typing import TYPE_CHECKING, Literal, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.exceptions import AuditAttestationError, AuditTamperDetectedError
from agentguard.models import EvidenceRef  # noqa: TC001 - Pydantic runtime field type

from .fairness import FairnessAnalyzer, FairnessObservation, FairnessReport, FairnessVerdict
from .governed_agent import DecisionAuditEvidence
from .model_governance import ModelFairnessStatus
from .notice_governance import opaque_credit_ref

if TYPE_CHECKING:
    from agentguard.core.audit import VerifiedAuditSnapshot
    from agentguard.models import AuditEvent, AuditLink


class AuditLogProtocol(Protocol):
    """Minimum verified-audit boundary required by the monitor."""

    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot: ...


class PrivateFairnessAttributes(BaseModel):
    """Private observation fields that must never cross into signed audit evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    group_name: str
    predicted_pd: float
    observed_default: bool | None = None
    observed_at: datetime

    @field_validator("group_name")
    @classmethod
    def _validate_group_name(cls, value: str) -> str:
        if not value or value != value.strip() or not value.isprintable():
            raise ValueError("group_name must be canonical printable text")
        return value

    @field_validator("predicted_pd")
    @classmethod
    def _validate_predicted_pd(cls, value: float) -> float:
        if isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("predicted_pd must be finite and in [0, 1]")
        return value

    @field_validator("observed_at")
    @classmethod
    def _normalize_observed_at(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value.astimezone(UTC)


class FairnessObservationProvider(Protocol):
    """Trusted private join boundary for protected and model-outcome attributes."""

    provider_id: str
    version: str

    async def get(
        self,
        application_ref: EvidenceRef,
        decision_ref: EvidenceRef,
        model_ref: EvidenceRef,
    ) -> PrivateFairnessAttributes | None: ...


class FairnessMonitoringReport(BaseModel):
    """Aggregate-only rolling result safe to retain outside the private provider."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    window_started_at: datetime
    window_ended_at: datetime
    provider_id: str
    provider_version: str
    model_id: str
    model_version: str
    audit_chain_id: str
    audit_head_sequence: int = Field(ge=0)
    audit_head_event_hash: str
    selected_event_count: int = Field(ge=0)
    analyzed_observation_count: int = Field(ge=0)
    malformed_event_count: int = Field(ge=0)
    duplicate_decision_count: int = Field(ge=0)
    missing_observation_count: int = Field(ge=0)
    malformed_observation_count: int = Field(ge=0)
    provider_error_count: int = Field(ge=0)
    status: ModelFairnessStatus
    analysis: FairnessReport

    @field_validator("window_started_at", "window_ended_at")
    @classmethod
    def _normalize_time(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("fairness report timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator(
        "provider_id",
        "provider_version",
        "model_id",
        "model_version",
        "audit_chain_id",
        "audit_head_event_hash",
    )
    @classmethod
    def _canonical_text(cls, value: str) -> str:
        if not value or value != value.strip() or not value.isprintable():
            raise ValueError("fairness report identifiers must be canonical printable text")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> FairnessMonitoringReport:
        if self.window_ended_at < self.window_started_at:
            raise ValueError("fairness monitoring window is reversed")
        if self.analyzed_observation_count > self.selected_event_count:
            raise ValueError("analyzed observations exceed selected events")
        integrity_errors = (
            self.malformed_event_count
            + self.duplicate_decision_count
            + self.missing_observation_count
            + self.malformed_observation_count
            + self.provider_error_count
        )
        expected = {
            FairnessVerdict.PASS: ModelFairnessStatus.PASSED,
            FairnessVerdict.FAIL: ModelFairnessStatus.FAILED,
            FairnessVerdict.INSUFFICIENT_DATA: ModelFairnessStatus.INSUFFICIENT_DATA,
        }[self.analysis.overall_verdict]
        if integrity_errors:
            expected = ModelFairnessStatus.INSUFFICIENT_DATA
        if self.status is not expected:
            raise ValueError("fairness report status disagrees with analysis or integrity counts")
        return self


class _DecisionJoin(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    application_ref: EvidenceRef
    decision_ref: EvidenceRef
    model_ref: EvidenceRef
    outcome: Literal["approve", "decline"]
    decision_at: datetime


def _is_opaque(reference: EvidenceRef, namespace: str) -> bool:
    return (
        reference.namespace == namespace
        and len(reference.value) == 64
        and all(character in "0123456789abcdef" for character in reference.value)
    )


def _exact_link(event: AuditEvent, relation: str, namespace: str) -> AuditLink | None:
    links = tuple(link for link in event.links if link.relation == relation)
    if len(links) != 1 or not _is_opaque(links[0].target, namespace):
        return None
    return links[0]


def _has_exact_decision_control(event: AuditEvent) -> bool:
    matches = tuple(
        evaluation
        for evaluation in event.guardrail_evaluations
        if evaluation.guardrail_id == "credit-decision-evidence"
    )
    return len(matches) == 1 and (
        matches[0].guardrail_version == "1"
        and matches[0].stage == "on_decision"
        and matches[0].effect == "allow"
        and matches[0].enforced
    )


def _eligible_action_outcome(event: AuditEvent) -> str | None:
    if event.event_type != "delivery_completed" or event.result != "allowed":
        return None
    if event.action == "decision:approve":
        return "approve"
    if event.action == "decision:decline":
        return "decline"
    if event.action == "decision:override":
        return "override"
    return None


def _join_from_event(event: AuditEvent) -> _DecisionJoin | None:
    action_outcome = _eligible_action_outcome(event)
    if action_outcome is None or not _has_exact_decision_control(event):
        return None
    subject = event.subject_ref
    decision_link = _exact_link(event, "decision", "credit-decision")
    model_link = _exact_link(event, "model", "credit-model")
    if (
        subject is None
        or not _is_opaque(subject, "credit-application")
        or decision_link is None
        or model_link is None
    ):
        return None
    value = event.payload_redacted.get("value")
    try:
        evidence = DecisionAuditEvidence.model_validate(value)
    except (TypeError, ValueError):
        return None
    outcome = evidence.outcome.value
    if action_outcome != "override" and outcome != action_outcome:
        return None
    if outcome not in {"approve", "decline"}:
        return None
    if (
        evidence.application_ref != subject.value
        or evidence.decision_ref != decision_link.target.value
        or evidence.model_ref != model_link.target.value
    ):
        return None
    final_outcome = cast("Literal['approve', 'decline']", outcome)
    return _DecisionJoin(
        application_ref=subject,
        decision_ref=decision_link.target,
        model_ref=model_link.target,
        outcome=final_outcome,
        decision_at=event.timestamp.astimezone(UTC),
    )


def _require_trusted(snapshot: VerifiedAuditSnapshot) -> None:
    verification = snapshot.verification
    if not verification.valid:
        raise AuditTamperDetectedError(
            event_index=verification.error_index or 0,
            event_id=verification.error_event_id or "<unverified-evidence>",
        )
    if not verification.attestable:
        raise AuditAttestationError(verification.checkpoint_status)


def _canonical_provider_field(value: str, field: str) -> str:
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError(f"provider {field} must be canonical printable text")
    return value


class FairnessMonitor:
    """Join verified final decisions to private observations and emit aggregates only."""

    def __init__(
        self,
        audit_log: AuditLogProtocol,
        provider: FairnessObservationProvider,
        analyzer: FairnessAnalyzer,
        *,
        model_id: str,
        model_version: str,
    ) -> None:
        self._audit_log = audit_log
        self._provider = provider
        self._analyzer = analyzer
        self._provider_id = _canonical_provider_field(provider.provider_id, "id")
        self._provider_version = _canonical_provider_field(provider.version, "version")
        self._model_id = _canonical_provider_field(model_id, "model_id")
        self._model_version = _canonical_provider_field(model_version, "model_version")
        self._model_ref = opaque_credit_ref(
            "credit-model", f"{self._model_id}:{self._model_version}"
        )

    async def analyze(
        self,
        *,
        as_of: datetime,
        window: timedelta,
    ) -> FairnessMonitoringReport:
        """Analyze final decisions in ``(as_of - window, as_of]``."""

        if as_of.utcoffset() is None:
            raise ValueError("as_of must be timezone-aware")
        if window <= timedelta(0):
            raise ValueError("window must be positive")
        self._assert_provider_identity()
        as_of = as_of.astimezone(UTC)
        window_start = as_of - window
        snapshot = await self._audit_log.read_verified(require_checkpoint=True)
        _require_trusted(snapshot)

        target_or_unscoped_events = tuple(
            event
            for event in snapshot.events
            if _eligible_action_outcome(event) is not None
            and (
                (model_link := _exact_link(event, "model", "credit-model")) is None
                or model_link.target == self._model_ref
            )
        )
        malformed_timestamps = sum(
            event.timestamp.utcoffset() is None for event in target_or_unscoped_events
        )
        candidates = tuple(
            event
            for event in target_or_unscoped_events
            if event.timestamp.utcoffset() is not None
            and window_start < event.timestamp.astimezone(UTC) <= as_of
        )
        parsed = tuple((event, _join_from_event(event)) for event in candidates)
        valid_joins = tuple(join for _, join in parsed if join is not None)
        malformed_events = malformed_timestamps + sum(join is None for _, join in parsed)
        decision_counts = Counter(join.decision_ref.value for join in valid_joins)
        duplicate_refs = frozenset(ref for ref, count in decision_counts.items() if count > 1)

        observations: list[FairnessObservation] = []
        missing = malformed = provider_errors = 0
        for join in valid_joins:
            if join.decision_ref.value in duplicate_refs:
                continue
            try:
                private = await self._provider.get(
                    join.application_ref,
                    join.decision_ref,
                    join.model_ref,
                )
            except Exception:  # trusted provider failures still fail closed
                provider_errors += 1
                continue
            if private is None:
                missing += 1
                continue
            try:
                private = PrivateFairnessAttributes.model_validate(private)
                if private.observed_at > as_of or private.observed_at < join.decision_at:
                    raise ValueError("future private observations are not eligible")
                if private.group_name not in self._analyzer.group_names:
                    raise ValueError("private observation is outside the configured group scope")
                observations.append(
                    FairnessObservation(
                        decision_ref=join.decision_ref.value,
                        group_name=private.group_name,
                        outcome=join.outcome,
                        predicted_pd=private.predicted_pd,
                        observed_default=private.observed_default,
                    )
                )
            except (TypeError, ValueError):
                malformed += 1

        analysis = self._analyzer.analyze(tuple(observations))
        self._assert_provider_identity()
        integrity_errors = (
            malformed_events + len(duplicate_refs) + missing + malformed + provider_errors
        )
        status = {
            FairnessVerdict.PASS: ModelFairnessStatus.PASSED,
            FairnessVerdict.FAIL: ModelFairnessStatus.FAILED,
            FairnessVerdict.INSUFFICIENT_DATA: ModelFairnessStatus.INSUFFICIENT_DATA,
        }[analysis.overall_verdict]
        if integrity_errors:
            status = ModelFairnessStatus.INSUFFICIENT_DATA

        verification = snapshot.verification
        return FairnessMonitoringReport(
            window_started_at=window_start,
            window_ended_at=as_of,
            provider_id=self._provider_id,
            provider_version=self._provider_version,
            model_id=self._model_id,
            model_version=self._model_version,
            audit_chain_id=verification.chain_id,
            audit_head_sequence=verification.head_sequence or 0,
            audit_head_event_hash=verification.head_event_hash,
            selected_event_count=len(valid_joins) + malformed_events,
            analyzed_observation_count=len(observations),
            malformed_event_count=malformed_events,
            duplicate_decision_count=len(duplicate_refs),
            missing_observation_count=missing,
            malformed_observation_count=malformed,
            provider_error_count=provider_errors,
            status=status,
            analysis=analysis,
        )

    def _assert_provider_identity(self) -> None:
        provider_id = _canonical_provider_field(self._provider.provider_id, "id")
        provider_version = _canonical_provider_field(self._provider.version, "version")
        if (provider_id, provider_version) != (self._provider_id, self._provider_version):
            raise ValueError("fairness provider identity changed during monitoring")


__all__ = [
    "FairnessMonitor",
    "FairnessMonitoringReport",
    "FairnessObservationProvider",
    "PrivateFairnessAttributes",
]
