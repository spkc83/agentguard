"""PII-free governed evidence for already-completed written credit notices."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta  # noqa: TC003 - Pydantic runtime type
from typing import TYPE_CHECKING, NoReturn, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from agentguard.exceptions import AdverseActionError, AdverseActionFailure
from agentguard.guardrails import (
    DecisionPayload,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    canonical_json_bytes,
    thaw_payload,
)
from agentguard.guardrails.reason_codes import PII_UNSAFE_DECISION_EVIDENCE
from agentguard.models import AuditLink, EvidenceRef

from .adverse_action import (
    CombinedCounterofferAdverseActionNotice,
    CounterofferNonAcceptanceNotice,
    DeniedApplicationNotice,
    IncompleteApplicationNotice,
    PrincipalReasonSelection,
    RenderableNotice,
    StandaloneCounterofferNotice,
)
from .agent_templates import CreditDecisionCandidate, CreditDecisionOutcome
from .notice_renderer import NoticeRenderer, RenderedNotice

if TYPE_CHECKING:
    from collections.abc import Callable

_REFERENCE_NAMESPACES = frozenset(
    {
        "credit-application",
        "credit-decision",
        "credit-model",
        "credit-notice",
        "credit-policy",
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _fail(failure: AdverseActionFailure) -> NoReturn:
    raise AdverseActionError(failure)


def opaque_credit_ref(namespace: str, value: str) -> EvidenceRef:
    """Hash a raw local identifier into an allowlisted signed evidence reference."""

    if namespace not in _REFERENCE_NAMESPACES:
        raise ValueError("unsupported credit evidence namespace")
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError("credit evidence source must be canonical printable text")
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "domain": f"agentguard.{namespace}.reference.v1",
                "value": value,
            }
        )
    ).hexdigest()
    return EvidenceRef(namespace=namespace, value=digest)


class NoticeIssueEvidence(BaseModel):
    """Allowlisted notice metadata safe for a signed runtime payload."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    notice_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_type: str
    profile: str
    template_version: str
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    notification_at: datetime
    deadline_at: datetime

    @field_validator("artifact_type", "profile", "template_version")
    @classmethod
    def _validate_text(cls, value: str) -> str:
        if not value or value != value.strip() or not value.isprintable():
            raise ValueError("notice evidence text must be canonical printable text")
        return value

    @field_validator("notification_at", "deadline_at")
    @classmethod
    def _normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            _fail(AdverseActionFailure.NOTICE_INCOMPLETE)
        return value.astimezone(UTC)

    @field_serializer("notification_at", "deadline_at", when_used="json")
    def _serialize_time(self, value: datetime) -> float:
        """Keep allowlisted audit timestamps exact without DOB-pattern masking."""

        return value.timestamp()

    @model_validator(mode="after")
    def _validate_window(self) -> NoticeIssueEvidence:
        if self.notification_at > self.deadline_at:
            _fail(AdverseActionFailure.NOTICE_WINDOW_EXCEEDED)
        return self

    def to_payload(self) -> DecisionPayload:
        return DecisionPayload.model_validate(
            {
                "domain": "credit_risk_notice",
                "decision_id": self.decision_ref,
                "outcome": "issued",
                "body": self.model_dump(mode="json"),
            }
        )


@dataclass(frozen=True, slots=True)
class PreparedNoticeRecord:
    """Trusted local record; it must never be serialized into audit evidence."""

    candidate: CreditDecisionCandidate
    notice: RenderableNotice
    rendered: RenderedNotice
    evidence: NoticeIssueEvidence


class PreparedNoticeProvider(Protocol):
    async def get(self, notice_ref: str) -> PreparedNoticeRecord | None:
        """Return a trusted prepared notice by its opaque reference."""


class InMemoryPreparedNoticeProvider:
    """Bounded process-local prepared-notice store for runtime validation."""

    def __init__(self, *, max_records: int = 1_000) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1:
            raise ValueError("max_records must be a positive integer")
        self._max_records = max_records
        self._records: dict[str, PreparedNoticeRecord] = {}
        self._lock = asyncio.Lock()

    async def put(self, record: PreparedNoticeRecord) -> None:
        async with self._lock:
            existing = self._records.get(record.evidence.notice_ref)
            if existing is not None and existing != record:
                raise ValueError("notice reference already identifies different content")
            if existing is None and len(self._records) >= self._max_records:
                raise ValueError("prepared notice capacity exceeded")
            self._records[record.evidence.notice_ref] = record

    async def get(self, notice_ref: str) -> PreparedNoticeRecord | None:
        async with self._lock:
            return self._records.get(notice_ref)


def _notification_window(notice: RenderableNotice) -> tuple[datetime, datetime]:
    if isinstance(
        notice,
        DeniedApplicationNotice
        | CombinedCounterofferAdverseActionNotice
        | IncompleteApplicationNotice,
    ):
        return (
            notice.timing.notification.occurred_at,
            notice.timing.trigger_at + timedelta(days=30),
        )
    if isinstance(notice, CounterofferNonAcceptanceNotice):
        return (
            notice.timing.notification.occurred_at,
            notice.timing.counteroffer_notification.occurred_at + timedelta(days=90),
        )
    if isinstance(notice, StandaloneCounterofferNotice):
        return (
            notice.timing.notification.occurred_at,
            notice.timing.trigger_at + timedelta(days=30),
        )
    _fail(AdverseActionFailure.NOTICE_INCOMPLETE)


def prepare_notice_record(
    candidate: CreditDecisionCandidate,
    notice: RenderableNotice,
    *,
    renderer: NoticeRenderer | None = None,
    clock: Callable[[], datetime] = _utc_now,
) -> PreparedNoticeRecord:
    """Revalidate a decline notice locally and derive only PII-free evidence."""

    selection = candidate.reason_selection
    if (
        candidate.outcome is not CreditDecisionOutcome.DECLINE
        or selection is None
        or not isinstance(notice, DeniedApplicationNotice | CounterofferNonAcceptanceNotice)
        or notice.credit_request.application_id != candidate.application_ref
    ):
        _fail(AdverseActionFailure.NOTICE_INCOMPLETE)
    expected_reasons = PrincipalReasonSelection.from_attribution(selection)
    if notice.principal_reasons != expected_reasons:
        _fail(AdverseActionFailure.NOTICE_INCOMPLETE)

    active_renderer = renderer or NoticeRenderer()
    rendered = active_renderer.render(notice)
    notification_at, deadline_at = _notification_window(notice)
    observed_at = clock()
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("notice clock must return a timezone-aware datetime")
    if notification_at > observed_at.astimezone(UTC):
        _fail(AdverseActionFailure.NOTICE_INCOMPLETE)
    application_ref = opaque_credit_ref(
        "credit-application",
        candidate.application_ref,
    )
    decision_ref = opaque_credit_ref("credit-decision", candidate.decision_id)
    notice_ref = opaque_credit_ref("credit-notice", notice.notice_id)
    model_ref = opaque_credit_ref(
        "credit-model",
        f"{candidate.model_id}:{candidate.model_version}",
    )
    evidence = NoticeIssueEvidence(
        application_ref=application_ref.value,
        decision_ref=decision_ref.value,
        notice_ref=notice_ref.value,
        model_ref=model_ref.value,
        artifact_type=type(notice).__name__,
        profile=rendered.profile.value,
        template_version=rendered.template_version,
        body_sha256=rendered.body_sha256,
        notification_at=notification_at,
        deadline_at=deadline_at,
    )
    return PreparedNoticeRecord(
        candidate=candidate,
        notice=notice,
        rendered=rendered,
        evidence=evidence,
    )


def notice_audit_references(
    evidence: NoticeIssueEvidence,
) -> tuple[EvidenceRef, tuple[AuditLink, ...]]:
    """Return the typed subject and relationship links for notice evidence."""

    subject_ref = EvidenceRef(
        namespace="credit-application",
        value=evidence.application_ref,
    )
    return (
        subject_ref,
        (
            AuditLink(
                relation="decision",
                target=EvidenceRef(
                    namespace="credit-decision",
                    value=evidence.decision_ref,
                ),
            ),
            AuditLink(
                relation="notice",
                target=EvidenceRef(
                    namespace="credit-notice",
                    value=evidence.notice_ref,
                ),
            ),
            AuditLink(
                relation="model",
                target=EvidenceRef(
                    namespace="credit-model",
                    value=evidence.model_ref,
                ),
            ),
        ),
    )


class NoticeCompletenessGuardrail:
    """Revalidate trusted notice content while governing only safe metadata."""

    id = "credit-notice-completeness"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.notice_governance:NoticeCompletenessGuardrail:1"
    )
    stages = frozenset({GuardrailStage.ON_DECISION})

    def __init__(
        self,
        provider: PreparedNoticeProvider,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._provider = provider
        self._clock = clock
        self.config: dict[str, object] = {}

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if context.action != "notice:issue":
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        payload = context.payload
        if (
            not isinstance(payload, DecisionPayload)
            or payload.domain != "credit_risk_notice"
            or payload.outcome != "issued"
        ):
            return self._deny(AdverseActionFailure.NOTICE_INCOMPLETE)
        try:
            evidence = NoticeIssueEvidence.model_validate(thaw_payload(payload.body))
            if payload.decision_id != evidence.decision_ref:
                return self._deny(AdverseActionFailure.NOTICE_INCOMPLETE)
            record = await self._provider.get(evidence.notice_ref)
            if record is None:
                return self._deny(AdverseActionFailure.NOTICE_INCOMPLETE)
            rebuilt = prepare_notice_record(
                record.candidate,
                record.notice,
                clock=self._clock,
            )
            if rebuilt.evidence != evidence or rebuilt.rendered != record.rendered:
                return self._deny(AdverseActionFailure.NOTICE_INCOMPLETE)
            retained = context.attributes.get("redacted_evidence")
            try:
                projected = NoticeIssueEvidence.model_validate(thaw_payload(retained))
            except (AdverseActionError, TypeError, ValueError):
                return self._unsafe_evidence()
            if projected != evidence:
                return self._unsafe_evidence()
        except AdverseActionError as exc:
            return self._deny(exc.failure)
        except Exception:
            return self._deny(AdverseActionFailure.NOTICE_INCOMPLETE)
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)

    @staticmethod
    def _deny(failure: AdverseActionFailure) -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.DENY,
            reason_codes=(failure.value,),
        )

    @staticmethod
    def _unsafe_evidence() -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.DENY,
            reason_codes=(PII_UNSAFE_DECISION_EVIDENCE,),
        )
