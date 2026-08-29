"""Thin governed orchestration for scoring, credit decisions, overrides, and notices."""

from __future__ import annotations

import math
from numbers import Real
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentguard.guardrails import DecisionPayload, GuardrailPayload, ToolCallPayload, thaw_payload
from agentguard.models import AuditLink, EvidenceRef

from .agent_templates import (
    CreditDecisionCandidate,
    CreditDecisionOutcome,
    CreditDecisionPolicy,
)
from .attribution import AttributionResult  # noqa: TC001 - Pydantic runtime type
from .notice_governance import (
    InMemoryPreparedNoticeProvider,
    NoticeIssueEvidence,
    PreparedNoticeProvider,
    notice_audit_references,
    opaque_credit_ref,
    prepare_notice_record,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence
    from datetime import datetime

    from .adverse_action import RenderableNotice
    from .decision_reasons import PolicyDenialSelection
    from .reason_codes import ReasonCodeSelection
    from .review_governance import ReviewLineageValidator


class _GovernanceKernel(Protocol):
    async def guarded_tool_call(
        self,
        *,
        agent_id: str | None = None,
        credential: object | None = None,
        action: str,
        resource: str | None,
        executor: Callable[[GuardrailPayload], Awaitable[Any]],
        payload: ToolCallPayload | None = None,
        fallback_action: str | None = None,
        subject_ref: EvidenceRef | None = None,
        links: Sequence[AuditLink] = (),
        redacted_evidence: object | None = None,
    ) -> Any: ...


def _canonical_text(value: str) -> str:
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError("identifiers must be canonical printable text")
    return value


class CreditModelScore(BaseModel):
    """Full-fidelity local score returned by a trusted scoring callback."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pd_score: float
    attribution: AttributionResult

    @field_validator("pd_score", mode="before")
    @classmethod
    def _validate_pd(cls, value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError("pd_score must be a finite value in [0, 1]")
        result = float(value)
        if not math.isfinite(result) or not 0 <= result <= 1:
            raise ValueError("pd_score must be a finite value in [0, 1]")
        return result


class ModelScoreAuditEvidence(BaseModel):
    """Allowlisted score metadata; it excludes PD, inputs, and attribution details."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_ref: str = Field(pattern=r"^[0-9a-f]{64}$")


class DecisionAuditEvidence(BaseModel):
    """Allowlisted decision metadata safe for signed audit retention."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    application_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    outcome: CreditDecisionOutcome


def decision_audit_evidence(candidate: CreditDecisionCandidate) -> DecisionAuditEvidence:
    """Project a full candidate into the only fields retained in audit evidence."""

    return DecisionAuditEvidence(
        application_ref=opaque_credit_ref("credit-application", candidate.application_ref).value,
        decision_ref=opaque_credit_ref("credit-decision", candidate.decision_id).value,
        model_ref=opaque_credit_ref(
            "credit-model", f"{candidate.model_id}:{candidate.model_version}"
        ).value,
        policy_ref=opaque_credit_ref(
            "credit-policy", f"{candidate.policy_id}:{candidate.policy_version}"
        ).value,
        outcome=candidate.outcome,
    )


def decision_audit_references(
    evidence: DecisionAuditEvidence,
) -> tuple[EvidenceRef, tuple[AuditLink, ...]]:
    """Return the opaque application subject plus decision and model links."""

    subject_ref = EvidenceRef(namespace="credit-application", value=evidence.application_ref)
    return (
        subject_ref,
        (
            AuditLink(
                relation="decision",
                target=EvidenceRef(namespace="credit-decision", value=evidence.decision_ref),
            ),
            AuditLink(
                relation="model",
                target=EvidenceRef(namespace="credit-model", value=evidence.model_ref),
            ),
        ),
    )


class GovernedCreditAgent:
    """Apply fixed governance actions without owning authentication or policy engines."""

    def __init__(
        self,
        kernel: _GovernanceKernel,
        *,
        policy: CreditDecisionPolicy | None = None,
        notice_provider: InMemoryPreparedNoticeProvider | None = None,
        review_lineage_validator: ReviewLineageValidator | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._kernel = kernel
        self._policy = policy or CreditDecisionPolicy()
        self._notice_provider = notice_provider or InMemoryPreparedNoticeProvider()
        self._review_lineage_validator = review_lineage_validator
        self._clock = clock

    @property
    def notice_provider(self) -> PreparedNoticeProvider:
        """Return the provider that must also back ``NoticeCompletenessGuardrail``."""

        return self._notice_provider

    async def score(
        self,
        *,
        application_ref: str,
        model_id: str,
        model_version: str,
        scorer: Callable[[], Awaitable[CreditModelScore]],
        agent_id: str | None = None,
        credential: object | None = None,
    ) -> CreditModelScore:
        """Run a scorer under ``model:score`` without auditing its inputs or output."""

        application_ref = _canonical_text(application_ref)
        model_id = _canonical_text(model_id)
        model_version = _canonical_text(model_version)
        application_evidence = opaque_credit_ref("credit-application", application_ref)
        model_evidence = opaque_credit_ref("credit-model", f"{model_id}:{model_version}")
        safe_evidence = ModelScoreAuditEvidence(
            application_ref=application_evidence.value,
            model_ref=model_evidence.value,
        )

        async def execute(_payload: GuardrailPayload) -> CreditModelScore:
            score = await scorer()
            if not isinstance(score, CreditModelScore):
                raise TypeError("scorer must return CreditModelScore")
            if (
                score.attribution.model_id != model_id
                or score.attribution.model_version != model_version
            ):
                raise ValueError("score attribution does not match the governed model")
            return score

        delivered = await self._kernel.guarded_tool_call(
            agent_id=agent_id,
            credential=credential,
            action="model:score",
            resource=f"model/{model_evidence.value}",
            executor=execute,
            payload=ToolCallPayload.model_validate(
                {
                    "arguments": {
                        "application_ref": application_evidence.value,
                        "model_ref": model_evidence.value,
                    }
                }
            ),
            subject_ref=application_evidence,
            links=(AuditLink(relation="model", target=model_evidence),),
            redacted_evidence=safe_evidence,
        )
        return CreditModelScore.model_validate(delivered)

    async def decide(
        self,
        *,
        decision_id: str,
        application_ref: str,
        score: CreditModelScore,
        reason_selection: ReasonCodeSelection | None = None,
        policy_denial: PolicyDenialSelection | None = None,
        agent_id: str | None = None,
        credential: object | None = None,
    ) -> CreditDecisionCandidate:
        """Evaluate the pure policy and emit its result through the full kernel.

        A ``policy_denial`` produced by a versioned credit-policy bundle declines
        the application regardless of the PD band, and its rules become the
        notice's principal reasons.
        """

        candidate = self._policy.evaluate(
            decision_id=decision_id,
            application_ref=application_ref,
            pd_score=score.pd_score,
            model_id=score.attribution.model_id,
            model_version=score.attribution.model_version,
            attribution=score.attribution,
            reason_selection=reason_selection,
            policy_denial=policy_denial,
        )
        return await self._emit_candidate(
            candidate,
            action=f"decision:{candidate.outcome.value}",
            agent_id=agent_id,
            credential=credential,
        )

    async def override(
        self,
        *,
        candidate: CreditDecisionCandidate,
        parent_escalation_id: str,
        agent_id: str | None = None,
        credential: object | None = None,
    ) -> CreditDecisionCandidate:
        """Emit a separately authorized final underwriter outcome linked to review.

        When the override declines on the reviewer's own judgment, that judgment
        must name the same escalation whose completed review lineage is verified
        before the decision is emitted.
        """

        if candidate.outcome is CreditDecisionOutcome.REVIEW:
            raise ValueError("an override must be a final approve or decline outcome")
        parent_escalation_id = _canonical_text(parent_escalation_id)
        judgment = candidate.review_judgment
        if judgment is not None and judgment.escalation_id != parent_escalation_id:
            raise ValueError("a judgmental decline must cite the escalation it is reviewed under")

        async def validate_lineage() -> None:
            if self._review_lineage_validator is None:
                raise RuntimeError("override requires a trusted review-lineage validator")
            await self._review_lineage_validator.verify(
                escalation_id=parent_escalation_id,
                candidate=candidate,
            )

        return await self._emit_candidate(
            candidate,
            action="decision:override",
            agent_id=agent_id,
            credential=credential,
            before_emit=validate_lineage,
            extra_links=(
                AuditLink(
                    relation="parent",
                    target=EvidenceRef(namespace="hitl-escalation", value=parent_escalation_id),
                ),
            ),
        )

    async def issue_notice(
        self,
        *,
        candidate: CreditDecisionCandidate,
        notice: RenderableNotice,
        agent_id: str | None = None,
        credential: object | None = None,
    ) -> NoticeIssueEvidence:
        """Record an already-completed written notification using PII-free evidence."""

        record = (
            prepare_notice_record(candidate, notice, clock=self._clock)
            if self._clock is not None
            else prepare_notice_record(candidate, notice)
        )
        subject_ref, links = notice_audit_references(record.evidence)

        async def execute(_payload: GuardrailPayload) -> DecisionPayload:
            await self._notice_provider.put(record)
            return record.evidence.to_payload()

        delivered = await self._kernel.guarded_tool_call(
            agent_id=agent_id,
            credential=credential,
            action="notice:issue",
            resource=f"notice/{record.evidence.notice_ref}",
            executor=execute,
            subject_ref=subject_ref,
            links=links,
            redacted_evidence=record.evidence,
        )
        payload = DecisionPayload.model_validate(delivered)
        return NoticeIssueEvidence.model_validate(thaw_payload(payload.body))

    async def _emit_candidate(
        self,
        candidate: CreditDecisionCandidate,
        *,
        action: str,
        agent_id: str | None,
        credential: object | None,
        before_emit: Callable[[], Awaitable[None]] | None = None,
        extra_links: tuple[AuditLink, ...] = (),
    ) -> CreditDecisionCandidate:
        evidence = decision_audit_evidence(candidate)
        subject_ref, links = decision_audit_references(evidence)

        async def execute(_payload: GuardrailPayload) -> DecisionPayload:
            if before_emit is not None:
                await before_emit()
            return candidate.to_payload()

        delivered = await self._kernel.guarded_tool_call(
            agent_id=agent_id,
            credential=credential,
            action=action,
            resource=f"application/{evidence.application_ref}",
            executor=execute,
            subject_ref=subject_ref,
            links=(*links, *extra_links),
            redacted_evidence=evidence,
        )
        payload = DecisionPayload.model_validate(delivered)
        return CreditDecisionCandidate.model_validate(thaw_payload(payload.body))


__all__ = [
    "CreditModelScore",
    "DecisionAuditEvidence",
    "GovernedCreditAgent",
    "ModelScoreAuditEvidence",
    "decision_audit_evidence",
    "decision_audit_references",
]
