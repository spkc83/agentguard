"""Governed credit orchestration uses fixed actions and allowlisted evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest

from agentguard.domains.finance.credit_risk.agent_templates import CreditDecisionPolicy
from agentguard.domains.finance.credit_risk.governed_agent import (
    CreditModelScore,
    DecisionAuditEvidence,
    GovernedCreditAgent,
    ModelScoreAuditEvidence,
)
from agentguard.domains.finance.credit_risk.notice_governance import (
    InMemoryPreparedNoticeProvider,
    NoticeIssueEvidence,
)
from agentguard.exceptions import PermissionDeniedError
from agentguard.guardrails import GuardrailPayload, ToolCallPayload
from agentguard.models import AuditLink, EvidenceRef
from tests.unit.domains.finance.test_notice_governance import _reason_evidence, _record

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from agentguard.domains.finance.credit_risk.attribution import AttributionResult


class _Kernel:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

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
    ) -> Any:
        self.calls.append(
            {
                "agent_id": agent_id,
                "credential": credential,
                "action": action,
                "resource": resource,
                "payload": payload,
                "fallback_action": fallback_action,
                "subject_ref": subject_ref,
                "links": links,
                "redacted_evidence": redacted_evidence,
            }
        )
        return await executor(payload or ToolCallPayload.model_validate({"arguments": {}}))


class _RejectKernel(_Kernel):
    async def guarded_tool_call(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        raise PermissionDeniedError(
            str(kwargs.get("agent_id") or "unknown"),
            str(kwargs["action"]),
            str(kwargs["resource"]),
        )


class _LineageValidator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def verify(self, *, escalation_id: str, candidate: object) -> object:
        self.calls.append((escalation_id, candidate))
        return object()


def _score(attribution: AttributionResult, *, pd_score: float = 0.30) -> CreditModelScore:
    return CreditModelScore(pd_score=pd_score, attribution=attribution)


async def _async_result(value: CreditModelScore) -> CreditModelScore:
    return value


@pytest.mark.asyncio
async def test_score_uses_fixed_action_and_retains_only_opaque_refs() -> None:
    kernel = _Kernel()
    agent = GovernedCreditAgent(kernel)
    attribution, _ = _reason_evidence()

    result = await agent.score(
        application_ref="APP-001",
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        scorer=lambda: _async_result(_score(attribution)),
        agent_id="credit-agent",
    )

    assert result.attribution == attribution
    call = kernel.calls[0]
    assert call["action"] == "model:score"
    assert isinstance(call["redacted_evidence"], ModelScoreAuditEvidence)
    retained = json.dumps(call["redacted_evidence"].model_dump(mode="json"))
    assert "APP-001" not in retained
    assert "dti_ratio" not in retained
    assert "0.3" not in retained


@pytest.mark.asyncio
async def test_decide_uses_outcome_action_and_redacts_policy_internals() -> None:
    kernel = _Kernel()
    agent = GovernedCreditAgent(kernel)
    attribution, selection = _reason_evidence()

    candidate = await agent.decide(
        decision_id="DECISION-001",
        application_ref="APP-001",
        score=_score(attribution),
        reason_selection=selection,
        agent_id="credit-agent",
    )

    assert candidate.outcome.value == "decline"
    call = kernel.calls[0]
    assert call["action"] == "decision:decline"
    assert isinstance(call["redacted_evidence"], DecisionAuditEvidence)
    retained = json.dumps(call["redacted_evidence"].model_dump(mode="json"))
    assert "DECISION-001" not in retained
    assert "APP-001" not in retained
    assert "dti_ratio" not in retained
    assert "0.3" not in retained
    assert {link.relation for link in call["links"]} == {"decision", "model"}


@pytest.mark.asyncio
async def test_override_is_separately_linked_and_notice_uses_safe_evidence() -> None:
    kernel = _Kernel()
    lineage = _LineageValidator()
    agent = GovernedCreditAgent(
        kernel,
        review_lineage_validator=lineage,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    )
    attribution, _ = _reason_evidence()
    approve = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-OVERRIDE",
        application_ref="APP-001",
        pd_score=0.01,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
    )

    await agent.override(
        candidate=approve,
        parent_escalation_id="ESCALATION-001",
        agent_id="underwriter",
    )
    prepared = _record()
    issued = await agent.issue_notice(
        candidate=prepared.candidate,
        notice=prepared.notice,
        agent_id="notice-agent",
    )

    override_call, notice_call = kernel.calls
    assert override_call["action"] == "decision:override"
    assert lineage.calls == [("ESCALATION-001", approve)]
    assert any(
        link.relation == "parent"
        and link.target == EvidenceRef(namespace="hitl-escalation", value="ESCALATION-001")
        for link in override_call["links"]
    )
    assert notice_call["action"] == "notice:issue"
    assert isinstance(notice_call["redacted_evidence"], NoticeIssueEvidence)
    assert issued == prepared.evidence
    serialized = json.dumps(issued.model_dump(mode="json"))
    assert prepared.notice.applicant.full_name not in serialized
    assert prepared.rendered.body not in serialized


@pytest.mark.asyncio
async def test_denied_notice_does_not_retain_pii_or_consume_provider_capacity() -> None:
    prepared = _record()
    provider = InMemoryPreparedNoticeProvider(max_records=1)
    clock = lambda: datetime(2026, 8, 30, tzinfo=UTC)  # noqa: E731
    denied = GovernedCreditAgent(
        _RejectKernel(),
        notice_provider=provider,
        clock=clock,
    )

    with pytest.raises(PermissionDeniedError):
        await denied.issue_notice(candidate=prepared.candidate, notice=prepared.notice)

    assert await provider.get(prepared.evidence.notice_ref) is None

    allowed = GovernedCreditAgent(_Kernel(), notice_provider=provider, clock=clock)
    await allowed.issue_notice(candidate=prepared.candidate, notice=prepared.notice)
    assert await provider.get(prepared.evidence.notice_ref) == prepared


@pytest.mark.asyncio
async def test_review_candidate_cannot_be_submitted_as_override() -> None:
    kernel = _Kernel()
    agent = GovernedCreditAgent(kernel)
    attribution, _ = _reason_evidence()
    review = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-REVIEW",
        application_ref="APP-001",
        pd_score=0.10,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
    )

    with pytest.raises(ValueError, match="final approve or decline"):
        await agent.override(candidate=review, parent_escalation_id="ESCALATION-001")
    assert kernel.calls == []


@pytest.mark.asyncio
async def test_override_without_trusted_lineage_fails_inside_governed_executor() -> None:
    kernel = _Kernel()
    agent = GovernedCreditAgent(kernel)
    attribution, _ = _reason_evidence()
    approve = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-REVIEW",
        application_ref="APP-001",
        pd_score=0.01,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
    )

    with pytest.raises(RuntimeError, match="trusted review-lineage validator"):
        await agent.override(candidate=approve, parent_escalation_id="ESCALATION-001")

    assert kernel.calls[0]["action"] == "decision:override"
