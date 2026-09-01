"""Real-kernel credit governance tests across decision, HITL, notice, and audit."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentguard.compliance.continuation import ApprovalDisposition
from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.escalation_store import EscalationStore
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.domains.finance.credit_risk import (
    AttributionIntegrityGuardrail,
    AttributionMethod,
    AttributionResult,
    CreditDecisionCandidate,
    CreditDecisionOutcome,
    CreditDecisionPolicy,
    CreditModelScore,
    DecisionBandGuardrail,
    DecisionEvidenceGuardrail,
    GovernedCreditAgent,
    InMemoryPreparedNoticeProvider,
    ModelFairnessStatus,
    ModelGovernanceEvidence,
    ModelProvenanceGuardrail,
    ModelValidationStatus,
    NoticeCompletenessGuardrail,
    NoticeRenderer,
    PolicyReasonIntegrityGuardrail,
    PrincipalReasonSelection,
    ProtectedAttributeGuardrail,
    ReasonCodeGuardrail,
    ReasonCodeMapper,
    ReasonCodeRegistry,
    ReviewEscalationVerifier,
    ReviewReasonIntegrityGuardrail,
    StaticModelGovernanceEvidenceProvider,
    feature_schema_digest,
    find_unresolved_declines,
)
from agentguard.domains.finance.credit_risk.attribution import AdverseContribution
from agentguard.exceptions import (
    EscalationRequiredError,
    PermissionDeniedError,
)
from agentguard.guardrails.kernel import GovernanceKernel
from agentguard.guardrails.reason_codes import AA_NO_REASON_CODES, HITL_REVIEW_BAND
from agentguard.models import EvidenceRef
from tests.unit.domains.finance.test_decision_reasons import (
    bundle,
    policy_denial,
    review_judgment,
)
from tests.unit.domains.finance.test_notice_renderer import _denial
from tests.unit.guardrails.test_kernel_post_resume import (
    STORE_KEY,
    _Authenticator,
    _TestProtector,
)

if TYPE_CHECKING:
    from pathlib import Path


NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
APPLICATION_ID = "APP-001"
DECISION_ID = "DECISION-001"
MODEL_ID = "credit-logit"
MODEL_VERSION = "2026.08"
PD_SCORE = 0.314159
REASON_TEXT = "Excessive obligations in relation to income"


class _CountingPolicy(CreditDecisionPolicy):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def evaluate(self, **kwargs: object):  # type: ignore[no-untyped-def]
        self.calls += 1
        return super().evaluate(**kwargs)  # type: ignore[arg-type]


def _reason_registry() -> ReasonCodeRegistry:
    return ReasonCodeRegistry.with_appendix_c(
        taxonomy_version="2026.07",
        ecoa_feature_codes={"dti_ratio": "AG-RB-C1-09"},
    )


def _attribution() -> AttributionResult:
    return AttributionResult(
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        reference_id="portfolio-2026q2",
        method=AttributionMethod.COEFFICIENT_DELTA,
        feature_names=("dti_ratio",),
        contributions=(AdverseContribution(feature_name="dti_ratio", value=0.42),),
    )


def _model_evidence() -> ModelGovernanceEvidence:
    return ModelGovernanceEvidence(
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        validation_status=ModelValidationStatus.VALIDATED,
        fairness_status=ModelFairnessStatus.PASSED,
        feature_schema_digest=feature_schema_digest(_attribution().feature_names),
        validation_ref="a" * 64,
        fairness_ref="b" * 64,
        validated_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=1),
    )


def _rbac(*allowed_actions: str) -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="credit-agent",
                permissions=[
                    Permission(action=action, resource="*", effect="allow")
                    for action in allowed_actions
                ],
            )
        ]
    )


async def _kernel_and_agent(
    tmp_path: Path,
    *,
    allowed_actions: tuple[str, ...],
    policy: CreditDecisionPolicy | None = None,
) -> tuple[GovernanceKernel, GovernedCreditAgent, AppendOnlyAuditLog, str]:
    registry = AgentRegistry()
    identity = await registry.register(name="Credit Agent", roles=["credit-agent"])
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    notice_provider = InMemoryPreparedNoticeProvider()
    reason_registry = _reason_registry()
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    guardrails = (
        DecisionEvidenceGuardrail(),
        ProtectedAttributeGuardrail({"race", "sex", "national_origin"}),
        ModelProvenanceGuardrail(
            StaticModelGovernanceEvidenceProvider((_model_evidence(),)),
            clock=lambda: NOW,
        ),
        DecisionBandGuardrail(),
        ReasonCodeGuardrail(reason_registry),
        AttributionIntegrityGuardrail(ReasonCodeMapper(reason_registry), reason_registry),
        PolicyReasonIntegrityGuardrail(bundle()),
        ReviewReasonIntegrityGuardrail(reason_registry),
        NoticeCompletenessGuardrail(
            notice_provider,
            clock=lambda: NOW + timedelta(days=3),
        ),
    )
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac(*allowed_actions),
        audit_log=audit,
        policy_engine=PolicyEngine(policy_dirs=[policy_dir]),
        guardrails=guardrails,
        escalation_store=EscalationStore(
            tmp_path / "escalations",
            signing_key=STORE_KEY,
        ),
        escalation_ttl=timedelta(minutes=10),
        approver_authenticator=_Authenticator(),
        continuation_protector=_TestProtector(),
    )
    agent = GovernedCreditAgent(
        kernel,
        policy=policy,
        notice_provider=notice_provider,
        review_lineage_validator=ReviewEscalationVerifier(audit),
        clock=lambda: NOW + timedelta(days=3),
    )
    return kernel, agent, audit, identity.agent_id


def _score(pd_score: float = PD_SCORE) -> CreditModelScore:
    return CreditModelScore(pd_score=pd_score, attribution=_attribution())


def _reason_selection() -> object:
    return ReasonCodeMapper(_reason_registry()).map(_attribution())


def _contains_number(value: object, expected: float) -> bool:
    if isinstance(value, dict):
        return any(_contains_number(item, expected) for item in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_number(item, expected) for item in value)
    return isinstance(value, float) and value == expected


@pytest.mark.asyncio
async def test_matching_notice_resolves_decline_without_retaining_private_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-private-evidence-p")
    _, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:decline", "notice:issue"),
    )
    candidate = await agent.decide(
        decision_id=DECISION_ID,
        application_ref=APPLICATION_ID,
        score=_score(),
        reason_selection=_reason_selection(),  # type: ignore[arg-type]
        agent_id=agent_id,
    )
    notice_evidence = await agent.issue_notice(
        candidate=candidate,
        notice=_denial(),
        agent_id=agent_id,
    )

    assert await find_unresolved_declines(audit) == ()
    snapshot = await audit.read_verified(require_checkpoint=True)
    assert snapshot.verification.attestable
    serialized = json.dumps(
        [event.model_dump(mode="json") for event in snapshot.events],
        sort_keys=True,
    )
    rendered_notice = NoticeRenderer().render(_denial())
    forbidden = (
        APPLICATION_ID,
        DECISION_ID,
        "Alex Example",
        "100 Main Street",
        "pd_score",
        "dti_ratio",
        "adverse_contribution",
        REASON_TEXT,
        rendered_notice.body,
    )
    assert all(secret not in serialized for secret in forbidden)
    assert not any(_contains_number(event.payload_redacted, PD_SCORE) for event in snapshot.events)
    assert not any(_contains_number(event.payload_redacted, 0.42) for event in snapshot.events)
    assert notice_evidence.body_sha256 in serialized
    assert '"relation": "decision"' in serialized
    assert '"relation": "notice"' in serialized
    assert '"relation": "model"' in serialized


@pytest.mark.asyncio
async def test_decline_without_reasons_is_signed_denied_and_never_delivered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-missing-reasons-pa")
    _, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:decline",),
    )

    with pytest.raises(PermissionDeniedError):
        await agent.decide(
            decision_id=DECISION_ID,
            application_ref=APPLICATION_ID,
            score=_score(),
            agent_id=agent_id,
        )

    snapshot = await audit.read_verified(require_checkpoint=True)
    denials = [event for event in snapshot.events if event.event_type == "delivery_denied"]
    deliveries = [
        event
        for event in snapshot.events
        if event.event_type == "delivery_completed" and event.action == "decision:decline"
    ]
    assert len(denials) == 1
    assert AA_NO_REASON_CODES in denials[0].reason_codes
    assert deliveries == []


@pytest.mark.asyncio
async def test_review_escalation_resumes_without_policy_replay_or_decline_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-review-resume-padd")
    policy = _CountingPolicy()
    kernel, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:review",),
        policy=policy,
    )
    with pytest.raises(EscalationRequiredError) as caught:
        await agent.decide(
            decision_id="DECISION-REVIEW",
            application_ref=APPLICATION_ID,
            score=_score(0.10),
            agent_id=agent_id,
        )
    escalation = caught.value

    assert escalation.reason_codes == (HITL_REVIEW_BAND,)
    assert policy.calls == 1
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="HITL-DECISION-001",
        disposition=ApprovalDisposition.APPROVE,
    )
    delivered = await kernel.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    assert delivered.outcome == "review"
    assert policy.calls == 1
    events = (await audit.read_verified(require_checkpoint=True)).events
    assert not any(event.action == "decision:decline" for event in events)
    review_delivery = next(
        event
        for event in events
        if event.event_type == "delivery_completed" and event.action == "decision:review"
    )
    assert '"outcome": "review"' in json.dumps(review_delivery.payload_redacted)


@pytest.mark.asyncio
async def test_override_requires_matching_checkpoint_attested_review_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-override-lineage-p")
    policy = CreditDecisionPolicy()
    kernel, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:review", "decision:override"),
        policy=policy,
    )
    with pytest.raises(EscalationRequiredError) as caught:
        await agent.decide(
            decision_id="DECISION-REVIEW",
            application_ref=APPLICATION_ID,
            score=_score(0.10),
            agent_id=agent_id,
        )
    escalation = caught.value
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="HITL-DECISION-OVERRIDE",
        disposition=ApprovalDisposition.APPROVE,
    )
    await kernel.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )
    final_candidate = policy.evaluate(
        decision_id="DECISION-REVIEW",
        application_ref=APPLICATION_ID,
        pd_score=0.01,
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        attribution=_attribution(),
    )

    delivered = await agent.override(
        candidate=final_candidate,
        parent_escalation_id=escalation.escalation_id,
        agent_id=agent_id,
    )

    assert delivered == final_candidate
    events = (await audit.read_verified(require_checkpoint=True)).events
    override = next(
        event
        for event in events
        if event.event_type == "delivery_completed" and event.action == "decision:override"
    )
    assert any(
        link.relation == "parent"
        and link.target == EvidenceRef(namespace="hitl-escalation", value=escalation.escalation_id)
        for link in override.links
    )


@pytest.mark.asyncio
async def test_notice_issue_requires_permission_separate_from_decline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-notice-rbac-padded")
    _, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:decline",),
    )
    candidate = await agent.decide(
        decision_id=DECISION_ID,
        application_ref=APPLICATION_ID,
        score=_score(),
        reason_selection=_reason_selection(),  # type: ignore[arg-type]
        agent_id=agent_id,
    )

    with pytest.raises(PermissionDeniedError):
        await agent.issue_notice(candidate=candidate, notice=_denial(), agent_id=agent_id)

    events = (await audit.read_verified(require_checkpoint=True)).events
    assert any(
        event.event_type == "delivery_completed" and event.action == "decision:decline"
        for event in events
    )
    assert not any(
        event.event_type == "delivery_completed" and event.action == "notice:issue"
        for event in events
    )


@pytest.mark.asyncio
async def test_decision_override_requires_permission_separate_from_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-override-rbac-padd")
    policy = CreditDecisionPolicy()
    _, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:approve",),
        policy=policy,
    )
    candidate = policy.evaluate(
        decision_id="DECISION-OVERRIDE",
        application_ref=APPLICATION_ID,
        pd_score=0.01,
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        attribution=_attribution(),
    )

    with pytest.raises(PermissionDeniedError):
        await agent.override(
            candidate=candidate,
            parent_escalation_id="ESCALATION-001",
            agent_id=agent_id,
        )

    events = (await audit.read_verified(require_checkpoint=True)).events
    assert not any(
        event.event_type == "delivery_completed" and event.action == "decision:override"
        for event in events
    )


@pytest.mark.asyncio
async def test_post_review_judgmental_decline_is_governed_and_resolved_by_its_notice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-judgment-decline-p")
    kernel, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:review", "decision:override", "notice:issue"),
    )
    with pytest.raises(EscalationRequiredError) as caught:
        await agent.decide(
            decision_id="DECISION-REVIEW",
            application_ref=APPLICATION_ID,
            score=_score(0.10),
            agent_id=agent_id,
        )
    escalation = caught.value
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="HITL-DECISION-JUDGMENT",
        disposition=ApprovalDisposition.APPROVE,
    )
    await kernel.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )
    judgment = review_judgment(
        application_ref=APPLICATION_ID,
        decision_id="DECISION-REVIEW",
        escalation_id=escalation.escalation_id,
    )
    declined = CreditDecisionCandidate(
        decision_id="DECISION-REVIEW",
        application_ref=APPLICATION_ID,
        outcome=CreditDecisionOutcome.DECLINE,
        pd_score=0.10,
        policy_id="pd-bands",
        policy_version="1",
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        attribution=_attribution(),
        review_judgment=judgment,
    )

    delivered = await agent.override(
        candidate=declined,
        parent_escalation_id=escalation.escalation_id,
        agent_id=agent_id,
    )
    notice = _denial(reasons=PrincipalReasonSelection.from_decision_basis(review_judgment=judgment))
    await agent.issue_notice(candidate=delivered, notice=notice, agent_id=agent_id)

    assert delivered == declined
    assert await find_unresolved_declines(audit) == ()
    events = (await audit.read_verified(require_checkpoint=True)).events
    override = next(
        event
        for event in events
        if event.event_type == "delivery_completed" and event.action == "decision:override"
    )
    serialized = json.dumps(
        [event.model_dump(mode="json") for event in events],
        sort_keys=True,
    )
    assert override.result == "allowed"
    assert "underwriter-7" not in serialized
    assert "Poor credit performance with us" not in serialized


@pytest.mark.asyncio
async def test_hard_policy_decline_overrides_the_approve_band_and_states_its_rule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-policy-decline-pad")
    _, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:decline", "notice:issue"),
    )
    denial = policy_denial(application_ref=APPLICATION_ID, decision_id=DECISION_ID)

    candidate = await agent.decide(
        decision_id=DECISION_ID,
        application_ref=APPLICATION_ID,
        score=_score(0.01),
        policy_denial=denial,
        agent_id=agent_id,
    )
    notice = _denial(reasons=PrincipalReasonSelection.from_decision_basis(policy_denial=denial))
    await agent.issue_notice(candidate=candidate, notice=notice, agent_id=agent_id)

    assert candidate.outcome is CreditDecisionOutcome.DECLINE
    assert candidate.reason_selection is None
    assert await find_unresolved_declines(audit) == ()
    events = (await audit.read_verified(require_checkpoint=True)).events
    assert any(
        event.event_type == "delivery_completed" and event.action == "decision:decline"
        for event in events
    )
    serialized = json.dumps(
        [event.model_dump(mode="json") for event in events],
        sort_keys=True,
    )
    assert "POLICY-COLLATERAL-LTV" not in serialized
    assert "collateral_ltv" not in serialized


@pytest.mark.asyncio
async def test_pre_scoring_decline_is_governed_and_resolved_by_its_notice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A knockout/incomplete decline with NO model score runs the full chain,
    emits no model link, and is resolved by a notice citing the policy rule."""
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "credit-kernel-prescoring-decl-pad")
    _, agent, audit, agent_id = await _kernel_and_agent(
        tmp_path,
        allowed_actions=("decision:decline", "notice:issue"),
    )
    denial = policy_denial(application_ref=APPLICATION_ID, decision_id=DECISION_ID)

    candidate = await agent.decide_without_score(
        decision_id=DECISION_ID,
        application_ref=APPLICATION_ID,
        policy_denial=denial,
        agent_id=agent_id,
    )
    notice = _denial(reasons=PrincipalReasonSelection.from_decision_basis(policy_denial=denial))
    await agent.issue_notice(candidate=candidate, notice=notice, agent_id=agent_id)

    assert candidate.outcome is CreditDecisionOutcome.DECLINE
    assert candidate.has_model_reference is False
    assert candidate.pd_score is None
    assert await find_unresolved_declines(audit) == ()
    events = (await audit.read_verified(require_checkpoint=True)).events
    decline = next(
        event
        for event in events
        if event.event_type == "delivery_completed" and event.action == "decision:decline"
    )
    # No model reference means no model audit link on the governed decision.
    assert not any(link.relation == "model" for link in decline.links)
    serialized = json.dumps(
        [event.model_dump(mode="json") for event in events],
        sort_keys=True,
    )
    assert "POLICY-COLLATERAL-LTV" not in serialized
    assert "collateral_ltv" not in serialized
