"""Focused ON_DECISION controls for truthful credit outcomes."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard.domains.finance.credit_risk.agent_templates import (
    CreditDecisionCandidate,
    CreditDecisionOutcome,
    CreditDecisionPolicy,
)
from agentguard.domains.finance.credit_risk.attribution import (
    AdverseContribution,
    AttributionMethod,
    AttributionResult,
)
from agentguard.domains.finance.credit_risk.decision_guardrails import (
    AttributionIntegrityGuardrail,
    DecisionBandGuardrail,
    DecisionEvidenceGuardrail,
    PolicyReasonIntegrityGuardrail,
    ProtectedAttributeGuardrail,
    ReasonCodeGuardrail,
    ReviewReasonIntegrityGuardrail,
)
from agentguard.domains.finance.credit_risk.decision_reasons import PolicyDenialSelection
from agentguard.domains.finance.credit_risk.governed_agent import decision_audit_evidence
from agentguard.domains.finance.credit_risk.reason_codes import (
    ReasonCode,
    ReasonCodeMapper,
    ReasonCodeRegistry,
)
from agentguard.exceptions import AdverseActionFailure
from agentguard.guardrails import (
    GuardrailContext,
    GuardrailEffect,
    GuardrailStage,
    IdentitySnapshot,
)
from agentguard.guardrails.reason_codes import (
    AA_ATTRIBUTION_MODEL_MISMATCH,
    AA_CODE_NOT_ATTRIBUTED,
    AA_NO_REASON_CODES,
    AA_POLICY_REASON_UNBOUND,
    AA_REVIEW_REASON_UNBOUND,
    AA_UNKNOWN_CODE,
    FAIR_PROTECTED_FEATURE_IN_INPUT,
    HITL_REVIEW_BAND,
    PII_UNSAFE_DECISION_EVIDENCE,
)
from tests.unit.domains.finance.test_decision_reasons import bundle, facts
from tests.unit.domains.finance.test_decision_reasons import policy_denial as _overlay_denial
from tests.unit.domains.finance.test_decision_reasons import registry as _overlay_registry
from tests.unit.domains.finance.test_decision_reasons import review_judgment as _overlay_judgment

_APPLICATION = "APPLICATION-001"
_DECISION = "DECISION-001"
_ESCALATION = "ESCALATION-001"


def _registry() -> ReasonCodeRegistry:
    return ReasonCodeRegistry(
        taxonomy_version="2026.1",
        ecoa_reason_codes=(
            ReasonCode(
                code="AG-RB-TEST-001",
                code_set_version="2026.1",
                consumer_text="Credit score did not meet the required level",
                reg_b_ref="12 CFR Part 1002 Appendix C",
            ),
            ReasonCode(
                code="AG-RB-TEST-002",
                code_set_version="2026.1",
                consumer_text="Excessive obligations in relation to income",
                reg_b_ref="12 CFR Part 1002 Appendix C",
            ),
        ),
        ecoa_feature_codes={
            "dti_ratio": "AG-RB-TEST-002",
            "fico_score": "AG-RB-TEST-001",
        },
    )


def _attribution() -> AttributionResult:
    return AttributionResult(
        model_id="pd-model",
        model_version="1",
        reference_id="reference-1",
        method=AttributionMethod.SCORECARD_POINTS_LOST,
        feature_names=("dti_ratio", "fico_score"),
        contributions=(
            AdverseContribution(feature_name="fico_score", value=2.0),
            AdverseContribution(feature_name="dti_ratio", value=1.0),
        ),
    )


def _candidate(*, pd_score: float = 0.30) -> CreditDecisionCandidate:
    attribution = _attribution()
    return CreditDecisionPolicy().evaluate(
        decision_id="DECISION-001",
        application_ref="APPLICATION-001",
        pd_score=pd_score,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
        reason_selection=ReasonCodeMapper(_registry()).map(attribution),
    )


def _context(candidate: CreditDecisionCandidate | None = None) -> GuardrailContext:
    selected = candidate or _candidate()
    return GuardrailContext.model_validate(
        {
            "trace_id": "trace-1",
            "invocation_id": "invocation-1",
            "stage": GuardrailStage.ON_DECISION,
            "identity": IdentitySnapshot(agent_id="agent-1", name="Credit Agent"),
            "action": f"decision:{selected.outcome.value}",
            "resource": "application/opaque-1",
            "payload": selected.to_payload(),
            "attributes": {"redacted_evidence": decision_audit_evidence(selected)},
        }
    )


@pytest.mark.asyncio
async def test_decision_evidence_rejects_envelope_discriminator_mismatch() -> None:
    context = _context()
    changed = context.payload.model_copy(update={"outcome": "approve"})
    outcome = await DecisionEvidenceGuardrail().evaluate(
        context.model_copy(update={"payload": changed})
    )

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (PII_UNSAFE_DECISION_EVIDENCE,)


@pytest.mark.asyncio
async def test_decision_controls_skip_the_notice_boundary() -> None:
    context = _context().model_copy(update={"action": "notice:issue"})

    outcomes = [
        await guardrail.evaluate(context)
        for guardrail in (
            ProtectedAttributeGuardrail({"fico_score"}),
            DecisionBandGuardrail(),
            ReasonCodeGuardrail(_registry()),
            AttributionIntegrityGuardrail(ReasonCodeMapper(_registry()), _registry()),
        )
    ]

    assert all(outcome.effect is GuardrailEffect.ALLOW for outcome in outcomes)


@pytest.mark.asyncio
async def test_decision_evidence_rejects_unsafe_audit_projection() -> None:
    context = _context().model_copy(
        update={"attributes": {"redacted_evidence": {"applicant_name": "Private Person"}}}
    )

    outcome = await DecisionEvidenceGuardrail().evaluate(context)

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (PII_UNSAFE_DECISION_EVIDENCE,)


@pytest.mark.asyncio
async def test_decision_action_must_match_typed_outcome() -> None:
    context = _context().model_copy(update={"action": "decision:approve"})

    outcome = await DecisionEvidenceGuardrail().evaluate(context)

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (PII_UNSAFE_DECISION_EVIDENCE,)


@pytest.mark.asyncio
async def test_protected_attribute_checks_complete_evaluated_schema() -> None:
    outcome = await ProtectedAttributeGuardrail({"fico_score"}).evaluate(_context())

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (FAIR_PROTECTED_FEATURE_IN_INPUT,)


@pytest.mark.asyncio
async def test_review_band_escalates_without_becoming_decline() -> None:
    candidate = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-REVIEW",
        application_ref="APPLICATION-001",
        pd_score=0.10,
        model_id="pd-model",
        model_version="1",
    )
    outcome = await DecisionBandGuardrail().evaluate(_context(candidate))

    assert candidate.outcome.value == "review"
    assert outcome.effect is GuardrailEffect.ESCALATE
    assert outcome.reason_codes == (HITL_REVIEW_BAND,)


@pytest.mark.asyncio
async def test_decline_without_reasons_is_denied() -> None:
    candidate = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-001",
        application_ref="APPLICATION-001",
        pd_score=0.30,
        model_id="pd-model",
        model_version="1",
    )
    outcome = await ReasonCodeGuardrail(_registry()).evaluate(_context(candidate))

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_NO_REASON_CODES,)


@pytest.mark.asyncio
async def test_typed_mapping_failure_survives_to_signed_guardrail_outcome() -> None:
    candidate = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-001",
        application_ref="APPLICATION-001",
        pd_score=0.30,
        model_id="pd-model",
        model_version="1",
        reason_failure=AdverseActionFailure.NO_TRUE_FACTORS,
    )
    outcome = await ReasonCodeGuardrail(_registry()).evaluate(_context(candidate))

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AdverseActionFailure.NO_TRUE_FACTORS.value,)


@pytest.mark.asyncio
async def test_unknown_reason_code_is_denied() -> None:
    candidate = _candidate()
    assert candidate.reason_selection is not None
    first = candidate.reason_selection.reasons[0]
    unknown = first.model_copy(
        update={
            "code": first.code.model_copy(
                update={"code": "AG-RB-UNKNOWN-001"},
            )
        }
    )
    selection = candidate.reason_selection.model_copy(
        update={"reasons": (unknown, *candidate.reason_selection.reasons[1:])}
    )
    changed = candidate.model_copy(update={"reason_selection": selection})

    outcome = await ReasonCodeGuardrail(_registry()).evaluate(_context(changed))

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_UNKNOWN_CODE,)


@pytest.mark.asyncio
async def test_model_provenance_mismatch_is_denied() -> None:
    candidate = _candidate().model_copy(update={"model_version": "2"})
    registry = _registry()
    outcome = await AttributionIntegrityGuardrail(
        ReasonCodeMapper(registry),
        registry,
    ).evaluate(_context(candidate))

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_ATTRIBUTION_MODEL_MISMATCH,)


@pytest.mark.asyncio
async def test_reason_text_not_produced_by_mapper_is_denied() -> None:
    candidate = _candidate()
    assert candidate.reason_selection is not None
    first = candidate.reason_selection.reasons[0]
    fabricated = first.model_copy(
        update={
            "code": first.code.model_copy(
                update={"consumer_text": "Fabricated reason text"},
            )
        }
    )
    selection = candidate.reason_selection.model_copy(
        update={"reasons": (fabricated, *candidate.reason_selection.reasons[1:])}
    )
    changed = candidate.model_copy(update={"reason_selection": selection})
    registry = _registry()

    outcome = await AttributionIntegrityGuardrail(
        ReasonCodeMapper(registry),
        registry,
    ).evaluate(_context(changed))

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_CODE_NOT_ATTRIBUTED,)


@pytest.mark.asyncio
async def test_valid_decline_reason_and_attribution_controls_allow() -> None:
    registry = _registry()
    context = _context()

    reason_outcome = await ReasonCodeGuardrail(registry).evaluate(context)
    attribution_outcome = await AttributionIntegrityGuardrail(
        ReasonCodeMapper(registry),
        registry,
    ).evaluate(context)

    assert reason_outcome.effect is GuardrailEffect.ALLOW
    assert attribution_outcome.effect is GuardrailEffect.ALLOW


def _denial(**kwargs: object) -> PolicyDenialSelection:
    return _overlay_denial(
        application_ref=_APPLICATION,
        decision_id=_DECISION,
        **kwargs,  # type: ignore[arg-type]
    )


def _policy_candidate(denial: PolicyDenialSelection | None = None) -> CreditDecisionCandidate:
    """An application the PD band would approve, declined by a hard overlay rule."""

    attribution = _attribution()
    return CreditDecisionPolicy().evaluate(
        decision_id=_DECISION,
        application_ref=_APPLICATION,
        pd_score=0.01,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
        policy_denial=denial if denial is not None else _denial(),
    )


def _judgment_candidate(
    *,
    escalation_id: str = _ESCALATION,
    codes: tuple[str, ...] = ("AG-RB-C1-16",),
) -> CreditDecisionCandidate:
    """A reviewed application the underwriter declined on their own judgment."""

    attribution = _attribution()
    return CreditDecisionCandidate(
        decision_id=_DECISION,
        application_ref=_APPLICATION,
        outcome=CreditDecisionOutcome.DECLINE,
        pd_score=0.10,
        policy_id="pd-bands",
        policy_version="1",
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
        review_judgment=_overlay_judgment(
            application_ref=_APPLICATION,
            decision_id=_DECISION,
            escalation_id=escalation_id,
            codes=codes,
        ),
    )


def _override_context(candidate: CreditDecisionCandidate) -> GuardrailContext:
    return _context(candidate).model_copy(update={"action": "decision:override"})


@pytest.mark.asyncio
async def test_policy_overlay_decline_passes_every_reason_control() -> None:
    context = _context(_policy_candidate())
    overlay = _overlay_registry()

    outcomes = [
        await PolicyReasonIntegrityGuardrail(bundle()).evaluate(context),
        await ReasonCodeGuardrail(overlay).evaluate(context),
        await AttributionIntegrityGuardrail(ReasonCodeMapper(overlay), overlay).evaluate(context),
        await ReviewReasonIntegrityGuardrail(overlay).evaluate(context),
    ]

    assert all(outcome.effect is GuardrailEffect.ALLOW for outcome in outcomes)


@pytest.mark.asyncio
async def test_policy_reason_swapped_for_another_code_is_denied() -> None:
    payload = _denial().model_dump()
    payload["findings"][0]["code"] = _overlay_registry().ecoa_code("AG-RB-C1-01").model_dump()
    candidate = _policy_candidate(PolicyDenialSelection.model_validate(payload))

    outcome = await PolicyReasonIntegrityGuardrail(bundle()).evaluate(_context(candidate))

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_POLICY_REASON_UNBOUND,)


@pytest.mark.asyncio
async def test_policy_denial_omitting_a_rule_that_also_fired_is_denied() -> None:
    complete = _denial(declared=facts(application_complete=0.0, collateral_ltv=0.97))
    payload = complete.model_dump()
    payload["findings"] = payload["findings"][:1]
    candidate = _policy_candidate(PolicyDenialSelection.model_validate(payload))

    outcome = await PolicyReasonIntegrityGuardrail(bundle()).evaluate(_context(candidate))

    assert len(complete.findings) == 2
    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_POLICY_REASON_UNBOUND,)


@pytest.mark.asyncio
async def test_policy_reason_from_an_unenforced_bundle_version_is_denied() -> None:
    candidate = _policy_candidate(_denial(overlay=bundle(bundle_version="2026.09")))

    outcome = await PolicyReasonIntegrityGuardrail(bundle()).evaluate(_context(candidate))

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_POLICY_REASON_UNBOUND,)


def test_a_non_model_reason_from_another_application_cannot_be_attached() -> None:
    with pytest.raises(ValidationError, match="name this application decision"):
        CreditDecisionPolicy().evaluate(
            decision_id=_DECISION,
            application_ref=_APPLICATION,
            pd_score=0.01,
            model_id="pd-model",
            model_version="1",
            attribution=_attribution(),
            policy_denial=_overlay_denial(application_ref="APPLICATION-OTHER"),
        )


@pytest.mark.asyncio
async def test_reviewed_override_decline_passes_every_reason_control() -> None:
    context = _override_context(_judgment_candidate())
    overlay = _overlay_registry()

    outcomes = [
        await ReviewReasonIntegrityGuardrail(overlay).evaluate(context),
        await ReasonCodeGuardrail(overlay).evaluate(context),
        await AttributionIntegrityGuardrail(ReasonCodeMapper(overlay), overlay).evaluate(context),
        await PolicyReasonIntegrityGuardrail(bundle()).evaluate(context),
    ]

    assert all(outcome.effect is GuardrailEffect.ALLOW for outcome in outcomes)


@pytest.mark.asyncio
async def test_judgmental_reason_without_a_reviewed_override_is_denied() -> None:
    context = _context(_judgment_candidate())

    outcome = await ReviewReasonIntegrityGuardrail(_overlay_registry()).evaluate(context)

    assert context.action == "decision:decline"
    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_REVIEW_REASON_UNBOUND,)


@pytest.mark.asyncio
async def test_judgmental_reason_outside_the_deployed_registry_is_denied() -> None:
    narrow = ReasonCodeRegistry.with_appendix_c(
        taxonomy_version="2026.07",
        ecoa_feature_codes={"dti_ratio": "AG-RB-C1-09"},
        additional_ecoa_codes=(),
    )
    trimmed = ReasonCodeRegistry(
        taxonomy_version="2026.07",
        ecoa_reason_codes=(narrow.ecoa_code("AG-RB-C1-09"),),
        ecoa_feature_codes={"dti_ratio": "AG-RB-C1-09"},
    )
    context = _override_context(_judgment_candidate())

    outcome = await ReviewReasonIntegrityGuardrail(trimmed).evaluate(context)

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_REVIEW_REASON_UNBOUND,)


@pytest.mark.asyncio
async def test_a_decline_with_no_basis_at_all_is_still_unattributed() -> None:
    candidate = CreditDecisionPolicy().evaluate(
        decision_id=_DECISION,
        application_ref=_APPLICATION,
        pd_score=0.30,
        model_id="pd-model",
        model_version="1",
        attribution=_attribution(),
    )
    registry = _registry()

    outcome = await AttributionIntegrityGuardrail(
        ReasonCodeMapper(registry),
        registry,
    ).evaluate(_context(candidate))

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (AA_CODE_NOT_ATTRIBUTED,)
