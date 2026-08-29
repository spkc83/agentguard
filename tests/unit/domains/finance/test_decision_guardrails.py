"""Focused ON_DECISION controls for truthful credit outcomes."""

from __future__ import annotations

import pytest

from agentguard.domains.finance.credit_risk.agent_templates import (
    CreditDecisionCandidate,
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
    ProtectedAttributeGuardrail,
    ReasonCodeGuardrail,
)
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
    AA_UNKNOWN_CODE,
    FAIR_PROTECTED_FEATURE_IN_INPUT,
    HITL_REVIEW_BAND,
    PII_UNSAFE_DECISION_EVIDENCE,
)


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
