"""Non-model decline reasons are derived from evidence, never asserted."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agentguard.domains.finance.credit_risk.decision_reasons import (
    CreditPolicyBundle,
    CreditPolicyRule,
    JudgmentalReason,
    PolicyComparison,
    PolicyDenialSelection,
    PolicyFact,
    PolicyRuleFinding,
    ReviewJudgment,
)
from agentguard.domains.finance.credit_risk.reason_codes import ReasonCodeRegistry
from agentguard.exceptions import AdverseActionError, AdverseActionFailure

TAXONOMY = "2026.07"
APPLICATION_REF = "APP-001"
DECISION_ID = "DECISION-001"
REVIEWED_AT = datetime(2026, 8, 28, 9, 30, tzinfo=UTC)


def registry() -> ReasonCodeRegistry:
    """Appendix C wording plus the model-feature bindings the tests share."""

    return ReasonCodeRegistry.with_appendix_c(
        taxonomy_version=TAXONOMY,
        ecoa_feature_codes={"dti_ratio": "AG-RB-C1-09", "fico_score": "AG-RB-C1-15"},
    )


def bundle(*, bundle_version: str = "2026.08") -> CreditPolicyBundle:
    """A three-rule credit-policy overlay over a declared fact schema."""

    return CreditPolicyBundle(
        bundle_id="retail-overlay",
        bundle_version=bundle_version,
        registry=registry(),
        rules=(
            CreditPolicyRule(
                rule_id="POLICY-APPLICATION-COMPLETE",
                reason_code_id="AG-RB-C1-01",
                fact_name="application_complete",
                comparison=PolicyComparison.LESS_THAN,
                threshold=1.0,
                severity=5,
            ),
            CreditPolicyRule(
                rule_id="POLICY-COLLATERAL-LTV",
                reason_code_id="AG-RB-C1-23",
                fact_name="collateral_ltv",
                comparison=PolicyComparison.GREATER_THAN,
                threshold=0.90,
                severity=3,
            ),
            CreditPolicyRule(
                rule_id="POLICY-BANKRUPTCY-SEASONING",
                reason_code_id="AG-RB-C1-21",
                fact_name="years_since_bankruptcy",
                comparison=PolicyComparison.LESS_THAN,
                threshold=2.0,
                severity=3,
            ),
        ),
    )


def facts(
    *,
    application_complete: float = 1.0,
    collateral_ltv: float = 0.50,
    years_since_bankruptcy: float = 9.0,
) -> tuple[PolicyFact, ...]:
    """The complete declared fact schema for one application."""

    return (
        PolicyFact(name="application_complete", value=application_complete),
        PolicyFact(name="collateral_ltv", value=collateral_ltv),
        PolicyFact(name="years_since_bankruptcy", value=years_since_bankruptcy),
    )


def policy_denial(
    *,
    application_ref: str = APPLICATION_REF,
    decision_id: str = DECISION_ID,
    overlay: CreditPolicyBundle | None = None,
    declared: tuple[PolicyFact, ...] | None = None,
) -> PolicyDenialSelection:
    """A collateral-rule denial recorded for one application decision."""

    denial = (overlay or bundle()).evaluate(
        application_ref=application_ref,
        decision_id=decision_id,
        facts=declared if declared is not None else facts(collateral_ltv=0.97),
    )
    assert denial is not None
    return denial


def review_judgment(
    *,
    application_ref: str = APPLICATION_REF,
    decision_id: str = DECISION_ID,
    escalation_id: str = "ESCALATION-001",
    codes: tuple[str, ...] = ("AG-RB-C1-16",),
) -> ReviewJudgment:
    """A completed reviewer's own principal reasons for declining."""

    known = registry()
    return ReviewJudgment(
        taxonomy_version=TAXONOMY,
        application_ref=application_ref,
        decision_id=decision_id,
        escalation_id=escalation_id,
        reviewer_id="underwriter-7",
        decided_at=REVIEWED_AT,
        reasons=tuple(
            JudgmentalReason(code=known.ecoa_code(code), rank=rank)
            for rank, code in enumerate(codes, 1)
        ),
    )


def test_bundle_reports_no_denial_when_no_rule_triggers() -> None:
    assert (
        bundle().evaluate(
            application_ref=APPLICATION_REF,
            decision_id=DECISION_ID,
            facts=facts(),
        )
        is None
    )


def test_bundle_requires_the_complete_declared_fact_schema() -> None:
    partial = facts(collateral_ltv=0.97)[:2]

    with pytest.raises(AdverseActionError) as exc_info:
        bundle().evaluate(
            application_ref=APPLICATION_REF,
            decision_id=DECISION_ID,
            facts=partial,
        )

    assert exc_info.value.failure is AdverseActionFailure.UNMAPPED_FEATURES


def test_bundle_rejects_a_rule_code_outside_the_versioned_registry() -> None:
    with pytest.raises(AdverseActionError) as exc_info:
        CreditPolicyBundle(
            bundle_id="retail-overlay",
            bundle_version="2026.08",
            registry=registry(),
            rules=(
                CreditPolicyRule(
                    rule_id="POLICY-INVENTED",
                    reason_code_id="AG-RB-INVENTED-01",
                    fact_name="collateral_ltv",
                    comparison=PolicyComparison.GREATER_THAN,
                    threshold=0.90,
                    severity=1,
                ),
            ),
        )

    assert exc_info.value.failure is AdverseActionFailure.TAXONOMY_MISMATCH


def test_findings_are_ordered_by_severity_then_rule_identifier() -> None:
    denial = policy_denial(
        declared=facts(
            application_complete=0.0,
            collateral_ltv=0.97,
            years_since_bankruptcy=0.5,
        )
    )

    assert tuple(finding.rule_id for finding in denial.findings) == (
        "POLICY-APPLICATION-COMPLETE",
        "POLICY-BANKRUPTCY-SEASONING",
        "POLICY-COLLATERAL-LTV",
    )
    assert tuple(finding.rank for finding in denial.findings) == (1, 2, 3)


def test_a_finding_cannot_claim_a_rule_that_did_not_trigger() -> None:
    known = registry()

    with pytest.raises(ValidationError, match="actually triggered"):
        PolicyRuleFinding(
            rule_id="POLICY-COLLATERAL-LTV",
            code=known.ecoa_code("AG-RB-C1-23"),
            fact_name="collateral_ltv",
            comparison=PolicyComparison.GREATER_THAN,
            threshold=0.90,
            observed_value=0.40,
            severity=3,
            rank=1,
        )


def test_a_finding_cannot_cite_a_value_the_recorded_facts_do_not_hold() -> None:
    payload = policy_denial().model_dump()
    payload["findings"][0]["observed_value"] = 0.99

    with pytest.raises(ValidationError, match="recorded declared fact"):
        PolicyDenialSelection.model_validate(payload)


def test_policy_reason_digest_binds_the_application_and_decision() -> None:
    mine = policy_denial()
    other = policy_denial(application_ref="APP-OTHER", decision_id="DECISION-OTHER")

    assert mine.findings == other.findings
    assert mine.reason_digest(mine.findings[0]) != other.reason_digest(other.findings[0])


def test_policy_reason_digest_rejects_a_finding_from_another_denial() -> None:
    mine = policy_denial()
    other = policy_denial(
        declared=facts(application_complete=0.0),
    )

    with pytest.raises(ValueError, match="does not belong"):
        mine.reason_digest(other.findings[0])


def _judgment_with(reasons: tuple[JudgmentalReason, ...]) -> ReviewJudgment:
    return ReviewJudgment(
        taxonomy_version=TAXONOMY,
        application_ref=APPLICATION_REF,
        decision_id=DECISION_ID,
        escalation_id="ESCALATION-001",
        reviewer_id="underwriter-7",
        decided_at=REVIEWED_AT,
        reasons=reasons,
    )


def test_review_judgment_requires_contiguous_ranks() -> None:
    reason = JudgmentalReason(code=registry().ecoa_code("AG-RB-C1-16"), rank=2)

    with pytest.raises(ValidationError, match="contiguous"):
        _judgment_with((reason,))


def test_review_judgment_requires_unique_codes() -> None:
    code = registry().ecoa_code("AG-RB-C1-16")

    with pytest.raises(ValidationError, match="unique"):
        _judgment_with((JudgmentalReason(code=code, rank=1), JudgmentalReason(code=code, rank=2)))


def test_review_judgment_rejects_a_code_from_another_taxonomy() -> None:
    stale = registry().ecoa_code("AG-RB-C1-16").model_copy(update={"code_set_version": "2025.01"})

    with pytest.raises(ValidationError, match="taxonomy_version"):
        ReviewJudgment(
            taxonomy_version=TAXONOMY,
            application_ref=APPLICATION_REF,
            decision_id=DECISION_ID,
            escalation_id="ESCALATION-001",
            reviewer_id="underwriter-7",
            decided_at=REVIEWED_AT,
            reasons=(JudgmentalReason(code=stale, rank=1),),
        )


def test_review_reason_digest_binds_the_escalation_and_reviewer() -> None:
    mine = review_judgment()
    replayed = review_judgment(escalation_id="ESCALATION-OTHER")
    impersonated = mine.model_copy(update={"reviewer_id": "underwriter-9"})

    assert mine.reasons == replayed.reasons == impersonated.reasons
    digests = {
        mine.reason_digest(mine.reasons[0]),
        replayed.reason_digest(replayed.reasons[0]),
        impersonated.reason_digest(impersonated.reasons[0]),
    }
    assert len(digests) == 3


def test_selections_survive_a_json_round_trip_unchanged() -> None:
    denial = policy_denial()
    judgment = review_judgment()

    assert PolicyDenialSelection.model_validate_json(denial.model_dump_json()) == denial
    assert ReviewJudgment.model_validate_json(judgment.model_dump_json()) == judgment
