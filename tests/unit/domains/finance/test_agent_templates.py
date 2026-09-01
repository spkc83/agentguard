"""Tests for the pure credit-decision policy boundary."""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from agentguard.domains.finance.credit_risk.agent_templates import (
    CreditDecisionOutcome,
    CreditDecisionPolicy,
    CreditDecisionPolicyConfig,
)


class TestCreditDecisionPolicy:
    @pytest.mark.parametrize(
        ("pd_score", "expected"),
        [
            (0.049999, CreditDecisionOutcome.APPROVE),
            (0.05, CreditDecisionOutcome.REVIEW),
            (0.199999, CreditDecisionOutcome.REVIEW),
            (0.20, CreditDecisionOutcome.DECLINE),
        ],
    )
    def test_exact_band_boundaries(
        self,
        pd_score: float,
        expected: CreditDecisionOutcome,
    ) -> None:
        candidate = CreditDecisionPolicy().evaluate(
            decision_id="DECISION-001",
            application_ref="APPLICATION-001",
            pd_score=pd_score,
            model_id="pd-model",
            model_version="1",
        )
        assert candidate.outcome is expected
        assert candidate.requires_review is (expected is CreditDecisionOutcome.REVIEW)

    @pytest.mark.parametrize("pd_score", [-0.01, 1.01, math.inf, math.nan, True])
    def test_invalid_pd_fails_before_policy_output(self, pd_score: float) -> None:
        with pytest.raises(ValidationError):
            CreditDecisionPolicy().evaluate(
                decision_id="DECISION-001",
                application_ref="APPLICATION-001",
                pd_score=pd_score,
                model_id="pd-model",
                model_version="1",
            )

    def test_policy_config_is_versioned_and_thresholds_are_ordered(self) -> None:
        config = CreditDecisionPolicyConfig(
            policy_id="credit-policy",
            policy_version="2026-08",
            auto_approve_threshold=0.03,
            decline_threshold=0.15,
        )
        candidate = CreditDecisionPolicy(config).evaluate(
            decision_id="DECISION-001",
            application_ref="APPLICATION-001",
            pd_score=0.04,
            model_id="pd-model",
            model_version="1",
        )
        assert candidate.outcome is CreditDecisionOutcome.REVIEW
        assert (candidate.policy_id, candidate.policy_version) == (
            "credit-policy",
            "2026-08",
        )

        with pytest.raises(ValidationError, match="below"):
            CreditDecisionPolicyConfig(
                auto_approve_threshold=0.20,
                decline_threshold=0.20,
            )

    def test_defaults_are_explicit_and_frozen(self) -> None:
        config = CreditDecisionPolicyConfig()
        assert config.auto_approve_threshold == 0.05
        assert config.decline_threshold == 0.20
        assert (config.policy_id, config.policy_version) == ("pd-bands", "1")
        with pytest.raises(ValidationError):
            config.policy_version = "2"


class TestPreScoringDecline:
    """A decline taken before scoring carries no model reference, but stays rigid."""

    def _denial(self):
        from tests.unit.domains.finance.test_decision_reasons import policy_denial

        return policy_denial(application_ref="APPLICATION-001", decision_id="DECISION-001")

    def test_policy_evaluate_without_a_score_declines_with_no_model_reference(self) -> None:
        candidate = CreditDecisionPolicy().evaluate(
            decision_id="DECISION-001",
            application_ref="APPLICATION-001",
            policy_denial=self._denial(),
        )
        assert candidate.outcome is CreditDecisionOutcome.DECLINE
        assert candidate.has_model_reference is False
        assert candidate.pd_score is None
        assert candidate.model_id is None
        assert candidate.model_version is None

    def test_a_no_score_decision_requires_a_basis(self) -> None:
        with pytest.raises(ValueError, match="requires a policy or review basis"):
            CreditDecisionPolicy().evaluate(
                decision_id="DECISION-001",
                application_ref="APPLICATION-001",
            )

    def test_a_partial_model_reference_is_rejected(self) -> None:
        from agentguard.domains.finance.credit_risk.agent_templates import CreditDecisionCandidate

        with pytest.raises(ValidationError, match="together"):
            CreditDecisionCandidate(
                decision_id="DECISION-001",
                application_ref="APPLICATION-001",
                outcome=CreditDecisionOutcome.DECLINE,
                pd_score=0.9,  # score present but model identity omitted
                policy_id="p",
                policy_version="1",
                policy_denial=self._denial(),
            )

    def test_a_no_model_approve_is_rejected(self) -> None:
        from agentguard.domains.finance.credit_risk.agent_templates import CreditDecisionCandidate

        with pytest.raises(ValidationError, match="must be a decline"):
            CreditDecisionCandidate(
                decision_id="DECISION-001",
                application_ref="APPLICATION-001",
                outcome=CreditDecisionOutcome.APPROVE,
                policy_id="p",
                policy_version="1",
                policy_denial=self._denial(),
            )

    def test_a_no_model_decline_without_a_basis_is_rejected(self) -> None:
        from agentguard.domains.finance.credit_risk.agent_templates import CreditDecisionCandidate

        with pytest.raises(ValidationError, match="requires a policy or review basis"):
            CreditDecisionCandidate(
                decision_id="DECISION-001",
                application_ref="APPLICATION-001",
                outcome=CreditDecisionOutcome.DECLINE,
                policy_id="p",
                policy_version="1",
            )

    def test_a_no_model_decline_cannot_smuggle_attribution(self) -> None:
        from agentguard.domains.finance.credit_risk.agent_templates import CreditDecisionCandidate
        from agentguard.domains.finance.credit_risk.attribution import (
            AdverseContribution,
            AttributionMethod,
            AttributionResult,
        )

        attribution = AttributionResult(
            model_id="model",
            model_version="1",
            reference_id="ref",
            method=AttributionMethod.SCORECARD_POINTS_LOST,
            feature_names=("factor",),
            contributions=(AdverseContribution(feature_name="factor", value=1.0),),
        )
        with pytest.raises(ValidationError, match="cannot carry model attribution"):
            CreditDecisionCandidate(
                decision_id="DECISION-001",
                application_ref="APPLICATION-001",
                outcome=CreditDecisionOutcome.DECLINE,
                policy_id="p",
                policy_version="1",
                policy_denial=self._denial(),
                attribution=attribution,
            )
