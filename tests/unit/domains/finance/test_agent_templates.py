"""Tests for agentguard.domains.finance.credit_risk.agent_templates."""

from __future__ import annotations

from agentguard.domains.finance.credit_risk.agent_templates import (
    CreditDecisionConfig,
    CreditDecisioningAgent,
)


class TestCreditDecisioningAgent:
    def test_auto_approve(self) -> None:
        agent = CreditDecisioningAgent()
        decision = agent.evaluate("APP-001", pd_score=0.02)
        assert decision.decision == "approved"
        assert decision.requires_review is False

    def test_auto_decline(self) -> None:
        agent = CreditDecisioningAgent()
        decision = agent.evaluate("APP-001", pd_score=0.25)
        assert decision.decision == "declined"
        assert decision.requires_review is False

    def test_review_band(self) -> None:
        agent = CreditDecisioningAgent()
        decision = agent.evaluate("APP-001", pd_score=0.10)
        assert decision.decision == "review"
        assert decision.requires_review is True

    def test_low_fico_decline(self) -> None:
        agent = CreditDecisioningAgent()
        decision = agent.evaluate(
            "APP-001",
            pd_score=0.10,
            application={"fico_score": 500, "dti_ratio": 0.60},
        )
        # Two hard-cutoff failures + PD in review band -> declined
        assert decision.decision == "declined"

    def test_custom_thresholds(self) -> None:
        config = CreditDecisionConfig(
            auto_approve_threshold=0.03,
            decline_threshold=0.15,
        )
        agent = CreditDecisioningAgent(config=config)
        # PD=0.04 is above 0.03 auto-approve, below 0.15 decline -> review
        decision = agent.evaluate("APP-001", pd_score=0.04)
        assert decision.decision == "review"

    def test_feature_importances_populated(self) -> None:
        agent = CreditDecisioningAgent()
        decision = agent.evaluate(
            "APP-001",
            pd_score=0.25,
            application={"fico_score": 650, "dti_ratio": 0.40},
        )
        assert "pd_score" in decision.feature_importances
        assert "fico_score" in decision.feature_importances

    def test_high_dti_flagged(self) -> None:
        agent = CreditDecisioningAgent()
        decision = agent.evaluate(
            "APP-001",
            pd_score=0.10,
            application={"dti_ratio": 0.55},
        )
        assert any("DTI" in r for r in decision.reasons)

    def test_high_loan_amount_flagged(self) -> None:
        agent = CreditDecisioningAgent()
        decision = agent.evaluate(
            "APP-001",
            pd_score=0.10,
            application={"loan_amount": 600000},
        )
        assert any("Loan amount" in r for r in decision.reasons)


class TestCreditDecisionConfig:
    def test_defaults(self) -> None:
        config = CreditDecisionConfig()
        assert config.auto_approve_threshold == 0.05
        assert config.decline_threshold == 0.20
        assert config.min_fico_score == 620
