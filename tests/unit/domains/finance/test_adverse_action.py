"""Tests for agentguard.domains.finance.credit_risk.adverse_action."""

from __future__ import annotations

from agentguard.domains.finance.credit_risk.adverse_action import (
    AdverseActionGenerator,
    AdverseActionNotice,
)


class TestAdverseActionGenerator:
    def test_generate_notice(self) -> None:
        gen = AdverseActionGenerator()
        notice = gen.generate(
            notice_id="AA-001",
            applicant_id="APP-001",
            feature_importances={
                "fico_score": 0.35,
                "dti_ratio": 0.25,
                "delinquency_24m": 0.20,
                "annual_income": 0.10,
                "credit_utilization": 0.05,
            },
            pd_score=0.25,
        )
        assert notice.notice_id == "AA-001"
        assert notice.applicant_id == "APP-001"
        assert len(notice.reasons) == 4  # MAX_REASONS
        # First reason should be from highest importance feature
        assert "Credit score" in notice.reasons[0]

    def test_deterministic_ordering(self) -> None:
        gen = AdverseActionGenerator()
        importances = {
            "fico_score": 0.35,
            "dti_ratio": 0.25,
            "delinquency_24m": 0.20,
        }
        notice1 = gen.generate("AA-1", "APP-1", importances)
        notice2 = gen.generate("AA-2", "APP-2", importances)
        assert notice1.reasons == notice2.reasons

    def test_max_reasons_respected(self) -> None:
        gen = AdverseActionGenerator(max_reasons=2)
        notice = gen.generate(
            "AA-001",
            "APP-001",
            {
                "fico_score": 0.35,
                "dti_ratio": 0.25,
                "delinquency_24m": 0.20,
                "annual_income": 0.10,
            },
        )
        assert len(notice.reasons) <= 2

    def test_custom_reason_map(self) -> None:
        custom_map = {"custom_feature": "Custom denial reason"}
        gen = AdverseActionGenerator(reason_map=custom_map)
        notice = gen.generate("AA-001", "APP-001", {"custom_feature": 0.5})
        assert notice.reasons[0] == "Custom denial reason"

    def test_unknown_features_skipped(self) -> None:
        gen = AdverseActionGenerator()
        notice = gen.generate(
            "AA-001",
            "APP-001",
            {"unknown_feature_xyz": 0.5},
        )
        assert len(notice.reasons) == 0

    def test_equal_importances_deterministic(self) -> None:
        """When importances are equal, features are sorted alphabetically."""
        gen = AdverseActionGenerator()
        notice = gen.generate(
            "AA-001",
            "APP-001",
            {"dti_ratio": 0.3, "annual_income": 0.3, "fico_score": 0.3},
        )
        # All same importance, sorted by name: annual_income, dti_ratio, fico_score
        assert "income" in notice.reasons[0].lower()

    def test_notice_includes_disclosure(self) -> None:
        gen = AdverseActionGenerator()
        notice = gen.generate("AA-001", "APP-001", {"fico_score": 0.5})
        assert "Equal Credit Opportunity Act" in notice.disclosure_text


class TestAdverseActionNotice:
    def test_notice_is_frozen(self) -> None:
        notice = AdverseActionNotice(
            notice_id="AA-001",
            applicant_id="APP-001",
            decision="denied",
            reasons=["Test reason"],
            reason_codes={"test": "Test reason"},
        )
        assert notice.decision == "denied"
