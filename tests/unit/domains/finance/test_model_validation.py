"""Tests for agentguard.domains.finance.credit_risk.model_validation."""

from __future__ import annotations

from agentguard.domains.finance.credit_risk.model_validation import (
    ModelValidator,
    PerformanceMetrics,
)


class TestModelValidator:
    def test_satisfactory_model(self) -> None:
        validator = ModelValidator()
        performance = PerformanceMetrics(
            gini=0.50, ks_statistic=0.35, auc_roc=0.80, psi=0.05, accuracy=0.85
        )
        report = validator.validate(
            report_id="VAL-001",
            model_name="Credit PD v1",
            model_version="1.0",
            performance=performance,
        )
        assert report.overall_rating == "satisfactory"
        assert report.approved_for_use is True

    def test_low_gini_flagged(self) -> None:
        validator = ModelValidator(gini_threshold=0.3)
        performance = PerformanceMetrics(gini=0.20, auc_roc=0.70, psi=0.05)
        report = validator.validate("VAL-001", "Model", "1.0", performance)
        assert any("Gini" in f.title for f in report.findings)
        assert report.overall_rating == "needs_improvement"

    def test_high_psi_flagged(self) -> None:
        validator = ModelValidator(psi_threshold=0.25)
        performance = PerformanceMetrics(gini=0.50, auc_roc=0.80, psi=0.30)
        report = validator.validate("VAL-001", "Model", "1.0", performance)
        assert any("stability" in f.title.lower() for f in report.findings)
        assert report.overall_rating == "unsatisfactory"

    def test_low_auc_flagged(self) -> None:
        validator = ModelValidator(auc_threshold=0.65)
        performance = PerformanceMetrics(gini=0.50, auc_roc=0.55, psi=0.05)
        report = validator.validate("VAL-001", "Model", "1.0", performance)
        assert any("AUC" in f.title for f in report.findings)

    def test_fairness_failure_flagged(self) -> None:
        validator = ModelValidator()
        performance = PerformanceMetrics(gini=0.50, auc_roc=0.80, psi=0.05)
        report = validator.validate(
            "VAL-001",
            "Model",
            "1.0",
            performance,
            fairness_results={"overall_passed": False, "di_ratio": 0.65},
        )
        assert any("Fairness" in f.title for f in report.findings)
        assert report.overall_rating == "unsatisfactory"

    def test_missing_docs_flagged(self) -> None:
        validator = ModelValidator()
        performance = PerformanceMetrics(gini=0.50, auc_roc=0.80, psi=0.05)
        report = validator.validate(
            "VAL-001",
            "Model",
            "1.0",
            performance,
            documentation={"model_card": True, "methodology": False},
        )
        assert any("documentation" in f.title.lower() for f in report.findings)

    def test_data_quality_flagged(self) -> None:
        validator = ModelValidator()
        performance = PerformanceMetrics(gini=0.50, auc_roc=0.80, psi=0.05)
        report = validator.validate(
            "VAL-001",
            "Model",
            "1.0",
            performance,
            data_quality={"missing_rate": 0.10},
        )
        assert any("missing" in f.title.lower() for f in report.findings)

    def test_multiple_high_findings(self) -> None:
        """Two high-severity findings -> needs_improvement, not approved."""
        validator = ModelValidator()
        performance = PerformanceMetrics(gini=0.20, auc_roc=0.55, psi=0.05)
        report = validator.validate("VAL-001", "Model", "1.0", performance)
        assert report.overall_rating == "needs_improvement"
        assert report.approved_for_use is False


class TestPerformanceMetrics:
    def test_defaults(self) -> None:
        metrics = PerformanceMetrics()
        assert metrics.gini == 0.0
        assert metrics.psi == 0.0
