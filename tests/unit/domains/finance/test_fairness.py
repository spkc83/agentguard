"""Tests for agentguard.domains.finance.credit_risk.fairness."""

from __future__ import annotations

from agentguard.domains.finance.credit_risk.fairness import FairnessAnalyzer


class TestFairnessAnalyzer:
    def test_disparate_impact_passes(self) -> None:
        analyzer = FairnessAnalyzer()
        groups = {
            "group_a": {"total": 100, "approved": 85, "denied": 15},
            "group_b": {"total": 100, "approved": 80, "denied": 20},
        }
        report = analyzer.analyze(groups)
        # 80/85 = 0.941 > 0.8
        assert report.disparate_impact_passed is True
        assert report.disparate_impact_ratio > 0.8

    def test_disparate_impact_fails(self) -> None:
        analyzer = FairnessAnalyzer()
        groups = {
            "group_a": {"total": 100, "approved": 90, "denied": 10},
            "group_b": {"total": 100, "approved": 50, "denied": 50},
        }
        report = analyzer.analyze(groups)
        # 50/90 = 0.556 < 0.8
        assert report.disparate_impact_passed is False
        assert report.disparate_impact_ratio < 0.8

    def test_equalized_odds(self) -> None:
        analyzer = FairnessAnalyzer(equalized_odds_threshold=0.15)
        groups = {
            "group_a": {
                "total": 100,
                "approved": 80,
                "denied": 20,
                "true_positives": 15,
                "false_positives": 5,
                "actual_positives": 20,
                "actual_negatives": 80,
            },
            "group_b": {
                "total": 100,
                "approved": 75,
                "denied": 25,
                "true_positives": 18,
                "false_positives": 7,
                "actual_positives": 25,
                "actual_negatives": 75,
            },
        }
        report = analyzer.analyze(groups)
        assert report.equalized_odds_tpr_diff >= 0
        assert report.equalized_odds_fpr_diff >= 0

    def test_calibration(self) -> None:
        analyzer = FairnessAnalyzer(calibration_threshold=0.05)
        groups = {
            "group_a": {
                "total": 100,
                "approved": 80,
                "denied": 20,
                "predicted_default_rate": 0.08,
                "observed_default_rate": 0.07,
            },
            "group_b": {
                "total": 100,
                "approved": 75,
                "denied": 25,
                "predicted_default_rate": 0.10,
                "observed_default_rate": 0.09,
            },
        }
        report = analyzer.analyze(groups)
        assert report.calibration_passed is True
        assert report.calibration_max_diff < 0.05

    def test_overall_passed(self) -> None:
        analyzer = FairnessAnalyzer()
        groups = {
            "group_a": {"total": 100, "approved": 85, "denied": 15},
            "group_b": {"total": 100, "approved": 82, "denied": 18},
        }
        report = analyzer.analyze(groups)
        assert report.overall_passed is True

    def test_overall_failed(self) -> None:
        analyzer = FairnessAnalyzer()
        groups = {
            "group_a": {"total": 100, "approved": 95, "denied": 5},
            "group_b": {"total": 100, "approved": 40, "denied": 60},
        }
        report = analyzer.analyze(groups)
        assert report.overall_passed is False

    def test_multiple_groups(self) -> None:
        analyzer = FairnessAnalyzer()
        groups = {
            "a": {"total": 100, "approved": 80, "denied": 20},
            "b": {"total": 100, "approved": 78, "denied": 22},
            "c": {"total": 100, "approved": 75, "denied": 25},
            "d": {"total": 100, "approved": 72, "denied": 28},
        }
        report = analyzer.analyze(groups)
        assert len(report.group_metrics) == 4
