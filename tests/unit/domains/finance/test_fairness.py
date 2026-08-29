"""Compatibility-boundary tests for typed credit fairness analysis."""

from __future__ import annotations

import pytest

from agentguard.domains.finance.credit_risk.fairness import (
    FairnessAnalyzer,
    FairnessVerdict,
)


def test_aggregate_compatibility_is_named_and_never_fabricates_calibration() -> None:
    analyzer = FairnessAnalyzer("group_a", "group_b", min_group_size=10)

    report = analyzer.analyze_aggregates(
        {
            "group_a": {
                "total": 100,
                "approved": 80,
                "denied": 20,
                "true_positives": 15,
                "false_positives": 8,
                "actual_positives": 20,
                "actual_negatives": 80,
            },
            "group_b": {
                "total": 100,
                "approved": 40,
                "denied": 60,
                "true_positives": 20,
                "false_positives": 6,
                "actual_positives": 25,
                "actual_negatives": 75,
            },
        }
    )

    assert report.disparate_impact_ratio == 2.0
    assert report.calibration_max_ece is None
    assert report.calibration_verdict is FairnessVerdict.INSUFFICIENT_DATA
    assert report.overall_verdict is FairnessVerdict.INSUFFICIENT_DATA


def test_aggregate_compatibility_requires_exact_named_groups_and_consistent_counts() -> None:
    analyzer = FairnessAnalyzer("group_a", "group_b", min_group_size=1)

    with pytest.raises(ValueError, match="exactly the two configured groups"):
        analyzer.analyze_aggregates({"group_a": {"total": 1, "approved": 1, "denied": 0}})
    with pytest.raises(ValueError, match="do not sum"):
        analyzer.analyze_aggregates(
            {
                "group_a": {"total": 2, "approved": 1, "denied": 0},
                "group_b": {"total": 2, "approved": 1, "denied": 1},
            }
        )
    with pytest.raises(ValueError, match="matured outcome counts exceed"):
        analyzer.analyze_aggregates(
            {
                "group_a": {
                    "total": 2,
                    "approved": 1,
                    "denied": 1,
                    "actual_positives": 2,
                    "actual_negatives": 1,
                },
                "group_b": {"total": 2, "approved": 1, "denied": 1},
            }
        )


def test_directionless_no_argument_analyzer_is_retired() -> None:
    with pytest.raises(TypeError):
        FairnessAnalyzer()  # type: ignore[call-arg]
