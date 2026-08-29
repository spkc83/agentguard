"""Golden statistical-contract tests for credit fairness analysis."""

from __future__ import annotations

import json
from collections.abc import Sequence

import pytest
from pydantic import ValidationError

from agentguard.domains.finance.credit_risk.fairness import (
    ApprovalRateTest,
    FairnessAnalyzer,
    FairnessObservation,
    FairnessReport,
    FairnessVerdict,
    GroupMetrics,
)


def _decisions(
    group_name: str,
    *,
    approved: int,
    declined: int,
    predicted_pd: float = 0.2,
) -> list[FairnessObservation]:
    return [
        FairnessObservation(
            decision_ref=f"{group_name}-approve-{index}",
            group_name=group_name,
            outcome="approve",
            predicted_pd=predicted_pd,
        )
        for index in range(approved)
    ] + [
        FairnessObservation(
            decision_ref=f"{group_name}-decline-{index}",
            group_name=group_name,
            outcome="decline",
            predicted_pd=predicted_pd,
        )
        for index in range(declined)
    ]


def _analyze(
    observations: Sequence[FairnessObservation],
    *,
    min_group_size: int = 1,
    equalized_odds_threshold: float = 0.1,
    calibration_threshold: float = 0.05,
) -> FairnessReport:
    return FairnessAnalyzer(
        "disadvantaged",
        "reference",
        min_group_size=min_group_size,
        equalized_odds_threshold=equalized_odds_threshold,
        calibration_threshold=calibration_threshold,
    ).analyze(observations)


def _group(report_groups: Sequence[GroupMetrics], name: str) -> GroupMetrics:
    return next(group for group in report_groups if group.group_name == name)


def test_disparate_impact_preserves_named_direction_when_ratio_exceeds_one() -> None:
    observations = _decisions("disadvantaged", approved=80, declined=20)
    observations += _decisions("reference", approved=40, declined=60)

    report = _analyze(observations)

    assert report.disparate_impact_ratio == pytest.approx(2.0)
    assert report.disparate_impact_verdict is FairnessVerdict.PASS


def test_two_proportion_z_test_matches_golden_values() -> None:
    observations = _decisions("disadvantaged", approved=40, declined=60)
    observations += _decisions("reference", approved=80, declined=20)

    report = _analyze(observations)

    assert report.approval_rate_test is ApprovalRateTest.TWO_PROPORTION_Z
    assert report.approval_rate_test_statistic == pytest.approx(-5.773502691896258)
    assert report.approval_rate_p_value == pytest.approx(7.764036537930662e-09)
    assert report.disparate_impact_ratio == pytest.approx(0.5)
    assert report.risk_ratio_ci_lower == pytest.approx(0.38580390966444533)
    assert report.risk_ratio_ci_upper == pytest.approx(0.6479975804740771)


def test_sparse_approval_table_uses_two_sided_fisher_exact_test() -> None:
    observations = _decisions("disadvantaged", approved=1, declined=9)
    observations += _decisions("reference", approved=5, declined=5)

    report = _analyze(observations)

    assert report.approval_rate_test is ApprovalRateTest.FISHER_EXACT
    assert report.approval_rate_p_value == pytest.approx(0.1408668730650155)
    assert report.disparate_impact_ratio == pytest.approx(0.2)
    assert report.risk_ratio_ci_lower == pytest.approx(0.028172698818643496)
    assert report.risk_ratio_ci_upper == pytest.approx(1.4198142768462672)


def test_fisher_exact_preserves_extreme_tail_probability() -> None:
    report = FairnessAnalyzer(
        "disadvantaged",
        "reference",
        min_group_size=1,
    ).analyze_aggregates(
        {
            "disadvantaged": {"total": 1_000_000, "approved": 0, "declined": 1_000_000},
            "reference": {"total": 5, "approved": 5, "declined": 0},
        }
    )

    assert report.approval_rate_test is ApprovalRateTest.FISHER_EXACT
    assert report.approval_rate_p_value == pytest.approx(1.1999819999636916e-28)


def test_zero_approval_cell_uses_haldane_anscombe_only_for_interval() -> None:
    observations = _decisions("disadvantaged", approved=0, declined=10)
    observations += _decisions("reference", approved=5, declined=5)

    report = _analyze(observations)

    assert report.disparate_impact_ratio == 0.0
    assert report.approval_rate_p_value == pytest.approx(0.032507739938080496)
    assert report.risk_ratio_ci_lower == pytest.approx(0.0056862578332829376)
    assert report.risk_ratio_ci_upper == pytest.approx(1.4534097911536128)


def test_zero_reference_approval_rate_is_insufficient_without_nonfinite_values() -> None:
    observations = _decisions("disadvantaged", approved=0, declined=10)
    observations += _decisions("reference", approved=0, declined=10)

    report = _analyze(observations)
    encoded = report.model_dump_json()

    assert report.disparate_impact_ratio is None
    assert report.disparate_impact_verdict is FairnessVerdict.INSUFFICIENT_DATA
    assert json.loads(encoded)["disparate_impact_ratio"] is None
    assert "NaN" not in encoded
    assert "Infinity" not in encoded


def test_disparate_impact_is_insufficient_below_minimum_completed_decisions() -> None:
    observations = _decisions("disadvantaged", approved=8, declined=1)
    observations += _decisions("reference", approved=8, declined=2)

    report = _analyze(observations, min_group_size=10)

    assert report.disparate_impact_ratio is None
    assert report.disparate_impact_verdict is FairnessVerdict.INSUFFICIENT_DATA


def test_equalized_odds_uses_decline_as_positive_prediction() -> None:
    observations = [
        FairnessObservation(
            decision_ref="d-default-decline",
            group_name="disadvantaged",
            outcome="decline",
            predicted_pd=0.7,
            observed_default=True,
        ),
        FairnessObservation(
            decision_ref="d-default-approve",
            group_name="disadvantaged",
            outcome="approve",
            predicted_pd=0.7,
            observed_default=True,
        ),
        *[
            FairnessObservation(
                decision_ref=f"d-nondefault-{index}",
                group_name="disadvantaged",
                outcome="decline" if index == 0 else "approve",
                predicted_pd=0.2,
                observed_default=False,
            )
            for index in range(4)
        ],
        *[
            FairnessObservation(
                decision_ref=f"r-default-{index}",
                group_name="reference",
                outcome="decline",
                predicted_pd=0.7,
                observed_default=True,
            )
            for index in range(2)
        ],
        *[
            FairnessObservation(
                decision_ref=f"r-nondefault-{index}",
                group_name="reference",
                outcome="decline" if index < 2 else "approve",
                predicted_pd=0.2,
                observed_default=False,
            )
            for index in range(4)
        ],
    ]

    report = _analyze(observations, min_group_size=2)
    disadvantaged = _group(report.group_metrics, "disadvantaged")
    reference = _group(report.group_metrics, "reference")

    assert disadvantaged.true_positive_rate == pytest.approx(0.5)
    assert reference.true_positive_rate == pytest.approx(1.0)
    assert disadvantaged.false_positive_rate == pytest.approx(0.25)
    assert reference.false_positive_rate == pytest.approx(0.5)
    assert report.equalized_odds_tpr_diff == pytest.approx(0.5)
    assert report.equalized_odds_fpr_diff == pytest.approx(0.25)
    assert report.equalized_odds_verdict is FairnessVerdict.FAIL


def test_equalized_odds_is_insufficient_when_one_default_denominator_is_sparse() -> None:
    observations = [
        FairnessObservation(
            decision_ref="d-default",
            group_name="disadvantaged",
            outcome="decline",
            predicted_pd=0.8,
            observed_default=True,
        ),
        FairnessObservation(
            decision_ref="d-nondefault",
            group_name="disadvantaged",
            outcome="approve",
            predicted_pd=0.1,
            observed_default=False,
        ),
        *[
            FairnessObservation(
                decision_ref=f"r-default-{index}",
                group_name="reference",
                outcome="decline",
                predicted_pd=0.8,
                observed_default=True,
            )
            for index in range(2)
        ],
        *[
            FairnessObservation(
                decision_ref=f"r-nondefault-{index}",
                group_name="reference",
                outcome="approve",
                predicted_pd=0.1,
                observed_default=False,
            )
            for index in range(2)
        ],
    ]

    report = _analyze(observations, min_group_size=2)

    assert report.equalized_odds_tpr_diff is None
    assert report.equalized_odds_verdict is FairnessVerdict.INSUFFICIENT_DATA


def test_fixed_width_calibration_ece_exposes_aggregate_mean_cancellation() -> None:
    observations = [
        FairnessObservation(
            decision_ref=f"{group}-low",
            group_name=group,
            outcome="approve",
            predicted_pd=0.1,
            observed_default=False,
        )
        for group in ("disadvantaged", "reference")
    ] + [
        FairnessObservation(
            decision_ref=f"{group}-high",
            group_name=group,
            outcome="decline",
            predicted_pd=0.9,
            observed_default=True,
        )
        for group in ("disadvantaged", "reference")
    ]

    report = _analyze(observations)

    assert report.calibration_max_ece == pytest.approx(0.1)
    assert report.calibration_verdict is FairnessVerdict.FAIL


def test_calibration_bins_use_stable_pd_boundaries() -> None:
    probabilities = (0.0, 0.099999, 0.1, 0.999999, 1.0)
    observations = [
        FairnessObservation(
            decision_ref=f"{group}-{index}",
            group_name=group,
            outcome="approve",
            predicted_pd=probability,
            observed_default=False,
        )
        for group in ("disadvantaged", "reference")
        for index, probability in enumerate(probabilities)
    ]

    report = _analyze(observations)
    bins = _group(report.group_metrics, "disadvantaged").calibration_bins

    assert [
        (bin_.lower_bound, bin_.upper_bound, bin_.upper_inclusive, bin_.count) for bin_ in bins
    ] == [
        (0.0, 0.1, False, 2),
        (0.1, 0.2, False, 1),
        (0.9, 1.0, True, 2),
    ]


def test_deterministic_balanced_fixture_passes_all_metrics() -> None:
    observations: list[FairnessObservation] = []
    for group in ("disadvantaged", "reference"):
        for index in range(100):
            observed_default = index < 20
            decline = index < 10 or 20 <= index < 30
            observations.append(
                FairnessObservation(
                    decision_ref=f"{group}-{index}",
                    group_name=group,
                    outcome="decline" if decline else "approve",
                    predicted_pd=0.2,
                    observed_default=observed_default,
                )
            )

    report = _analyze(observations, min_group_size=20)

    assert report.disparate_impact_verdict is FairnessVerdict.PASS
    assert report.equalized_odds_verdict is FairnessVerdict.PASS
    assert report.calibration_verdict is FairnessVerdict.PASS
    assert report.overall_verdict is FairnessVerdict.PASS


def test_fairness_observation_is_immutable() -> None:
    observation = FairnessObservation(
        decision_ref="decision-1",
        group_name="disadvantaged",
        outcome="approve",
        predicted_pd=0.2,
    )

    with pytest.raises(ValidationError):
        observation.predicted_pd = 0.9


def test_fairness_report_uses_immutable_nested_collections() -> None:
    observations = _decisions("disadvantaged", approved=1, declined=1)
    observations += _decisions("reference", approved=1, declined=1)

    report = _analyze(observations)

    assert isinstance(report.group_metrics, tuple)
    assert isinstance(report.group_metrics[0].calibration_bins, tuple)


def test_fairness_observation_rejects_review_outcome() -> None:
    with pytest.raises(ValidationError):
        FairnessObservation(
            decision_ref="decision-1",
            group_name="disadvantaged",
            outcome="review",  # type: ignore[arg-type]
            predicted_pd=0.2,
        )


@pytest.mark.parametrize(
    "predicted_pd",
    [-0.01, 1.01, float("nan"), float("inf"), True, "0.2"],
)
def test_fairness_observation_rejects_invalid_predicted_pd(predicted_pd: object) -> None:
    with pytest.raises(ValidationError):
        FairnessObservation(
            decision_ref="decision-1",
            group_name="disadvantaged",
            outcome="approve",
            predicted_pd=predicted_pd,
        )


@pytest.mark.parametrize("field", ["decision_ref", "group_name"])
@pytest.mark.parametrize("value", ["", " leading", "trailing ", "line\nbreak"])
def test_fairness_observation_rejects_noncanonical_identifiers(field: str, value: str) -> None:
    data: dict[str, object] = {
        "decision_ref": "decision-1",
        "group_name": "disadvantaged",
        "outcome": "approve",
        "predicted_pd": 0.2,
    }
    data[field] = value

    with pytest.raises(ValidationError):
        FairnessObservation.model_validate(data)


def test_fairness_observation_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        FairnessObservation.model_validate(
            {
                "decision_ref": "decision-1",
                "group_name": "disadvantaged",
                "outcome": "approve",
                "predicted_pd": 0.2,
                "inferred_group": True,
            }
        )


def test_analyzer_rejects_identical_named_groups() -> None:
    with pytest.raises(ValueError, match="different"):
        FairnessAnalyzer("same", "same")
