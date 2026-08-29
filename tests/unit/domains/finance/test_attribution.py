"""Tests for truthful adverse-factor attribution."""

from __future__ import annotations

from typing import cast

import pytest
from pydantic import ValidationError

from agentguard.domains.finance.credit_risk.attribution import (
    AdverseContribution,
    AttributionMethod,
    AttributionResult,
    CoefficientAttributor,
    ModelAttributor,
    OutputDirection,
    ScorecardAttributor,
    ScoreDirection,
)


@pytest.mark.parametrize(
    ("direction", "application", "expected"),
    [
        (ScoreDirection.HIGHER_IS_BETTER, {"fico_score": 650.0}, 50.0),
        (ScoreDirection.LOWER_IS_BETTER, {"dti_ratio": 0.45}, 0.1),
    ],
)
def test_scorecard_attributor_respects_score_direction(
    direction: ScoreDirection,
    application: dict[str, float],
    expected: float,
) -> None:
    feature = next(iter(application))
    reference = {feature: 700.0 if direction is ScoreDirection.HIGHER_IS_BETTER else 0.35}
    attributor = ScorecardAttributor(
        model_id="credit-scorecard",
        model_version="1.0",
        reference_id="approval-boundary",
        reference_points=reference,
        score_direction=direction,
    )

    result = attributor.attribute(application)

    assert result.method is AttributionMethod.SCORECARD_POINTS_LOST
    assert result.feature_names == (feature,)
    assert result.contributions[0].feature_name == feature
    assert result.contributions[0].value == pytest.approx(expected)


def test_scorecard_omits_favorable_and_zero_factors_and_sorts_ties() -> None:
    attributor = ScorecardAttributor(
        model_id="scorecard",
        model_version="1",
        reference_id="reference",
        reference_points={"zeta": 10.0, "alpha": 10.0, "favorable": 10.0, "zero": 10.0},
        score_direction=ScoreDirection.HIGHER_IS_BETTER,
    )

    result = attributor.attribute({"zeta": 8.0, "alpha": 8.0, "favorable": 12.0, "zero": 10.0})

    assert result.feature_names == ("alpha", "favorable", "zero", "zeta")
    assert [(item.feature_name, item.value) for item in result.contributions] == [
        ("alpha", 2.0),
        ("zeta", 2.0),
    ]


def test_strong_fico_and_low_dti_have_no_adverse_scorecard_factors() -> None:
    fico_attributor = ScorecardAttributor(
        model_id="underwriting",
        model_version="1",
        reference_id="minimum-approval",
        reference_points={"fico_score": 700.0},
        score_direction=ScoreDirection.HIGHER_IS_BETTER,
    )
    dti_attributor = ScorecardAttributor(
        model_id="underwriting",
        model_version="1",
        reference_id="maximum-approval",
        reference_points={"dti_ratio": 0.35},
        score_direction=ScoreDirection.LOWER_IS_BETTER,
    )

    fico_result = fico_attributor.attribute({"fico_score": 810.0})
    dti_result = dti_attributor.attribute({"dti_ratio": 0.10})

    assert fico_result.contributions == ()
    assert dti_result.contributions == ()


@pytest.mark.parametrize(
    ("coefficient", "application", "reference", "direction", "expected"),
    [
        (2.0, 3.0, 1.0, OutputDirection.HIGHER_IS_MORE_ADVERSE, 4.0),
        (-2.0, 0.0, 1.0, OutputDirection.HIGHER_IS_MORE_ADVERSE, 2.0),
        (2.0, 0.0, 1.0, OutputDirection.LOWER_IS_MORE_ADVERSE, 2.0),
        (-2.0, 3.0, 1.0, OutputDirection.LOWER_IS_MORE_ADVERSE, 4.0),
    ],
)
def test_coefficient_attributor_covers_all_sign_and_direction_quadrants(
    coefficient: float,
    application: float,
    reference: float,
    direction: OutputDirection,
    expected: float,
) -> None:
    attributor = CoefficientAttributor(
        model_id="linear-model",
        model_version="2",
        reference_id="reference-profile",
        coefficients={"factor": coefficient},
        reference_values={"factor": reference},
        output_direction=direction,
    )

    result = attributor.attribute({"factor": application})

    assert result.method is AttributionMethod.COEFFICIENT_DELTA
    assert result.feature_names == ("factor",)
    assert result.contributions == (AdverseContribution(feature_name="factor", value=expected),)


def test_coefficient_omits_nonadverse_and_zero_factors_and_sorts() -> None:
    attributor = CoefficientAttributor(
        model_id="linear",
        model_version="1",
        reference_id="reference",
        coefficients={"zeta": 1.0, "alpha": 1.0, "favorable": 1.0, "zero": 1.0},
        reference_values={"zeta": 0.0, "alpha": 0.0, "favorable": 2.0, "zero": 1.0},
        output_direction=OutputDirection.HIGHER_IS_MORE_ADVERSE,
    )

    result = attributor.attribute({"zeta": 1.0, "alpha": 1.0, "favorable": 1.0, "zero": 1.0})

    assert [item.feature_name for item in result.contributions] == ["alpha", "zeta"]


@pytest.mark.parametrize("factory", [ScorecardAttributor, CoefficientAttributor])
def test_configuration_is_defensively_copied(factory: object) -> None:
    values = {"factor": 10.0}
    if factory is ScorecardAttributor:
        attributor: ModelAttributor = ScorecardAttributor(
            model_id="model",
            model_version="1",
            reference_id="ref",
            reference_points=values,
            score_direction=ScoreDirection.HIGHER_IS_BETTER,
        )
    else:
        attributor = CoefficientAttributor(
            model_id="model",
            model_version="1",
            reference_id="ref",
            coefficients={"factor": -1.0},
            reference_values=values,
            output_direction=OutputDirection.HIGHER_IS_MORE_ADVERSE,
        )
    values["factor"] = 100.0

    result = attributor.attribute({"factor": 8.0})

    assert result.contributions == (AdverseContribution(feature_name="factor", value=2.0),)
    assert isinstance(attributor, ModelAttributor)


@pytest.mark.parametrize(
    "values",
    [
        {"factor": True},
        {"factor": cast("float", "not-a-number")},
        {"factor": float("nan")},
        {"factor": float("inf")},
    ],
)
def test_invalid_numeric_configuration_is_rejected(values: dict[str, float]) -> None:
    with pytest.raises((TypeError, ValueError)):
        ScorecardAttributor(
            model_id="model",
            model_version="1",
            reference_id="ref",
            reference_points=values,
            score_direction=ScoreDirection.HIGHER_IS_BETTER,
        )


def test_invalid_numeric_runtime_input_is_rejected() -> None:
    attributor = ScorecardAttributor(
        model_id="model",
        model_version="1",
        reference_id="ref",
        reference_points={"factor": 1.0},
        score_direction=ScoreDirection.HIGHER_IS_BETTER,
    )

    with pytest.raises(TypeError):
        attributor.attribute({"factor": True})
    with pytest.raises(ValueError):
        attributor.attribute({"factor": float("-inf")})


def test_nonfinite_derived_contribution_is_rejected() -> None:
    attributor = CoefficientAttributor(
        model_id="model",
        model_version="1",
        reference_id="ref",
        coefficients={"factor": 1e308},
        reference_values={"factor": -1e308},
        output_direction=OutputDirection.HIGHER_IS_MORE_ADVERSE,
    )

    with pytest.raises(ValueError, match="derived contribution"):
        attributor.attribute({"factor": 1e308})


def test_exact_feature_keys_are_required() -> None:
    scorecard = ScorecardAttributor(
        model_id="model",
        model_version="1",
        reference_id="ref",
        reference_points={"one": 1.0},
        score_direction=ScoreDirection.HIGHER_IS_BETTER,
    )
    coefficients = CoefficientAttributor(
        model_id="model",
        model_version="1",
        reference_id="ref",
        coefficients={"one": 1.0},
        reference_values={"one": 0.0},
        output_direction=OutputDirection.HIGHER_IS_MORE_ADVERSE,
    )

    with pytest.raises(ValueError, match="exactly match"):
        scorecard.attribute({"two": 1.0})
    with pytest.raises(ValueError, match="exactly match"):
        coefficients.attribute({"one": 1.0, "two": 2.0})


def test_coefficient_configuration_requires_exact_feature_keys() -> None:
    with pytest.raises(ValueError, match="exactly match"):
        CoefficientAttributor(
            model_id="model",
            model_version="1",
            reference_id="ref",
            coefficients={"one": 1.0},
            reference_values={"two": 0.0},
            output_direction=OutputDirection.HIGHER_IS_MORE_ADVERSE,
        )


@pytest.mark.parametrize("pseudo_feature", ["intercept", "Intercept", "bias", "const"])
def test_coefficient_configuration_rejects_intercept_pseudo_features(
    pseudo_feature: str,
) -> None:
    with pytest.raises(ValueError, match="intercept"):
        CoefficientAttributor(
            model_id="model",
            model_version="1",
            reference_id="ref",
            coefficients={pseudo_feature: 1.0},
            reference_values={pseudo_feature: 1.0},
            output_direction=OutputDirection.HIGHER_IS_MORE_ADVERSE,
        )


@pytest.mark.parametrize("identifier", ["", " ", " padded", "padded ", "bad\nvalue"])
def test_model_metadata_must_be_canonical(identifier: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        ScorecardAttributor(
            model_id=identifier,
            model_version="1",
            reference_id="ref",
            reference_points={},
            score_direction=ScoreDirection.HIGHER_IS_BETTER,
        )


def test_noncanonical_and_canonical_collision_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="canonical collision"):
        ScorecardAttributor(
            model_id="model",
            model_version="1",
            reference_id="ref",
            reference_points={"factor": 1.0, " factor ": 2.0},
            score_direction=ScoreDirection.HIGHER_IS_BETTER,
        )
    with pytest.raises(ValueError, match="canonical"):
        ScorecardAttributor(
            model_id="model",
            model_version="1",
            reference_id="ref",
            reference_points={" factor ": 2.0},
            score_direction=ScoreDirection.HIGHER_IS_BETTER,
        )


def test_attribution_models_are_strict_frozen_and_immutable() -> None:
    contribution = AdverseContribution(feature_name="factor", value=1.0)
    result = AttributionResult(
        model_id="model",
        model_version="1",
        reference_id="ref",
        method=AttributionMethod.SCORECARD_POINTS_LOST,
        feature_names=("factor",),
        contributions=(contribution,),
    )

    with pytest.raises(ValidationError):
        contribution.value = 2.0  # type: ignore[misc]
    with pytest.raises(ValidationError):
        result.model_id = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        AdverseContribution(feature_name="factor", value=1.0, unexpected=True)
    with pytest.raises(ValidationError):
        AttributionResult(
            model_id="model",
            model_version="1",
            reference_id="ref",
            method=AttributionMethod.SCORECARD_POINTS_LOST,
            contributions=(contribution,),
            unexpected=True,
        )


def test_attribution_result_rejects_duplicates_and_nondeterministic_order() -> None:
    one = AdverseContribution(feature_name="one", value=1.0)
    duplicate = AdverseContribution(feature_name="one", value=0.5)
    two = AdverseContribution(feature_name="two", value=2.0)
    base = {
        "model_id": "model",
        "model_version": "1",
        "reference_id": "ref",
        "method": AttributionMethod.SCORECARD_POINTS_LOST,
        "feature_names": ("one", "two"),
    }

    with pytest.raises(ValidationError, match="duplicate"):
        AttributionResult(**base, contributions=(one, duplicate))
    with pytest.raises(ValidationError, match="deterministic"):
        AttributionResult(**base, contributions=(one, two))


def test_attribution_result_requires_complete_deterministic_feature_schema() -> None:
    contribution = AdverseContribution(feature_name="unbound", value=1.0)
    base = {
        "model_id": "model",
        "model_version": "1",
        "reference_id": "ref",
        "method": AttributionMethod.COEFFICIENT_DELTA,
    }

    with pytest.raises(ValidationError, match="at least one"):
        AttributionResult(**base, feature_names=(), contributions=())
    with pytest.raises(ValidationError, match="duplicate"):
        AttributionResult(**base, feature_names=("one", "one"), contributions=())
    with pytest.raises(ValidationError, match="sorted"):
        AttributionResult(**base, feature_names=("two", "one"), contributions=())
    with pytest.raises(ValidationError, match="belong"):
        AttributionResult(**base, feature_names=("bound",), contributions=(contribution,))


def test_zero_feature_model_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        ScorecardAttributor(
            model_id="model",
            model_version="1",
            reference_id="ref",
            reference_points={},
            score_direction=ScoreDirection.HIGHER_IS_BETTER,
        ).attribute({})


@pytest.mark.parametrize("value", [0.0, -1.0, float("nan"), float("inf")])
def test_adverse_contribution_requires_positive_finite_value(value: float) -> None:
    with pytest.raises(ValidationError):
        AdverseContribution(feature_name="factor", value=value)
