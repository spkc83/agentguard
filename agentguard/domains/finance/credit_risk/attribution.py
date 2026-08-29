"""Truthful, deterministic attribution of adverse credit-model factors."""

from __future__ import annotations

import math
from enum import StrEnum
from numbers import Real
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

if TYPE_CHECKING:
    from collections.abc import Mapping

_INTERCEPT_ALIASES = frozenset({"intercept", "(intercept)", "bias", "const", "constant"})


class AttributionMethod(StrEnum):
    """Supported methods for deriving adverse contributions."""

    SCORECARD_POINTS_LOST = "scorecard_points_lost"
    COEFFICIENT_DELTA = "coefficient_delta"


class ScoreDirection(StrEnum):
    """Direction in which a scorecard feature becomes more favorable."""

    HIGHER_IS_BETTER = "higher_is_better"
    LOWER_IS_BETTER = "lower_is_better"


class OutputDirection(StrEnum):
    """Direction in which a linear-model output becomes more adverse."""

    HIGHER_IS_MORE_ADVERSE = "higher_is_more_adverse"
    LOWER_IS_MORE_ADVERSE = "lower_is_more_adverse"


def _canonical_identifier(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError(f"{field_name} must be canonical nonempty printable text")
    return value


def _finite_number(value: object, *, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{field_name} must be a finite real number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{field_name} must be a finite real number")
    return result


def _numeric_mapping(values: Mapping[str, Real], *, field_name: str) -> Mapping[str, float]:
    copied: dict[str, float] = {}
    canonical_keys: set[str] = set()
    for raw_key, raw_value in values.items():
        if not isinstance(raw_key, str):
            raise TypeError(f"{field_name} keys must be strings")
        canonical_key = raw_key.strip()
        if canonical_key in canonical_keys:
            raise ValueError(f"{field_name} contains a canonical collision: {canonical_key!r}")
        canonical_keys.add(canonical_key)
        key = _canonical_identifier(raw_key, field_name=f"{field_name} key")
        copied[key] = _finite_number(raw_value, field_name=f"{field_name}[{key!r}]")
    return MappingProxyType(copied)


class AdverseContribution(BaseModel):
    """One strictly adverse, positive model contribution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    feature_name: str
    value: float

    @field_validator("feature_name", mode="before")
    @classmethod
    def _validate_feature_name(cls, value: object) -> str:
        return _canonical_identifier(value, field_name="feature_name")

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: object) -> float:
        result = _finite_number(value, field_name="value")
        if result <= 0:
            raise ValueError("value must be greater than zero")
        return result


class AttributionResult(BaseModel):
    """Immutable attribution result with deterministic contribution ordering."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str
    model_version: str
    reference_id: str
    method: AttributionMethod
    feature_names: tuple[str, ...]
    contributions: tuple[AdverseContribution, ...] = ()

    @field_validator("model_id", "model_version", "reference_id", mode="before")
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        field_name = getattr(info, "field_name", "identifier")
        return _canonical_identifier(value, field_name=field_name)

    @field_validator("feature_names", mode="before")
    @classmethod
    def _validate_feature_names(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("feature_names must be a sequence")
        return tuple(_canonical_identifier(item, field_name="feature_name") for item in value)

    @model_validator(mode="after")
    def _validate_contributions(self) -> AttributionResult:
        if not self.feature_names:
            raise ValueError("feature_names must contain at least one feature")
        if len(self.feature_names) != len(set(self.feature_names)):
            raise ValueError("feature_names contain duplicate features")
        if self.feature_names != tuple(sorted(self.feature_names)):
            raise ValueError("feature_names must use deterministic sorted ordering")
        feature_names = [item.feature_name for item in self.contributions]
        if len(feature_names) != len(set(feature_names)):
            raise ValueError("contributions contain duplicate features")
        if not set(feature_names).issubset(self.feature_names):
            raise ValueError("every contribution feature must belong to feature_names")
        expected = tuple(
            sorted(self.contributions, key=lambda item: (-item.value, item.feature_name))
        )
        if self.contributions != expected:
            raise ValueError("contributions must use deterministic adverse ordering")
        return self


@runtime_checkable
class ModelAttributor(Protocol):
    """Structural contract implemented by credit-model attributors."""

    def attribute(self, values: Mapping[str, Real]) -> AttributionResult: ...


class ScorecardAttributor:
    """Attribute adverse scorecard points relative to a declared reference."""

    def __init__(
        self,
        *,
        model_id: str,
        model_version: str,
        reference_id: str,
        reference_points: Mapping[str, Real],
        score_direction: ScoreDirection,
    ) -> None:
        self._model_id = _canonical_identifier(model_id, field_name="model_id")
        self._model_version = _canonical_identifier(model_version, field_name="model_version")
        self._reference_id = _canonical_identifier(reference_id, field_name="reference_id")
        if not isinstance(score_direction, ScoreDirection):
            raise TypeError("score_direction must be a ScoreDirection")
        self._score_direction = score_direction
        self._reference_points = _numeric_mapping(reference_points, field_name="reference_points")
        if not self._reference_points:
            raise ValueError("reference_points must contain at least one feature")

    def attribute(self, values: Mapping[str, Real]) -> AttributionResult:
        """Return only positive points lost, ordered by impact then feature."""

        application = _numeric_mapping(values, field_name="values")
        _require_exact_keys(application, self._reference_points)
        contributions: list[AdverseContribution] = []
        for feature_name, reference_value in self._reference_points.items():
            application_value = application[feature_name]
            if self._score_direction is ScoreDirection.HIGHER_IS_BETTER:
                adverse_value = reference_value - application_value
            else:
                adverse_value = application_value - reference_value
            adverse_value = _finite_number(
                adverse_value, field_name=f"derived contribution for {feature_name!r}"
            )
            if adverse_value > 0:
                contributions.append(
                    AdverseContribution(feature_name=feature_name, value=adverse_value)
                )
        return _result(
            self._model_id,
            self._model_version,
            self._reference_id,
            AttributionMethod.SCORECARD_POINTS_LOST,
            tuple(sorted(self._reference_points)),
            contributions,
        )


class CoefficientAttributor:
    """Attribute adverse signed coefficient deltas from a reference profile."""

    def __init__(
        self,
        *,
        model_id: str,
        model_version: str,
        reference_id: str,
        coefficients: Mapping[str, Real],
        reference_values: Mapping[str, Real],
        output_direction: OutputDirection,
    ) -> None:
        self._model_id = _canonical_identifier(model_id, field_name="model_id")
        self._model_version = _canonical_identifier(model_version, field_name="model_version")
        self._reference_id = _canonical_identifier(reference_id, field_name="reference_id")
        if not isinstance(output_direction, OutputDirection):
            raise TypeError("output_direction must be an OutputDirection")
        self._output_direction = output_direction
        self._coefficients = _numeric_mapping(coefficients, field_name="coefficients")
        self._reference_values = _numeric_mapping(reference_values, field_name="reference_values")
        if not self._coefficients:
            raise ValueError("coefficients must contain at least one feature")
        if any(feature.casefold() in _INTERCEPT_ALIASES for feature in self._coefficients):
            raise ValueError("intercept pseudo-features cannot be attributed")
        _require_exact_keys(self._coefficients, self._reference_values)

    def attribute(self, values: Mapping[str, Real]) -> AttributionResult:
        """Return only positive signed deltas, ordered by impact then feature."""

        application = _numeric_mapping(values, field_name="values")
        _require_exact_keys(application, self._reference_values)
        contributions: list[AdverseContribution] = []
        for feature_name, coefficient in self._coefficients.items():
            adverse_value = coefficient * (
                application[feature_name] - self._reference_values[feature_name]
            )
            if self._output_direction is OutputDirection.LOWER_IS_MORE_ADVERSE:
                adverse_value = -adverse_value
            adverse_value = _finite_number(
                adverse_value, field_name=f"derived contribution for {feature_name!r}"
            )
            if adverse_value > 0:
                contributions.append(
                    AdverseContribution(feature_name=feature_name, value=adverse_value)
                )
        return _result(
            self._model_id,
            self._model_version,
            self._reference_id,
            AttributionMethod.COEFFICIENT_DELTA,
            tuple(sorted(self._reference_values)),
            contributions,
        )


def _require_exact_keys(left: Mapping[str, object], right: Mapping[str, object]) -> None:
    if left.keys() != right.keys():
        raise ValueError("feature keys must exactly match the configured feature keys")


def _result(
    model_id: str,
    model_version: str,
    reference_id: str,
    method: AttributionMethod,
    feature_names: tuple[str, ...],
    contributions: list[AdverseContribution],
) -> AttributionResult:
    ordered = tuple(sorted(contributions, key=lambda item: (-item.value, item.feature_name)))
    return AttributionResult(
        model_id=model_id,
        model_version=model_version,
        reference_id=reference_id,
        method=method,
        feature_names=feature_names,
        contributions=ordered,
    )
