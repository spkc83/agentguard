"""Typed, observation-level fairness analysis for credit decisions.

The analyzer consumes final decisions joined to protected-group and performance
data by a trusted caller. It never infers group membership or substitutes
aggregate mean PD for calibration observations.
"""

from __future__ import annotations

import math
from enum import StrEnum
from numbers import Real
from statistics import NormalDist
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


class FairnessVerdict(StrEnum):
    """Tri-state result for a fairness check."""

    PASS = "PASS"  # noqa: S105 - verdict label, not a credential
    FAIL = "FAIL"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ApprovalRateTest(StrEnum):
    """Statistical test used to compare approval rates."""

    TWO_PROPORTION_Z = "TWO_PROPORTION_Z"
    FISHER_EXACT = "FISHER_EXACT"


class FairnessObservation(BaseModel):
    """One final, scored credit decision and its optional matured outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    decision_ref: str = Field(min_length=1)
    group_name: str = Field(min_length=1)
    outcome: Literal["approve", "decline"]
    predicted_pd: float = Field(ge=0.0, le=1.0)
    observed_default: bool | None = None

    @field_validator("decision_ref", "group_name")
    @classmethod
    def _canonical_text(cls, value: str) -> str:
        if not value or value != value.strip() or not value.isprintable():
            raise ValueError("value must be canonical printable text")
        return value

    @field_validator("predicted_pd", mode="before")
    @classmethod
    def _finite_pd(cls, value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError("predicted_pd must be a finite value in [0, 1]")
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("predicted_pd must be a finite value in [0, 1]")
        return result


class CalibrationBin(BaseModel):
    """One nonempty fixed-width predicted-PD calibration bin."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    lower_bound: float
    upper_bound: float
    upper_inclusive: bool
    count: int = Field(ge=1)
    mean_predicted_pd: float = Field(ge=0.0, le=1.0)
    observed_default_rate: float = Field(ge=0.0, le=1.0)
    absolute_gap: float = Field(ge=0.0, le=1.0)


class GroupMetrics(BaseModel):
    """Metrics for one named group; unavailable rates remain ``None``."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    group_name: str
    total: int = Field(ge=0)
    approved: int = Field(ge=0)
    declined: int = Field(ge=0)
    approval_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    defaulted_count: int = Field(ge=0)
    non_defaulted_count: int = Field(ge=0)
    true_positive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    false_positive_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    matured_count: int = Field(ge=0)
    calibration_bins: tuple[CalibrationBin, ...] = ()
    expected_calibration_error: float | None = Field(default=None, ge=0.0, le=1.0)

    @property
    def denied(self) -> int:
        """Compatibility alias for the former aggregate model."""

        return self.declined


class FairnessReport(BaseModel):
    """Deeply immutable aggregate fairness report for two named groups."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    disadvantaged_group: str
    reference_group: str
    group_metrics: tuple[GroupMetrics, GroupMetrics]
    disparate_impact_ratio: float | None = Field(default=None, ge=0.0)
    disparate_impact_verdict: FairnessVerdict
    approval_rate_p_value: float | None = Field(default=None, ge=0.0, le=1.0)
    approval_rate_test: ApprovalRateTest | None = None
    approval_rate_test_statistic: float | None = None
    risk_ratio_ci_lower: float | None = Field(default=None, ge=0.0)
    risk_ratio_ci_upper: float | None = Field(default=None, ge=0.0)
    equalized_odds_tpr_diff: float | None = Field(default=None, ge=0.0, le=1.0)
    equalized_odds_fpr_diff: float | None = Field(default=None, ge=0.0, le=1.0)
    equalized_odds_verdict: FairnessVerdict
    calibration_max_ece: float | None = Field(default=None, ge=0.0, le=1.0)
    calibration_verdict: FairnessVerdict
    overall_verdict: FairnessVerdict

    @staticmethod
    def _legacy_passed(verdict: FairnessVerdict) -> bool | None:
        if verdict is FairnessVerdict.INSUFFICIENT_DATA:
            return None
        return verdict is FairnessVerdict.PASS

    @property
    def disparate_impact_passed(self) -> bool | None:
        return self._legacy_passed(self.disparate_impact_verdict)

    @property
    def equalized_odds_passed(self) -> bool | None:
        return self._legacy_passed(self.equalized_odds_verdict)

    @property
    def calibration_passed(self) -> bool | None:
        return self._legacy_passed(self.calibration_verdict)

    @property
    def overall_passed(self) -> bool | None:
        return self._legacy_passed(self.overall_verdict)

    @property
    def calibration_max_diff(self) -> float | None:
        """Compatibility alias; the value is now maximum group ECE."""

        return self.calibration_max_ece

    @property
    def demographic_parity_diff(self) -> float | None:
        disadvantaged, reference = self.group_metrics
        if disadvantaged.approval_rate is None or reference.approval_rate is None:
            return None
        return abs(disadvantaged.approval_rate - reference.approval_rate)


class FairnessAnalyzer:
    """Analyze two explicitly named groups from decision-level observations."""

    def __init__(
        self,
        disadvantaged_group: str,
        reference_group: str,
        *,
        min_group_size: int = 100,
        disparate_impact_threshold: float = 0.8,
        equalized_odds_threshold: float = 0.1,
        calibration_threshold: float = 0.05,
        confidence_level: float = 0.95,
    ) -> None:
        if (
            not disadvantaged_group
            or disadvantaged_group != disadvantaged_group.strip()
            or not disadvantaged_group.isprintable()
            or not reference_group
            or reference_group != reference_group.strip()
            or not reference_group.isprintable()
        ):
            raise ValueError("group names must be canonical printable text")
        if disadvantaged_group == reference_group:
            raise ValueError("disadvantaged and reference groups must be different")
        if min_group_size < 1:
            raise ValueError("min_group_size must be at least one")
        for name, value in (
            ("disparate_impact_threshold", disparate_impact_threshold),
            ("equalized_odds_threshold", equalized_odds_threshold),
            ("calibration_threshold", calibration_threshold),
            ("confidence_level", confidence_level),
        ):
            if not math.isfinite(value) or not 0.0 < value < 1.0:
                raise ValueError(f"{name} must be finite and between zero and one")
        self._disadvantaged_group = disadvantaged_group
        self._reference_group = reference_group
        self._min_group_size = min_group_size
        self._di_threshold = disparate_impact_threshold
        self._eo_threshold = equalized_odds_threshold
        self._calibration_threshold = calibration_threshold
        self._confidence_level = confidence_level

    def analyze(self, observations: Sequence[FairnessObservation]) -> FairnessReport:
        """Analyze per-decision observations, rejecting duplicates and unknown groups."""

        seen: set[str] = set()
        grouped: dict[str, list[FairnessObservation]] = {
            self._disadvantaged_group: [],
            self._reference_group: [],
        }
        for observation in observations:
            if not isinstance(observation, FairnessObservation):
                raise TypeError("observations must contain FairnessObservation instances")
            if observation.decision_ref in seen:
                raise ValueError(f"duplicate decision_ref: {observation.decision_ref}")
            seen.add(observation.decision_ref)
            try:
                grouped[observation.group_name].append(observation)
            except KeyError as exc:
                raise ValueError(f"unexpected group: {observation.group_name}") from exc
        metrics = (
            self._group_metrics(self._disadvantaged_group, grouped[self._disadvantaged_group]),
            self._group_metrics(self._reference_group, grouped[self._reference_group]),
        )
        return self._report(metrics)

    @property
    def group_names(self) -> tuple[str, str]:
        """Return the exact disadvantaged/reference analysis scope."""

        return self._disadvantaged_group, self._reference_group

    def analyze_aggregates(self, groups: Mapping[str, Mapping[str, Any]]) -> FairnessReport:
        """Explicit legacy count path; calibration always remains insufficient."""

        if set(groups) != {self._disadvantaged_group, self._reference_group}:
            raise ValueError("aggregate input must contain exactly the two configured groups")
        metrics = tuple(
            self._aggregate_group(name, groups[name])
            for name in (self._disadvantaged_group, self._reference_group)
        )
        return self._report((metrics[0], metrics[1]), calibration_available=False)

    def _group_metrics(
        self, group_name: str, observations: Sequence[FairnessObservation]
    ) -> GroupMetrics:
        total = len(observations)
        approved = sum(item.outcome == "approve" for item in observations)
        matured = [item for item in observations if item.observed_default is not None]
        defaulted = [item for item in matured if item.observed_default]
        non_defaulted = [item for item in matured if not item.observed_default]
        tpr = (
            sum(item.outcome == "decline" for item in defaulted) / len(defaulted)
            if defaulted
            else None
        )
        fpr = (
            sum(item.outcome == "decline" for item in non_defaulted) / len(non_defaulted)
            if non_defaulted
            else None
        )
        bins, ece = self._calibration(matured)
        return GroupMetrics(
            group_name=group_name,
            total=total,
            approved=approved,
            declined=total - approved,
            approval_rate=approved / total if total else None,
            defaulted_count=len(defaulted),
            non_defaulted_count=len(non_defaulted),
            true_positive_rate=tpr,
            false_positive_rate=fpr,
            matured_count=len(matured),
            calibration_bins=bins,
            expected_calibration_error=ece,
        )

    def _aggregate_group(self, group_name: str, data: Mapping[str, Any]) -> GroupMetrics:
        total = self._count(data, "total")
        approved = self._count(data, "approved")
        declined = self._count(data, "declined", fallback="denied")
        if approved + declined != total:
            raise ValueError(f"aggregate counts do not sum to total for {group_name}")
        actual_positives = self._count(data, "actual_positives", required=False)
        actual_negatives = self._count(data, "actual_negatives", required=False)
        true_positives = self._count(data, "true_positives", required=False)
        false_positives = self._count(data, "false_positives", required=False)
        if true_positives > actual_positives or false_positives > actual_negatives:
            raise ValueError(f"equalized-odds counts exceed denominators for {group_name}")
        if actual_positives + actual_negatives > total:
            raise ValueError(f"matured outcome counts exceed completed decisions for {group_name}")
        return GroupMetrics(
            group_name=group_name,
            total=total,
            approved=approved,
            declined=declined,
            approval_rate=approved / total if total else None,
            defaulted_count=actual_positives,
            non_defaulted_count=actual_negatives,
            true_positive_rate=true_positives / actual_positives if actual_positives else None,
            false_positive_rate=false_positives / actual_negatives if actual_negatives else None,
            matured_count=actual_positives + actual_negatives,
            calibration_bins=(),
            expected_calibration_error=None,
        )

    @staticmethod
    def _count(
        data: Mapping[str, Any],
        key: str,
        *,
        fallback: str | None = None,
        required: bool = True,
    ) -> int:
        raw = data.get(key, data.get(fallback) if fallback else None)
        if raw is None:
            if required:
                raise ValueError(f"missing aggregate count: {key}")
            return 0
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise ValueError(f"aggregate count {key} must be a non-negative integer")
        return raw

    def _report(
        self,
        metrics: tuple[GroupMetrics, GroupMetrics],
        *,
        calibration_available: bool = True,
    ) -> FairnessReport:
        disadvantaged, reference = metrics
        di_ready = (
            disadvantaged.total >= self._min_group_size
            and reference.total >= self._min_group_size
            and reference.approval_rate is not None
            and reference.approval_rate > 0.0
        )
        disadvantaged_rate = disadvantaged.approval_rate
        reference_rate = reference.approval_rate
        ratio = (
            disadvantaged_rate / reference_rate
            if di_ready and disadvantaged_rate is not None and reference_rate is not None
            else None
        )
        di_verdict = (
            FairnessVerdict.PASS
            if ratio is not None and ratio >= self._di_threshold
            else FairnessVerdict.FAIL
            if ratio is not None
            else FairnessVerdict.INSUFFICIENT_DATA
        )
        test, statistic, p_value = (
            self._approval_rate_test(disadvantaged, reference) if di_ready else (None, None, None)
        )
        ci_lower, ci_upper = (
            self._risk_ratio_interval(disadvantaged, reference) if di_ready else (None, None)
        )

        tpr_ready = (
            disadvantaged.defaulted_count >= self._min_group_size
            and reference.defaulted_count >= self._min_group_size
        )
        fpr_ready = (
            disadvantaged.non_defaulted_count >= self._min_group_size
            and reference.non_defaulted_count >= self._min_group_size
        )
        tpr_diff = (
            abs(disadvantaged.true_positive_rate - reference.true_positive_rate)
            if tpr_ready
            and disadvantaged.true_positive_rate is not None
            and reference.true_positive_rate is not None
            else None
        )
        fpr_diff = (
            abs(disadvantaged.false_positive_rate - reference.false_positive_rate)
            if fpr_ready
            and disadvantaged.false_positive_rate is not None
            and reference.false_positive_rate is not None
            else None
        )
        if tpr_diff is None or fpr_diff is None:
            eo_verdict = FairnessVerdict.INSUFFICIENT_DATA
        elif tpr_diff <= self._eo_threshold and fpr_diff <= self._eo_threshold:
            eo_verdict = FairnessVerdict.PASS
        else:
            eo_verdict = FairnessVerdict.FAIL

        calibration_ready = (
            calibration_available
            and disadvantaged.matured_count >= self._min_group_size
            and reference.matured_count >= self._min_group_size
            and disadvantaged.expected_calibration_error is not None
            and reference.expected_calibration_error is not None
        )
        max_ece = (
            max(
                disadvantaged.expected_calibration_error,
                reference.expected_calibration_error,
            )
            if calibration_ready
            and disadvantaged.expected_calibration_error is not None
            and reference.expected_calibration_error is not None
            else None
        )
        calibration_verdict = (
            FairnessVerdict.PASS
            if max_ece is not None and max_ece <= self._calibration_threshold
            else FairnessVerdict.FAIL
            if max_ece is not None
            else FairnessVerdict.INSUFFICIENT_DATA
        )
        overall = self._overall(di_verdict, eo_verdict, calibration_verdict)
        return FairnessReport(
            disadvantaged_group=self._disadvantaged_group,
            reference_group=self._reference_group,
            group_metrics=metrics,
            disparate_impact_ratio=ratio,
            disparate_impact_verdict=di_verdict,
            approval_rate_p_value=p_value,
            approval_rate_test=test,
            approval_rate_test_statistic=statistic,
            risk_ratio_ci_lower=ci_lower,
            risk_ratio_ci_upper=ci_upper,
            equalized_odds_tpr_diff=tpr_diff,
            equalized_odds_fpr_diff=fpr_diff,
            equalized_odds_verdict=eo_verdict,
            calibration_max_ece=max_ece,
            calibration_verdict=calibration_verdict,
            overall_verdict=overall,
        )

    @staticmethod
    def _overall(*verdicts: FairnessVerdict) -> FairnessVerdict:
        if FairnessVerdict.FAIL in verdicts:
            return FairnessVerdict.FAIL
        if FairnessVerdict.INSUFFICIENT_DATA in verdicts:
            return FairnessVerdict.INSUFFICIENT_DATA
        return FairnessVerdict.PASS

    @staticmethod
    def _approval_rate_test(
        disadvantaged: GroupMetrics, reference: GroupMetrics
    ) -> tuple[ApprovalRateTest, float | None, float]:
        a, b = disadvantaged.approved, disadvantaged.declined
        c, d = reference.approved, reference.declined
        total = a + b + c + d
        first_total = a + b
        second_total = c + d
        approved = a + c
        declined = b + d
        expected = (
            first_total * approved / total,
            first_total * declined / total,
            second_total * approved / total,
            second_total * declined / total,
        )
        if all(cell >= 5.0 for cell in expected):
            pooled = approved / total
            standard_error = math.sqrt(
                pooled * (1.0 - pooled) * (1.0 / first_total + 1.0 / second_total)
            )
            z_score = (
                0.0
                if standard_error == 0.0
                else (a / first_total - c / second_total) / standard_error
            )
            p_value = math.erfc(abs(z_score) / math.sqrt(2.0))
            return ApprovalRateTest.TWO_PROPORTION_Z, z_score, min(1.0, max(0.0, p_value))
        return (
            ApprovalRateTest.FISHER_EXACT,
            None,
            FairnessAnalyzer._fisher_two_sided(a, b, c, d),
        )

    @staticmethod
    def _fisher_two_sided(a: int, b: int, c: int, d: int) -> float:
        row_one = a + b
        approved = a + c
        total = a + b + c + d
        low = max(0, row_one - (total - approved))
        high = min(row_one, approved)

        def log_probability(cell: int) -> float:
            return (
                math.lgamma(approved + 1)
                - math.lgamma(cell + 1)
                - math.lgamma(approved - cell + 1)
                + math.lgamma(total - approved + 1)
                - math.lgamma(row_one - cell + 1)
                - math.lgamma(total - approved - row_one + cell + 1)
                - math.lgamma(total + 1)
                + math.lgamma(row_one + 1)
                + math.lgamma(total - row_one + 1)
            )

        observed_log_probability = log_probability(a)
        relative_log_tolerance = math.log1p(1e-12)
        selected = tuple(
            candidate
            for candidate in (log_probability(cell) for cell in range(low, high + 1))
            if candidate <= observed_log_probability + relative_log_tolerance
        )
        maximum = max(selected)
        probability = math.exp(maximum) * sum(
            math.exp(candidate - maximum) for candidate in selected
        )
        return min(1.0, probability)

    def _risk_ratio_interval(
        self, disadvantaged: GroupMetrics, reference: GroupMetrics
    ) -> tuple[float, float]:
        a = float(disadvantaged.approved)
        b = float(disadvantaged.declined)
        c = float(reference.approved)
        d = float(reference.declined)
        if 0.0 in (a, b, c, d):
            a, b, c, d = a + 0.5, b + 0.5, c + 0.5, d + 0.5
        risk_ratio = (a / (a + b)) / (c / (c + d))
        standard_error = math.sqrt(1.0 / a - 1.0 / (a + b) + 1.0 / c - 1.0 / (c + d))
        critical = NormalDist().inv_cdf(0.5 + self._confidence_level / 2.0)
        log_ratio = math.log(risk_ratio)
        return (
            math.exp(log_ratio - critical * standard_error),
            math.exp(log_ratio + critical * standard_error),
        )

    @staticmethod
    def _calibration(
        matured: Sequence[FairnessObservation],
    ) -> tuple[tuple[CalibrationBin, ...], float | None]:
        if not matured:
            return (), None
        buckets: list[list[FairnessObservation]] = [[] for _ in range(10)]
        for observation in matured:
            buckets[min(9, int(observation.predicted_pd * 10.0))].append(observation)
        bins: list[CalibrationBin] = []
        weighted_gap = 0.0
        for index, bucket in enumerate(buckets):
            if not bucket:
                continue
            mean_pd = sum(item.predicted_pd for item in bucket) / len(bucket)
            observed_rate = sum(bool(item.observed_default) for item in bucket) / len(bucket)
            gap = abs(mean_pd - observed_rate)
            weighted_gap += len(bucket) * gap
            bins.append(
                CalibrationBin(
                    lower_bound=index / 10.0,
                    upper_bound=(index + 1) / 10.0,
                    upper_inclusive=index == 9,
                    count=len(bucket),
                    mean_predicted_pd=mean_pd,
                    observed_default_rate=observed_rate,
                    absolute_gap=gap,
                )
            )
        return tuple(bins), weighted_gap / len(matured)
