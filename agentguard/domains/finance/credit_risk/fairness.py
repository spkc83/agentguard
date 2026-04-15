"""Fairness analysis tools for credit risk models.

Implements the primary fairness metrics used in credit lending:
- Disparate impact test (4/5ths rule): ECOA / Fair Housing Act
- Equalized odds: equal TPR and FPR across groups
- Calibration: predicted PD matches observed default rate per group
- Demographic parity: equal approval rates across groups

All computations use synthetic demographic proxies — never infer
real demographics from applicant data.
"""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

logger = structlog.get_logger()


class GroupMetrics(BaseModel):
    """Metrics for a single demographic group.

    Args:
        group_name: Identifier for this group.
        total: Total number of applicants.
        approved: Number approved.
        denied: Number denied.
        approval_rate: Approval rate (approved / total).
        true_positive_rate: TPR (correctly predicted defaults).
        false_positive_rate: FPR (incorrectly predicted defaults).
        predicted_default_rate: Mean predicted PD for this group.
        observed_default_rate: Actual default rate for this group.
    """

    model_config = ConfigDict(frozen=True)

    group_name: str
    total: int
    approved: int
    denied: int
    approval_rate: float
    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    predicted_default_rate: float = 0.0
    observed_default_rate: float = 0.0


class FairnessReport(BaseModel):
    """Comprehensive fairness analysis report.

    Args:
        group_metrics: Per-group statistics.
        disparate_impact_ratio: Min group approval rate / max group approval rate.
        disparate_impact_passed: True if ratio >= 0.8 (4/5ths rule).
        equalized_odds_tpr_diff: Max TPR difference across groups.
        equalized_odds_fpr_diff: Max FPR difference across groups.
        equalized_odds_passed: True if both diffs < threshold.
        calibration_max_diff: Max |predicted - observed| default rate difference.
        calibration_passed: True if max diff < threshold.
        demographic_parity_diff: Max approval rate difference across groups.
        overall_passed: True if all tests pass.
        details: Additional analysis details.
    """

    model_config = ConfigDict(frozen=True)

    group_metrics: list[GroupMetrics]
    disparate_impact_ratio: float
    disparate_impact_passed: bool
    equalized_odds_tpr_diff: float = 0.0
    equalized_odds_fpr_diff: float = 0.0
    equalized_odds_passed: bool = True
    calibration_max_diff: float = 0.0
    calibration_passed: bool = True
    demographic_parity_diff: float = 0.0
    overall_passed: bool = True
    details: dict[str, Any] = {}


class FairnessAnalyzer:
    """Analyzes credit model fairness across demographic groups.

    Uses synthetic demographic proxies for all analysis. The analyzer
    computes standard regulatory fairness metrics and produces a
    structured report suitable for compliance documentation.

    Args:
        disparate_impact_threshold: 4/5ths rule threshold (default 0.8).
        equalized_odds_threshold: Max allowed TPR/FPR diff (default 0.1).
        calibration_threshold: Max allowed PD calibration diff (default 0.05).
    """

    def __init__(
        self,
        disparate_impact_threshold: float = 0.8,
        equalized_odds_threshold: float = 0.1,
        calibration_threshold: float = 0.05,
    ) -> None:
        self._di_threshold = disparate_impact_threshold
        self._eo_threshold = equalized_odds_threshold
        self._cal_threshold = calibration_threshold

    def analyze(
        self,
        groups: dict[str, dict[str, Any]],
    ) -> FairnessReport:
        """Run fairness analysis across demographic groups.

        Args:
            groups: Dict mapping group name to metrics dict with keys:
                - total: int
                - approved: int
                - denied: int
                - true_positives: int (optional)
                - false_positives: int (optional)
                - actual_positives: int (optional, total actual defaults)
                - actual_negatives: int (optional, total actual non-defaults)
                - predicted_default_rate: float (optional)
                - observed_default_rate: float (optional)

        Returns:
            FairnessReport with all metrics computed.
        """
        group_metrics = []
        approval_rates = []
        tpr_values = []
        fpr_values = []
        cal_diffs = []

        for name, data in groups.items():
            total = data["total"]
            approved = data["approved"]
            denied = data["denied"]
            approval_rate = approved / total if total > 0 else 0.0

            # TPR and FPR for equalized odds
            tp = data.get("true_positives", 0)
            fp = data.get("false_positives", 0)
            actual_pos = data.get("actual_positives", 0)
            actual_neg = data.get("actual_negatives", 0)

            tpr = tp / actual_pos if actual_pos > 0 else 0.0
            fpr = fp / actual_neg if actual_neg > 0 else 0.0

            # Calibration
            pred_rate = data.get("predicted_default_rate", 0.0)
            obs_rate = data.get("observed_default_rate", 0.0)
            cal_diff = abs(pred_rate - obs_rate)

            gm = GroupMetrics(
                group_name=name,
                total=total,
                approved=approved,
                denied=denied,
                approval_rate=round(approval_rate, 4),
                true_positive_rate=round(tpr, 4),
                false_positive_rate=round(fpr, 4),
                predicted_default_rate=round(pred_rate, 4),
                observed_default_rate=round(obs_rate, 4),
            )
            group_metrics.append(gm)
            approval_rates.append(approval_rate)

            if actual_pos > 0:
                tpr_values.append(tpr)
            if actual_neg > 0:
                fpr_values.append(fpr)
            cal_diffs.append(cal_diff)

        # Disparate impact (4/5ths rule)
        max_rate = max(approval_rates) if approval_rates else 1.0
        min_rate = min(approval_rates) if approval_rates else 0.0
        di_ratio = min_rate / max_rate if max_rate > 0 else 0.0
        di_passed = di_ratio >= self._di_threshold

        # Equalized odds
        tpr_diff = max(tpr_values) - min(tpr_values) if len(tpr_values) >= 2 else 0.0
        fpr_diff = max(fpr_values) - min(fpr_values) if len(fpr_values) >= 2 else 0.0
        eo_passed = tpr_diff < self._eo_threshold and fpr_diff < self._eo_threshold

        # Calibration
        max_cal_diff = max(cal_diffs) if cal_diffs else 0.0
        cal_passed = max_cal_diff < self._cal_threshold

        # Demographic parity
        dp_diff = max_rate - min_rate

        # Overall
        overall = di_passed and eo_passed and cal_passed

        report = FairnessReport(
            group_metrics=group_metrics,
            disparate_impact_ratio=round(di_ratio, 4),
            disparate_impact_passed=di_passed,
            equalized_odds_tpr_diff=round(tpr_diff, 4),
            equalized_odds_fpr_diff=round(fpr_diff, 4),
            equalized_odds_passed=eo_passed,
            calibration_max_diff=round(max_cal_diff, 4),
            calibration_passed=cal_passed,
            demographic_parity_diff=round(dp_diff, 4),
            overall_passed=overall,
        )

        logger.info(
            "fairness_analysis_complete",
            groups=len(groups),
            di_ratio=report.disparate_impact_ratio,
            di_passed=report.disparate_impact_passed,
            overall_passed=report.overall_passed,
        )
        return report
