"""SR 11-7 model validation agent patterns.

Federal Reserve / OCC SR 11-7 guidance requires banks to independently
validate AI/ML credit models. This module provides structured validation
workflows covering:

- Conceptual soundness review
- Data quality analysis
- Performance metrics (Gini, KS, AUC, PSI)
- Fairness analysis
- Documentation completeness

The output is a ModelValidationReport aligned to SR 11-7 sections.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

logger = structlog.get_logger()


class PerformanceMetrics(BaseModel):
    """Model performance metrics for validation.

    Args:
        gini: Gini coefficient (0-1, higher is better discrimination).
        ks_statistic: Kolmogorov-Smirnov statistic.
        auc_roc: Area under ROC curve.
        psi: Population Stability Index (model drift measure).
        accuracy: Overall accuracy.
    """

    model_config = ConfigDict(frozen=True)

    gini: float = 0.0
    ks_statistic: float = 0.0
    auc_roc: float = 0.0
    psi: float = 0.0
    accuracy: float = 0.0


class ValidationFinding(BaseModel):
    """A single finding from model validation.

    Args:
        section: SR 11-7 section this finding relates to.
        severity: Finding severity.
        title: Short finding title.
        description: Detailed description.
        recommendation: Recommended remediation.
    """

    model_config = ConfigDict(frozen=True)

    section: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    recommendation: str = ""


class ModelValidationReport(BaseModel):
    """SR 11-7 aligned model validation report.

    Args:
        report_id: Unique report identifier.
        model_name: Name of the model being validated.
        model_version: Version of the model.
        validation_date: When validation was performed.
        validator_id: Who performed the validation.
        performance: Model performance metrics.
        findings: Validation findings organized by SR 11-7 section.
        overall_rating: Overall model rating.
        approved_for_use: Whether the model is approved.
        sections_reviewed: Which SR 11-7 sections were covered.
    """

    model_config = ConfigDict(frozen=True)

    report_id: str
    model_name: str
    model_version: str
    validation_date: datetime = datetime.now(UTC)
    validator_id: str = ""
    performance: PerformanceMetrics = PerformanceMetrics()
    findings: list[ValidationFinding] = []
    overall_rating: str = ""  # satisfactory, needs_improvement, unsatisfactory
    approved_for_use: bool = False
    sections_reviewed: list[str] = []


class ModelValidator:
    """SR 11-7 model validation workflow.

    Evaluates credit risk models against regulatory standards and
    produces structured validation reports.

    Args:
        gini_threshold: Minimum acceptable Gini coefficient.
        psi_threshold: Maximum acceptable PSI (drift).
        auc_threshold: Minimum acceptable AUC-ROC.
    """

    def __init__(
        self,
        gini_threshold: float = 0.3,
        psi_threshold: float = 0.25,
        auc_threshold: float = 0.65,
    ) -> None:
        self._gini_threshold = gini_threshold
        self._psi_threshold = psi_threshold
        self._auc_threshold = auc_threshold

    def validate(
        self,
        report_id: str,
        model_name: str,
        model_version: str,
        performance: PerformanceMetrics,
        data_quality: dict[str, Any] | None = None,
        fairness_results: dict[str, Any] | None = None,
        documentation: dict[str, bool] | None = None,
    ) -> ModelValidationReport:
        """Run full SR 11-7 validation workflow.

        Args:
            report_id: Unique report ID.
            model_name: Name of the model.
            model_version: Model version string.
            performance: Model performance metrics.
            data_quality: Optional data quality assessment dict.
            fairness_results: Optional fairness analysis results.
            documentation: Optional dict of doc requirements -> bool.

        Returns:
            ModelValidationReport with findings and rating.
        """
        findings: list[ValidationFinding] = []
        sections = ["conceptual_soundness", "ongoing_monitoring", "outcomes_analysis"]

        # Section 1: Performance metrics assessment
        if performance.gini < self._gini_threshold:
            findings.append(
                ValidationFinding(
                    section="outcomes_analysis",
                    severity="high",
                    title="Gini coefficient below threshold",
                    description=(
                        f"Gini={performance.gini:.3f}, threshold={self._gini_threshold:.3f}"
                    ),
                    recommendation="Retrain model or review feature engineering.",
                )
            )

        if performance.auc_roc < self._auc_threshold:
            findings.append(
                ValidationFinding(
                    section="outcomes_analysis",
                    severity="high",
                    title="AUC-ROC below threshold",
                    description=(
                        f"AUC={performance.auc_roc:.3f}, threshold={self._auc_threshold:.3f}"
                    ),
                    recommendation="Model discrimination is insufficient.",
                )
            )

        if performance.psi > self._psi_threshold:
            findings.append(
                ValidationFinding(
                    section="ongoing_monitoring",
                    severity="critical",
                    title="Population stability index exceeds threshold",
                    description=(f"PSI={performance.psi:.3f}, threshold={self._psi_threshold:.3f}"),
                    recommendation=(
                        "Significant population drift detected. "
                        "Consider model recalibration or retraining."
                    ),
                )
            )

        # Section 2: Data quality
        if data_quality:
            missing_rate = data_quality.get("missing_rate", 0)
            if missing_rate > 0.05:
                findings.append(
                    ValidationFinding(
                        section="conceptual_soundness",
                        severity="medium",
                        title="High missing data rate",
                        description=f"Missing rate={missing_rate:.1%}",
                        recommendation="Review data pipeline for completeness.",
                    )
                )

        # Section 3: Fairness
        if fairness_results and not fairness_results.get("overall_passed", True):
            findings.append(
                ValidationFinding(
                    section="outcomes_analysis",
                    severity="critical",
                    title="Fairness tests failed",
                    description=(f"DI ratio={fairness_results.get('di_ratio', 'N/A')}"),
                    recommendation=(
                        "Model exhibits disparate impact. "
                        "Review feature selection and consider bias mitigation."
                    ),
                )
            )

        # Section 4: Documentation
        if documentation:
            missing_docs = [k for k, v in documentation.items() if not v]
            if missing_docs:
                findings.append(
                    ValidationFinding(
                        section="conceptual_soundness",
                        severity="medium",
                        title="Incomplete model documentation",
                        description=f"Missing: {', '.join(missing_docs)}",
                        recommendation="Complete all required documentation.",
                    )
                )

        # Determine overall rating
        critical_count = sum(1 for f in findings if f.severity == "critical")
        high_count = sum(1 for f in findings if f.severity == "high")

        if critical_count > 0:
            rating = "unsatisfactory"
            approved = False
        elif high_count > 1:
            rating = "needs_improvement"
            approved = False
        elif high_count == 1:
            rating = "needs_improvement"
            approved = True  # Conditional approval
        else:
            rating = "satisfactory"
            approved = True

        report = ModelValidationReport(
            report_id=report_id,
            model_name=model_name,
            model_version=model_version,
            performance=performance,
            findings=findings,
            overall_rating=rating,
            approved_for_use=approved,
            sections_reviewed=sections,
        )

        logger.info(
            "model_validation_complete",
            report_id=report_id,
            model_name=model_name,
            rating=rating,
            findings_count=len(findings),
        )
        return report
