"""Typed, immutable credit-model validation evidence and report lifecycle."""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.guardrails import canonical_json_bytes

if TYPE_CHECKING:
    from .fairness_monitor import FairnessMonitoringReport

logger = structlog.get_logger()
_SHA256 = r"^[0-9a-f]{64}$"
_SECTIONS = ("conceptual_soundness", "ongoing_monitoring", "outcomes_analysis")


def _canonical(value: str, name: str) -> str:
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError(f"{name} must be canonical printable text")
    return value


def _utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _require_roc_gini(
    metrics: PerformanceMetrics,
    tolerance: float,
    *,
    subject: str,
) -> None:
    if metrics.gini_definition is not GiniDefinition.ROC_DERIVED or not math.isclose(
        metrics.gini,
        2 * metrics.auc_roc - 1,
        rel_tol=0,
        abs_tol=tolerance,
    ):
        raise ValueError(f"{subject} requires consistent ROC-derived Gini")


class GiniDefinition(StrEnum):
    ROC_DERIVED = "roc_derived"
    UNSPECIFIED = "unspecified"


class ValidationSection(StrEnum):
    CONCEPTUAL_SOUNDNESS = "conceptual_soundness"
    ONGOING_MONITORING = "ongoing_monitoring"
    OUTCOMES_ANALYSIS = "outcomes_analysis"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_REMEDIATION = "in_remediation"
    CLOSED = "closed"


class ModelValidationReportStatus(StrEnum):
    VALIDATED = "validated"
    UNVALIDATED = "unvalidated"


class ValidationPolicy(BaseModel):
    """Versioned institution policy; these thresholds are not regulatory rules."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    policy_id: str = "default-credit-model-validation"
    version: str = "1"
    minimum_gini: float = 0.30
    minimum_auc_roc: float = 0.65
    maximum_psi: float = 0.25
    maximum_brier_score: float = 1.0
    gini_auc_absolute_tolerance: float = 1e-9
    minimum_backtest_sample_count: int = 100
    maximum_backtest_age: timedelta = timedelta(days=365)
    maximum_fairness_age: timedelta = timedelta(days=365)
    report_validity: timedelta = timedelta(days=365)

    @field_validator("policy_id", "version")
    @classmethod
    def _identity(cls, value: str, info: Any) -> str:
        return _canonical(value, info.field_name)

    @field_validator(
        "minimum_gini",
        "minimum_auc_roc",
        "maximum_psi",
        "maximum_brier_score",
        "gini_auc_absolute_tolerance",
    )
    @classmethod
    def _finite(cls, value: float) -> float:
        if isinstance(value, bool) or not math.isfinite(value):
            raise ValueError("validation thresholds must be finite")
        return value

    @model_validator(mode="after")
    def _bounds(self) -> ValidationPolicy:
        if not -1 <= self.minimum_gini <= 1 or not 0 <= self.minimum_auc_roc <= 1:
            raise ValueError("discrimination thresholds are outside their domains")
        if self.maximum_psi < 0 or not 0 <= self.maximum_brier_score <= 1:
            raise ValueError("PSI/Brier thresholds are outside their domains")
        if self.gini_auc_absolute_tolerance < 0 or self.minimum_backtest_sample_count < 1:
            raise ValueError("tolerance and sample bounds cannot be negative")
        if (
            self.maximum_backtest_age <= timedelta(0)
            or self.maximum_fairness_age <= timedelta(0)
            or self.report_validity <= timedelta(0)
        ):
            raise ValueError("freshness bounds must be positive")
        return self


class PerformanceMetrics(BaseModel):
    """Finite performance metrics with a definition-aware Gini field."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    gini: float = 0.0
    ks_statistic: float = 0.0
    auc_roc: float = 0.0
    psi: float = 0.0
    accuracy: float = 0.0
    brier_score: float = 0.0
    gini_definition: GiniDefinition = GiniDefinition.UNSPECIFIED

    @field_validator("gini", "ks_statistic", "auc_roc", "psi", "accuracy", "brier_score")
    @classmethod
    def _metric(cls, value: float) -> float:
        if isinstance(value, bool) or not math.isfinite(value):
            raise ValueError("performance metrics must be finite")
        return value

    @model_validator(mode="after")
    def _domains(self) -> PerformanceMetrics:
        if not -1 <= self.gini <= 1 or not 0 <= self.ks_statistic <= 1:
            raise ValueError("Gini/KS is outside its domain")
        if not 0 <= self.auc_roc <= 1 or self.psi < 0:
            raise ValueError("AUC/PSI is outside its domain")
        if not 0 <= self.accuracy <= 1 or not 0 <= self.brier_score <= 1:
            raise ValueError("accuracy/Brier is outside its domain")
        return self


class BacktestEvidence(BaseModel):
    """Exact-model outcomes evidence over one opaque dataset."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    model_id: str
    model_version: str
    dataset_ref: str
    evidence_ref: str
    observation_started_at: datetime
    observation_ended_at: datetime
    evaluated_at: datetime
    sample_count: int = Field(ge=1)
    default_count: int = Field(ge=0)
    predicted_default_rate: float
    observed_default_rate: float
    performance: PerformanceMetrics

    @field_validator("model_id", "model_version", "dataset_ref", "evidence_ref")
    @classmethod
    def _text(cls, value: str, info: Any) -> str:
        return _canonical(value, info.field_name)

    @field_validator("observation_started_at", "observation_ended_at", "evaluated_at")
    @classmethod
    def _time(cls, value: datetime, info: Any) -> datetime:
        return _utc(value, info.field_name)

    @field_validator("predicted_default_rate", "observed_default_rate")
    @classmethod
    def _rate(cls, value: float) -> float:
        if isinstance(value, bool) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("default rates must be finite and in [0, 1]")
        return value

    @model_validator(mode="after")
    def _possible(self) -> BacktestEvidence:
        if self.default_count > self.sample_count:
            raise ValueError("default_count cannot exceed sample_count")
        if self.observation_ended_at < self.observation_started_at:
            raise ValueError("observation window is reversed")
        if self.evaluated_at < self.observation_ended_at:
            raise ValueError("evaluation predates the observation window")
        if not math.isclose(
            self.observed_default_rate, self.default_count / self.sample_count, abs_tol=1e-12
        ):
            raise ValueError("observed default rate disagrees with counts")
        return self


class ChallengerEvidence(BaseModel):
    """Different exact model evaluated over the champion's same sample."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    model_id: str
    model_version: str
    dataset_ref: str
    evidence_ref: str
    observation_started_at: datetime
    observation_ended_at: datetime
    evaluated_at: datetime
    sample_count: int = Field(ge=1)
    default_count: int = Field(ge=0)
    performance: PerformanceMetrics

    @field_validator("model_id", "model_version", "dataset_ref", "evidence_ref")
    @classmethod
    def _text(cls, value: str, info: Any) -> str:
        return _canonical(value, info.field_name)

    @field_validator("observation_started_at", "observation_ended_at", "evaluated_at")
    @classmethod
    def _time(cls, value: datetime, info: Any) -> datetime:
        return _utc(value, info.field_name)

    @model_validator(mode="after")
    def _possible(self) -> ChallengerEvidence:
        if self.default_count > self.sample_count:
            raise ValueError("default_count cannot exceed sample_count")
        if self.observation_ended_at < self.observation_started_at:
            raise ValueError("observation window is reversed")
        if self.evaluated_at < self.observation_ended_at:
            raise ValueError("evaluation predates the observation window")
        return self

    def auc_delta_from(self, champion: BacktestEvidence) -> float:
        _require_comparable(champion, self)
        return self.performance.auc_roc - champion.performance.auc_roc

    def brier_delta_from(self, champion: BacktestEvidence) -> float:
        _require_comparable(champion, self)
        return self.performance.brier_score - champion.performance.brier_score


class FairnessValidationEvidence(BaseModel):
    """Aggregate-only binding to an exact private-monitor report."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    monitor_report_digest: str = Field(pattern=_SHA256)
    model_id: str
    model_version: str
    status: str
    window_started_at: datetime
    window_ended_at: datetime
    provider_id: str
    provider_version: str
    audit_chain_id: str
    audit_head_sequence: int = Field(ge=0)
    audit_head_event_hash: str
    selected_event_count: int = Field(ge=0)
    analyzed_observation_count: int = Field(ge=0)
    integrity_error_count: int = Field(ge=0)

    @field_validator(
        "model_id",
        "model_version",
        "status",
        "provider_id",
        "provider_version",
        "audit_chain_id",
        "audit_head_event_hash",
    )
    @classmethod
    def _text(cls, value: str, info: Any) -> str:
        return _canonical(value, info.field_name)

    @field_validator("window_started_at", "window_ended_at")
    @classmethod
    def _time(cls, value: datetime, info: Any) -> datetime:
        return _utc(value, info.field_name)

    @model_validator(mode="after")
    def _consistent(self) -> FairnessValidationEvidence:
        if self.window_ended_at < self.window_started_at:
            raise ValueError("fairness window is reversed")
        if self.analyzed_observation_count > self.selected_event_count:
            raise ValueError("analyzed count exceeds selected events")
        if self.status not in {"passed", "failed", "insufficient_data"}:
            raise ValueError("unknown fairness status")
        if self.integrity_error_count and self.status != "insufficient_data":
            raise ValueError("integrity errors require insufficient_data")
        return self

    @classmethod
    def from_monitor(cls, report: FairnessMonitoringReport) -> FairnessValidationEvidence:
        from .fairness_monitor import FairnessMonitoringReport

        report = FairnessMonitoringReport.model_validate(report.model_dump(mode="python"))
        payload = report.model_dump(mode="json")
        integrity = sum(
            int(payload[name])
            for name in (
                "malformed_event_count",
                "duplicate_decision_count",
                "missing_observation_count",
                "malformed_observation_count",
                "provider_error_count",
            )
        )
        return cls(
            monitor_report_digest=hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
            model_id=report.model_id,
            model_version=report.model_version,
            status=report.status.value,
            window_started_at=report.window_started_at,
            window_ended_at=report.window_ended_at,
            provider_id=report.provider_id,
            provider_version=report.provider_version,
            audit_chain_id=report.audit_chain_id,
            audit_head_sequence=report.audit_head_sequence,
            audit_head_event_hash=report.audit_head_event_hash,
            selected_event_count=report.selected_event_count,
            analyzed_observation_count=report.analyzed_observation_count,
            integrity_error_count=integrity,
        )


class ValidationFinding(BaseModel):
    """Immutable finding with explicit ownership, due date, and closure evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    finding_id: str = "legacy-finding"
    section: ValidationSection
    severity: FindingSeverity
    title: str
    description: str
    recommendation: str = ""
    owner: str = "unassigned"
    opened_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    due_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + timedelta(days=30))
    status: FindingStatus = FindingStatus.OPEN
    closed_at: datetime | None = None
    closure_evidence_refs: tuple[str, ...] = ()

    @field_validator("finding_id", "title", "description", "owner", "recommendation")
    @classmethod
    def _text(cls, value: str, info: Any) -> str:
        if info.field_name == "recommendation" and not value:
            return value
        return _canonical(value, info.field_name)

    @field_validator("opened_at", "due_at", "closed_at")
    @classmethod
    def _time(cls, value: datetime | None, info: Any) -> datetime | None:
        return None if value is None else _utc(value, info.field_name)

    @field_validator("closure_evidence_refs")
    @classmethod
    def _refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("closure references must be unique")
        return tuple(_canonical(value, "closure_evidence_ref") for value in values)

    @model_validator(mode="after")
    def _lifecycle(self) -> ValidationFinding:
        if self.due_at <= self.opened_at:
            raise ValueError("finding due date must follow opening")
        closed = self.status is FindingStatus.CLOSED
        if closed != (self.closed_at is not None) or closed != bool(self.closure_evidence_refs):
            raise ValueError("only closed findings have closure time and evidence")
        if self.closed_at is not None and self.closed_at < self.opened_at:
            raise ValueError("finding closure predates opening")
        return self


class ModelValidationReport(BaseModel):
    """Immutable, revisioned report for one exact model version."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    report_id: str
    revision: int = Field(default=1, ge=1)
    supersedes_report_ref: str | None = Field(default=None, pattern=_SHA256)
    model_name: str
    model_id: str = "legacy-model"
    model_version: str
    validation_date: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    validator_id: str = "unassigned"
    policy_id: str = "legacy-policy"
    policy_version: str = "1"
    policy: ValidationPolicy | None = None
    feature_schema_digest: str = Field(default="0" * 64, pattern=_SHA256)
    independent_challenge: bool = False
    challenge_evidence_refs: tuple[str, ...] = ()
    backtest: BacktestEvidence | None = None
    challenger: ChallengerEvidence | None = None
    fairness: FairnessValidationEvidence | None = None
    performance: PerformanceMetrics = PerformanceMetrics()
    findings: tuple[ValidationFinding, ...] = ()
    status: ModelValidationReportStatus = ModelValidationReportStatus.UNVALIDATED
    overall_rating: str = ""
    approved_for_use: bool = False
    sections_reviewed: tuple[str, ...] = ()

    @field_validator(
        "report_id",
        "model_name",
        "model_id",
        "model_version",
        "validator_id",
        "policy_id",
        "policy_version",
    )
    @classmethod
    def _text(cls, value: str, info: Any) -> str:
        return _canonical(value, info.field_name)

    @field_validator("validation_date", "expires_at")
    @classmethod
    def _time(cls, value: datetime | None, info: Any) -> datetime | None:
        return None if value is None else _utc(value, info.field_name)

    @field_validator("challenge_evidence_refs")
    @classmethod
    def _refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("challenge references must be unique")
        return tuple(_canonical(value, "challenge_evidence_ref") for value in values)

    @model_validator(mode="after")
    def _consistent(self) -> ModelValidationReport:
        if (self.revision == 1) != (self.supersedes_report_ref is None):
            raise ValueError("report revision must bind exactly its predecessor")
        if self.expires_at is not None and self.expires_at <= self.validation_date:
            raise ValueError("report expiry must follow validation")
        ids = tuple(f.finding_id for f in self.findings)
        if len(ids) != len(set(ids)):
            raise ValueError("finding IDs must be unique")
        if any(finding.opened_at > self.validation_date for finding in self.findings):
            raise ValueError("finding cannot be opened after report validation")
        if any(
            finding.closed_at is not None and finding.closed_at > self.validation_date
            for finding in self.findings
        ):
            raise ValueError("finding cannot be closed after report validation")
        if self.independent_challenge != bool(self.challenge_evidence_refs):
            raise ValueError("independent challenge must bind evidence")
        if self.challenger is not None and not self.independent_challenge:
            raise ValueError("challenger requires independent challenge evidence")
        if self.approved_for_use != (self.status is ModelValidationReportStatus.VALIDATED):
            raise ValueError("approval and validation status disagree")
        if self.policy is not None and (
            self.policy.policy_id != self.policy_id or self.policy.version != self.policy_version
        ):
            raise ValueError("embedded validation policy identity mismatch")
        if self.backtest is not None:
            if (self.backtest.model_id, self.backtest.model_version) != (
                self.model_id,
                self.model_version,
            ):
                raise ValueError("backtest does not bind the report model")
            if self.performance != self.backtest.performance:
                raise ValueError("report and backtest metrics disagree")
        if self.fairness is not None and (self.fairness.model_id, self.fairness.model_version) != (
            self.model_id,
            self.model_version,
        ):
            raise ValueError("fairness evidence does not bind the report model")
        if self.challenger is not None and self.backtest is not None:
            _require_comparable(self.backtest, self.challenger)
            if self.challenger.evaluated_at > self.validation_date:
                raise ValueError("report contains future-dated challenger evidence")
            if self.policy is not None:
                _require_roc_gini(
                    self.challenger.performance,
                    self.policy.gini_auc_absolute_tolerance,
                    subject="challenger",
                )
        if self.policy is not None and self.backtest is not None and self.fairness is not None:
            metrics = self.backtest.performance
            _require_roc_gini(
                metrics,
                self.policy.gini_auc_absolute_tolerance,
                subject="embedded policy",
            )
            if self.backtest.evaluated_at > self.validation_date:
                raise ValueError("report contains future-dated backtest evidence")
            if self.fairness.window_ended_at > self.validation_date:
                raise ValueError("report contains future-dated fairness evidence")
            if (
                self.validation_date - self.backtest.evaluated_at > self.policy.maximum_backtest_age
                or self.validation_date - self.fairness.window_ended_at
                > self.policy.maximum_fairness_age
            ):
                raise ValueError("report contains stale validation evidence")
            blocking = any(
                finding.status in {FindingStatus.OPEN, FindingStatus.IN_REMEDIATION}
                and (
                    finding.severity in {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
                    or finding.due_at <= self.validation_date
                )
                for finding in self.findings
            )
            expected_validated = (
                self.backtest.sample_count >= self.policy.minimum_backtest_sample_count
                and metrics.gini >= self.policy.minimum_gini
                and metrics.auc_roc >= self.policy.minimum_auc_roc
                and metrics.psi <= self.policy.maximum_psi
                and metrics.brier_score <= self.policy.maximum_brier_score
                and self.fairness.status == "passed"
                and not blocking
            )
            if expected_validated != (self.status is ModelValidationReportStatus.VALIDATED):
                raise ValueError("report status disagrees with its embedded validation policy")
            expected_rating = (
                "satisfactory"
                if self.status is ModelValidationReportStatus.VALIDATED
                else "unsatisfactory"
            )
            if self.overall_rating != expected_rating:
                raise ValueError("report rating disagrees with its embedded validation status")
            if self.expires_at != self.derived_expires_at:
                raise ValueError("report expiry disagrees with embedded evidence and policy")
        return self

    @property
    def report_ref(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.model_dump(mode="json"))).hexdigest()

    @property
    def is_strict(self) -> bool:
        return (
            self.expires_at is not None
            and self.policy is not None
            and self.backtest is not None
            and self.fairness is not None
            and self.performance.gini_definition is GiniDefinition.ROC_DERIVED
            and self.sections_reviewed == _SECTIONS
        )

    @property
    def derived_expires_at(self) -> datetime | None:
        """Return the exact non-caller-controlled expiry for a complete report."""

        if self.policy is None or self.backtest is None or self.fairness is None:
            return None
        candidates = [
            self.validation_date + self.policy.report_validity,
            self.backtest.evaluated_at + self.policy.maximum_backtest_age,
            self.fairness.window_ended_at + self.policy.maximum_fairness_age,
        ]
        candidates.extend(
            finding.due_at
            for finding in self.findings
            if finding.status is not FindingStatus.CLOSED
        )
        return max(self.validation_date + timedelta(microseconds=1), min(candidates))


def require_valid_report_revision(
    previous: ModelValidationReport,
    current: ModelValidationReport,
) -> None:
    """Reject finding deletion, regression, or retroactive history across revisions."""

    if current.revision != previous.revision + 1:
        raise ValueError("report revisions must be exactly adjacent")
    if current.validation_date < previous.validation_date:
        raise ValueError("report revision validation time cannot move backwards")
    previous_findings = {finding.finding_id: finding for finding in previous.findings}
    current_findings = {finding.finding_id: finding for finding in current.findings}
    for finding_id, old in previous_findings.items():
        new = current_findings.get(finding_id)
        if old.status is not FindingStatus.CLOSED and new is None:
            raise ValueError("unresolved finding cannot be omitted from a report revision")
        if new is None:
            continue
        stable_old = (
            old.finding_id,
            old.section,
            old.severity,
            old.title,
            old.description,
            old.recommendation,
            old.opened_at,
        )
        stable_new = (
            new.finding_id,
            new.section,
            new.severity,
            new.title,
            new.description,
            new.recommendation,
            new.opened_at,
        )
        if stable_new != stable_old:
            raise ValueError("finding identity and substance cannot change across revisions")
        allowed = {
            FindingStatus.OPEN: {
                FindingStatus.OPEN,
                FindingStatus.IN_REMEDIATION,
                FindingStatus.CLOSED,
            },
            FindingStatus.IN_REMEDIATION: {
                FindingStatus.IN_REMEDIATION,
                FindingStatus.CLOSED,
            },
            FindingStatus.CLOSED: {FindingStatus.CLOSED},
        }
        if new.status not in allowed[old.status]:
            raise ValueError("finding lifecycle cannot regress across report revisions")
        if old.status is FindingStatus.CLOSED and new != old:
            raise ValueError("closed finding evidence cannot change across report revisions")
        if (
            new.status is FindingStatus.CLOSED
            and old.status is not FindingStatus.CLOSED
            and (new.closed_at is None or new.closed_at < previous.validation_date)
        ):
            raise ValueError("finding closure cannot predate the previous report")
        if old.status is not FindingStatus.CLOSED and new.due_at > old.due_at:
            raise ValueError("unresolved finding due date cannot be extended across revisions")
    for finding_id, finding in current_findings.items():
        if finding_id not in previous_findings and finding.opened_at <= previous.validation_date:
            raise ValueError("new finding cannot be opened retroactively in a report revision")


def _require_comparable(champion: BacktestEvidence, challenger: ChallengerEvidence) -> None:
    if (challenger.model_id, challenger.model_version) == (
        champion.model_id,
        champion.model_version,
    ):
        raise ValueError("challenger must be a different exact model")
    if (
        challenger.dataset_ref != champion.dataset_ref
        or challenger.observation_started_at != champion.observation_started_at
        or challenger.observation_ended_at != champion.observation_ended_at
        or challenger.sample_count != champion.sample_count
        or challenger.default_count != champion.default_count
    ):
        raise ValueError("champion and challenger must use the same sample")


class ModelValidator:
    """Build strict evidence reports while preserving the lightweight API."""

    def __init__(
        self,
        gini_threshold: float = 0.3,
        psi_threshold: float = 0.25,
        auc_threshold: float = 0.65,
        *,
        policy: ValidationPolicy | None = None,
    ) -> None:
        self._policy = policy or ValidationPolicy(
            minimum_gini=gini_threshold,
            maximum_psi=psi_threshold,
            minimum_auc_roc=auc_threshold,
        )

    @property
    def policy(self) -> ValidationPolicy:
        return self._policy

    def validate_evidence(
        self,
        *,
        report_id: str,
        revision: int,
        model_name: str,
        model_id: str,
        model_version: str,
        validator_id: str,
        feature_schema_digest: str,
        backtest: BacktestEvidence,
        fairness: FairnessValidationEvidence,
        findings: tuple[ValidationFinding, ...] = (),
        challenger: ChallengerEvidence | None = None,
        challenge_evidence_refs: tuple[str, ...] = (),
        supersedes_report_ref: str | None = None,
        validated_at: datetime,
    ) -> ModelValidationReport:
        """Evaluate typed exact-model evidence and derive authorizing status."""

        validated_at = _utc(validated_at, "validated_at")
        if (backtest.model_id, backtest.model_version) != (model_id, model_version):
            raise ValueError("backtest does not bind exact model")
        if (fairness.model_id, fairness.model_version) != (model_id, model_version):
            raise ValueError("fairness does not bind exact model")
        if backtest.evaluated_at > validated_at or fairness.window_ended_at > validated_at:
            raise ValueError("future-dated evidence cannot be validated")
        if validated_at - backtest.evaluated_at > self._policy.maximum_backtest_age:
            raise ValueError("backtest evidence is stale")
        if validated_at - fairness.window_ended_at > self._policy.maximum_fairness_age:
            raise ValueError("fairness evidence is stale")
        if backtest.sample_count < self._policy.minimum_backtest_sample_count:
            raise ValueError("backtest sample is below policy minimum")
        _require_roc_gini(
            backtest.performance,
            self._policy.gini_auc_absolute_tolerance,
            subject="strict validation",
        )
        if challenger is not None:
            _require_comparable(backtest, challenger)
            if challenger.evaluated_at > validated_at:
                raise ValueError("future-dated challenger evidence cannot be validated")
            _require_roc_gini(
                challenger.performance,
                self._policy.gini_auc_absolute_tolerance,
                subject="challenger",
            )
        blocking = any(
            f.status in {FindingStatus.OPEN, FindingStatus.IN_REMEDIATION}
            and (
                f.severity in {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
                or f.due_at <= validated_at
            )
            for f in findings
        )
        metrics_pass = (
            backtest.performance.gini >= self._policy.minimum_gini
            and backtest.performance.auc_roc >= self._policy.minimum_auc_roc
            and backtest.performance.psi <= self._policy.maximum_psi
            and backtest.performance.brier_score <= self._policy.maximum_brier_score
        )
        approved = metrics_pass and fairness.status == "passed" and not blocking
        expires_at = max(
            validated_at + timedelta(microseconds=1),
            min(
                [
                    validated_at + self._policy.report_validity,
                    backtest.evaluated_at + self._policy.maximum_backtest_age,
                    fairness.window_ended_at + self._policy.maximum_fairness_age,
                    *(
                        finding.due_at
                        for finding in findings
                        if finding.status is not FindingStatus.CLOSED
                    ),
                ]
            ),
        )
        if expires_at == validated_at + timedelta(microseconds=1):
            approved = False
        return ModelValidationReport(
            report_id=report_id,
            revision=revision,
            supersedes_report_ref=supersedes_report_ref,
            model_name=model_name,
            model_id=model_id,
            model_version=model_version,
            validation_date=validated_at,
            expires_at=expires_at,
            validator_id=validator_id,
            policy_id=self._policy.policy_id,
            policy_version=self._policy.version,
            policy=self._policy,
            feature_schema_digest=feature_schema_digest,
            independent_challenge=bool(challenge_evidence_refs),
            challenge_evidence_refs=challenge_evidence_refs,
            backtest=backtest,
            challenger=challenger,
            fairness=fairness,
            performance=backtest.performance,
            findings=findings,
            status=(
                ModelValidationReportStatus.VALIDATED
                if approved
                else ModelValidationReportStatus.UNVALIDATED
            ),
            overall_rating="satisfactory" if approved else "unsatisfactory",
            approved_for_use=approved,
            sections_reviewed=_SECTIONS,
        )

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
        """Compatibility workflow; its unsigned report cannot enter the trusted provider."""

        now = datetime.now(UTC)
        findings: list[ValidationFinding] = []

        def add(
            fid: str,
            section: ValidationSection,
            severity: FindingSeverity,
            title: str,
            description: str,
            recommendation: str,
        ) -> None:
            findings.append(
                ValidationFinding(
                    finding_id=fid,
                    section=section,
                    severity=severity,
                    title=title,
                    description=description,
                    recommendation=recommendation,
                    owner="model-risk-management",
                    opened_at=now,
                    due_at=now + timedelta(days=30),
                )
            )

        if performance.gini < self._policy.minimum_gini:
            add(
                "performance-gini",
                ValidationSection.OUTCOMES_ANALYSIS,
                FindingSeverity.HIGH,
                "Gini coefficient below threshold",
                f"Gini={performance.gini:.3f}, threshold={self._policy.minimum_gini:.3f}",
                "Retrain model or review feature engineering.",
            )
        if performance.auc_roc < self._policy.minimum_auc_roc:
            add(
                "performance-auc",
                ValidationSection.OUTCOMES_ANALYSIS,
                FindingSeverity.HIGH,
                "AUC-ROC below threshold",
                f"AUC={performance.auc_roc:.3f}, threshold={self._policy.minimum_auc_roc:.3f}",
                "Model discrimination is insufficient.",
            )
        if performance.psi > self._policy.maximum_psi:
            add(
                "performance-psi",
                ValidationSection.ONGOING_MONITORING,
                FindingSeverity.CRITICAL,
                "Population stability index exceeds threshold",
                f"PSI={performance.psi:.3f}, threshold={self._policy.maximum_psi:.3f}",
                "Consider model recalibration or retraining.",
            )
        if data_quality and data_quality.get("missing_rate", 0) > 0.05:
            rate = float(data_quality["missing_rate"])
            add(
                "data-quality-missing",
                ValidationSection.CONCEPTUAL_SOUNDNESS,
                FindingSeverity.MEDIUM,
                "High missing data rate",
                f"Missing rate={rate:.1%}",
                "Review data pipeline for completeness.",
            )
        if fairness_results and not fairness_results.get("overall_passed", True):
            add(
                "fairness-failed",
                ValidationSection.OUTCOMES_ANALYSIS,
                FindingSeverity.CRITICAL,
                "Fairness tests failed",
                f"DI ratio={fairness_results.get('di_ratio', 'N/A')}",
                "Review feature selection and consider bias mitigation.",
            )
        if documentation:
            missing = [key for key, value in documentation.items() if not value]
            if missing:
                add(
                    "documentation-incomplete",
                    ValidationSection.CONCEPTUAL_SOUNDNESS,
                    FindingSeverity.MEDIUM,
                    "Incomplete model documentation",
                    f"Missing: {', '.join(missing)}",
                    "Complete all required documentation.",
                )
        critical = sum(f.severity is FindingSeverity.CRITICAL for f in findings)
        high = sum(f.severity is FindingSeverity.HIGH for f in findings)
        approved = not critical and not high
        rating = "unsatisfactory" if critical else "needs_improvement" if high else "satisfactory"
        return ModelValidationReport(
            report_id=report_id,
            model_name=model_name,
            model_version=model_version,
            validation_date=now,
            performance=performance,
            findings=tuple(findings),
            status=(
                ModelValidationReportStatus.VALIDATED
                if approved
                else ModelValidationReportStatus.UNVALIDATED
            ),
            overall_rating=rating,
            approved_for_use=approved,
            sections_reviewed=_SECTIONS,
        )


__all__ = [
    "BacktestEvidence",
    "ChallengerEvidence",
    "FairnessValidationEvidence",
    "FindingSeverity",
    "FindingStatus",
    "GiniDefinition",
    "ModelValidationReport",
    "ModelValidationReportStatus",
    "ModelValidator",
    "PerformanceMetrics",
    "ValidationFinding",
    "ValidationPolicy",
    "ValidationSection",
    "require_valid_report_revision",
]
