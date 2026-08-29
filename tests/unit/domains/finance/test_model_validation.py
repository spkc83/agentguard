"""Acceptance tests for typed, revisioned model-validation evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agentguard.domains.finance.credit_risk.fairness import (
    FairnessAnalyzer,
    FairnessObservation,
)
from agentguard.domains.finance.credit_risk.fairness_monitor import FairnessMonitoringReport
from agentguard.domains.finance.credit_risk.model_governance import ModelFairnessStatus
from agentguard.domains.finance.credit_risk.model_validation import (
    BacktestEvidence,
    ChallengerEvidence,
    FairnessValidationEvidence,
    FindingSeverity,
    FindingStatus,
    GiniDefinition,
    ModelValidationReport,
    ModelValidationReportStatus,
    ModelValidator,
    PerformanceMetrics,
    ValidationFinding,
    ValidationPolicy,
    ValidationSection,
)

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
WINDOW_START = NOW - timedelta(days=90)
WINDOW_END = NOW - timedelta(days=30)
EVALUATED_AT = NOW - timedelta(days=1)
MODEL_ID = "credit-pd"
MODEL_VERSION = "2026.08"
SCHEMA_DIGEST = "a" * 64


def _metrics(**updates: object) -> PerformanceMetrics:
    values: dict[str, object] = {
        "gini": 0.50,
        "ks_statistic": 0.35,
        "auc_roc": 0.75,
        "psi": 0.05,
        "accuracy": 0.85,
        "brier_score": 0.12,
        "gini_definition": GiniDefinition.ROC_DERIVED,
    }
    values.update(updates)
    return PerformanceMetrics.model_validate(values)


def _backtest(**updates: object) -> BacktestEvidence:
    values: dict[str, object] = {
        "model_id": MODEL_ID,
        "model_version": MODEL_VERSION,
        "dataset_ref": "dataset-sha256:champion-sample",
        "evidence_ref": "backtest-sha256:champion",
        "observation_started_at": WINDOW_START,
        "observation_ended_at": WINDOW_END,
        "evaluated_at": EVALUATED_AT,
        "sample_count": 1_000,
        "default_count": 100,
        "predicted_default_rate": 0.11,
        "observed_default_rate": 0.10,
        "performance": _metrics(),
    }
    values.update(updates)
    return BacktestEvidence.model_validate(values)


def _fairness(**updates: object) -> FairnessValidationEvidence:
    values: dict[str, object] = {
        "monitor_report_digest": "b" * 64,
        "model_id": MODEL_ID,
        "model_version": MODEL_VERSION,
        "status": "passed",
        "window_started_at": WINDOW_START,
        "window_ended_at": WINDOW_END,
        "provider_id": "private-fairness-store",
        "provider_version": "2026.08",
        "audit_chain_id": "audit-chain-1",
        "audit_head_sequence": 51,
        "audit_head_event_hash": "c" * 64,
        "selected_event_count": 1_000,
        "analyzed_observation_count": 1_000,
        "integrity_error_count": 0,
    }
    values.update(updates)
    return FairnessValidationEvidence.model_validate(values)


def _challenger(**updates: object) -> ChallengerEvidence:
    values: dict[str, object] = {
        "model_id": "credit-pd-challenger",
        "model_version": "2026.08",
        "dataset_ref": "dataset-sha256:champion-sample",
        "evidence_ref": "backtest-sha256:challenger",
        "observation_started_at": WINDOW_START,
        "observation_ended_at": WINDOW_END,
        "evaluated_at": EVALUATED_AT,
        "sample_count": 1_000,
        "default_count": 100,
        "performance": _metrics(gini=0.54, auc_roc=0.77, brier_score=0.10),
    }
    values.update(updates)
    return ChallengerEvidence.model_validate(values)


def _finding(**updates: object) -> ValidationFinding:
    values: dict[str, object] = {
        "finding_id": "FINDING-001",
        "section": ValidationSection.OUTCOMES_ANALYSIS,
        "severity": FindingSeverity.MEDIUM,
        "title": "Calibration monitoring needed",
        "description": "Monitoring cadence needs explicit ownership.",
        "recommendation": "Assign and evidence the monthly monitoring control.",
        "owner": "model-risk-management",
        "opened_at": NOW - timedelta(days=10),
        "due_at": NOW + timedelta(days=20),
        "status": FindingStatus.OPEN,
    }
    values.update(updates)
    return ValidationFinding.model_validate(values)


def _strict_report(**updates: object) -> ModelValidationReport:
    values: dict[str, object] = {
        "report_id": "VALIDATION-001",
        "revision": 1,
        "model_name": "Credit PD",
        "model_id": MODEL_ID,
        "model_version": MODEL_VERSION,
        "validator_id": "independent-validator",
        "feature_schema_digest": SCHEMA_DIGEST,
        "backtest": _backtest(),
        "fairness": _fairness(),
        "challenge_evidence_refs": ("challenge-workpaper:001",),
        "validated_at": NOW,
    }
    values.update(updates)
    return ModelValidator().validate_evidence(**values)  # type: ignore[arg-type]


def test_accepts_exact_roc_gini_auc_identity() -> None:
    report = _strict_report()

    assert report.status is ModelValidationReportStatus.VALIDATED
    assert report.approved_for_use is True


def test_accepts_gini_auc_difference_at_configured_tolerance() -> None:
    policy = ValidationPolicy(gini_auc_absolute_tolerance=1e-4)
    backtest = _backtest(performance=_metrics(gini=0.5001))

    report = ModelValidator(policy=policy).validate_evidence(
        report_id="VALIDATION-001",
        revision=1,
        model_name="Credit PD",
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        validator_id="independent-validator",
        feature_schema_digest=SCHEMA_DIGEST,
        backtest=backtest,
        fairness=_fairness(),
        challenge_evidence_refs=("challenge-workpaper:001",),
        validated_at=NOW,
    )

    assert report.status is ModelValidationReportStatus.VALIDATED


def test_rejects_contradictory_roc_gini_auc_pair() -> None:
    with pytest.raises(ValueError, match="Gini"):
        _strict_report(backtest=_backtest(performance=_metrics(gini=0.51)))


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), True, "0.5"])
def test_rejects_nonfinite_or_coerced_performance_metric(bad_value: object) -> None:
    with pytest.raises(ValidationError):
        _metrics(gini=bad_value)


def test_rejects_roc_identity_when_gini_definition_is_unspecified() -> None:
    backtest = _backtest(performance=_metrics(gini_definition=GiniDefinition.UNSPECIFIED))

    with pytest.raises(ValueError, match="ROC-derived"):
        _strict_report(backtest=backtest)


def test_rejects_backtest_default_count_above_sample_count() -> None:
    with pytest.raises(ValidationError, match="default_count"):
        _backtest(sample_count=100, default_count=101, observed_default_rate=1.0)


def test_rejects_backtest_rate_that_disagrees_with_counts() -> None:
    with pytest.raises(ValidationError, match="rate"):
        _backtest(observed_default_rate=0.11)


def test_rejects_backtest_evaluated_before_observation_window_ends() -> None:
    with pytest.raises(ValidationError, match="evaluation"):
        _backtest(evaluated_at=WINDOW_END - timedelta(microseconds=1))


def test_rejects_backtest_below_policy_minimum_sample() -> None:
    policy = ValidationPolicy(minimum_backtest_sample_count=1_001)

    with pytest.raises(ValueError, match="sample"):
        ModelValidator(policy=policy).validate_evidence(
            report_id="VALIDATION-001",
            revision=1,
            model_name="Credit PD",
            model_id=MODEL_ID,
            model_version=MODEL_VERSION,
            validator_id="independent-validator",
            feature_schema_digest=SCHEMA_DIGEST,
            backtest=_backtest(),
            fairness=_fairness(),
            validated_at=NOW,
        )


def test_rejects_stale_backtest_evidence() -> None:
    policy = ValidationPolicy(maximum_backtest_age=timedelta(hours=12))

    with pytest.raises(ValueError, match="stale"):
        ModelValidator(policy=policy).validate_evidence(
            report_id="VALIDATION-001",
            revision=1,
            model_name="Credit PD",
            model_id=MODEL_ID,
            model_version=MODEL_VERSION,
            validator_id="independent-validator",
            feature_schema_digest=SCHEMA_DIGEST,
            backtest=_backtest(),
            fairness=_fairness(),
            validated_at=NOW,
        )


def test_rejects_future_backtest_evidence() -> None:
    with pytest.raises(ValueError, match="future"):
        _strict_report(backtest=_backtest(evaluated_at=NOW + timedelta(microseconds=1)))


def test_challenger_deltas_are_derived_from_same_sample() -> None:
    champion = _backtest()
    challenger = _challenger()

    assert challenger.auc_delta_from(champion) == pytest.approx(0.02)
    assert challenger.brier_delta_from(champion) == pytest.approx(-0.02)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dataset_ref", "dataset-sha256:different"),
        ("observation_ended_at", WINDOW_END - timedelta(days=1)),
        ("sample_count", 999),
        ("default_count", 99),
    ],
)
def test_rejects_challenger_not_evaluated_on_champion_sample(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="same sample"):
        _strict_report(
            challenger=_challenger(**{field: value}),
            challenge_evidence_refs=("challenge-workpaper:001",),
        )


def test_rejects_challenger_with_same_exact_model_identity() -> None:
    with pytest.raises(ValueError, match="different exact model"):
        _strict_report(
            challenger=_challenger(model_id=MODEL_ID, model_version=MODEL_VERSION),
            challenge_evidence_refs=("challenge-workpaper:001",),
        )


def test_rejects_future_challenger_evidence() -> None:
    with pytest.raises(ValueError, match="future"):
        _strict_report(
            challenger=_challenger(evaluated_at=NOW + timedelta(microseconds=1)),
            challenge_evidence_refs=("challenge-workpaper:001",),
        )


@pytest.mark.parametrize(
    "performance",
    [
        _metrics(gini_definition=GiniDefinition.UNSPECIFIED),
        _metrics(gini=0.51),
    ],
)
def test_rejects_challenger_without_consistent_roc_derived_gini(
    performance: PerformanceMetrics,
) -> None:
    with pytest.raises(ValueError, match="challenger.*Gini"):
        _strict_report(
            challenger=_challenger(performance=performance),
            challenge_evidence_refs=("challenge-workpaper:001",),
        )


def test_open_high_finding_makes_report_unvalidated() -> None:
    report = _strict_report(findings=(_finding(severity=FindingSeverity.HIGH),))

    assert report.status is ModelValidationReportStatus.UNVALIDATED
    assert report.approved_for_use is False


def test_closed_high_finding_does_not_block_validation() -> None:
    report = _strict_report(
        findings=(
            _finding(
                severity=FindingSeverity.HIGH,
                status=FindingStatus.CLOSED,
                closed_at=NOW - timedelta(days=1),
                closure_evidence_refs=("remediation-evidence:001",),
            ),
        ),
    )

    assert report.status is ModelValidationReportStatus.VALIDATED


def test_rejects_closed_finding_without_closure_evidence() -> None:
    with pytest.raises(ValidationError, match="closed"):
        _finding(status=FindingStatus.CLOSED, closed_at=NOW)


def test_rejects_open_finding_with_closure_evidence() -> None:
    with pytest.raises(ValidationError, match="closed"):
        _finding(closure_evidence_refs=("remediation-evidence:001",))


def test_rejects_finding_due_at_opened_at() -> None:
    opened_at = NOW - timedelta(days=1)

    with pytest.raises(ValidationError, match="due"):
        _finding(opened_at=opened_at, due_at=opened_at)


def test_rejects_finding_opened_after_report_validation() -> None:
    with pytest.raises(ValidationError, match="opened"):
        _strict_report(findings=(_finding(opened_at=NOW + timedelta(microseconds=1)),))


def test_rejects_finding_closed_after_report_validation() -> None:
    with pytest.raises(ValidationError, match="closed"):
        _strict_report(
            findings=(
                _finding(
                    status=FindingStatus.CLOSED,
                    closed_at=NOW + timedelta(microseconds=1),
                    closure_evidence_refs=("remediation-evidence:001",),
                ),
            )
        )


def test_rejects_duplicate_finding_ids() -> None:
    finding = _finding()

    with pytest.raises(ValidationError, match="unique"):
        _strict_report(findings=(finding, finding))


def test_second_revision_binds_superseded_report_digest() -> None:
    first = _strict_report()
    second = _strict_report(
        revision=2,
        supersedes_report_ref=first.report_ref,
        findings=(
            _finding(
                status=FindingStatus.CLOSED,
                closed_at=NOW,
                closure_evidence_refs=("remediation-evidence:001",),
            ),
        ),
    )

    assert second.revision == 2
    assert second.supersedes_report_ref == first.report_ref
    assert first.findings == ()


def test_rejects_revision_without_exact_predecessor_reference() -> None:
    with pytest.raises(ValidationError, match="predecessor"):
        _strict_report(revision=2)


def test_report_is_deeply_immutable() -> None:
    report = _strict_report(findings=(_finding(),))

    with pytest.raises(ValidationError):
        report.findings[0].owner = "caller-controlled"


def test_fairness_evidence_binds_exact_model() -> None:
    with pytest.raises(ValueError, match="fairness"):
        _strict_report(fairness=_fairness(model_version="different"))


def test_fairness_binding_is_derived_from_exact_model_aggregate_report() -> None:
    analysis = FairnessAnalyzer("group-a", "group-b", min_group_size=1).analyze(
        (
            FairnessObservation(
                decision_ref="decision-a",
                group_name="group-a",
                outcome="approve",
                predicted_pd=0.1,
                observed_default=False,
            ),
            FairnessObservation(
                decision_ref="decision-b",
                group_name="group-b",
                outcome="approve",
                predicted_pd=0.2,
                observed_default=False,
            ),
        )
    )
    monitor_report = FairnessMonitoringReport(
        window_started_at=WINDOW_START,
        window_ended_at=WINDOW_END,
        provider_id="private-fairness-store",
        provider_version="2026.08",
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        audit_chain_id="audit-chain-1",
        audit_head_sequence=51,
        audit_head_event_hash="c" * 64,
        selected_event_count=2,
        analyzed_observation_count=2,
        malformed_event_count=0,
        duplicate_decision_count=0,
        missing_observation_count=0,
        malformed_observation_count=0,
        provider_error_count=0,
        status=ModelFairnessStatus.FAILED,
        analysis=analysis,
    )

    evidence = FairnessValidationEvidence.from_monitor(monitor_report)

    assert (evidence.model_id, evidence.model_version) == (MODEL_ID, MODEL_VERSION)
    assert evidence.status == "failed"
    assert evidence.selected_event_count == 2
    assert evidence.analyzed_observation_count == 2
    assert "group-a" not in evidence.model_dump_json()
    assert "decision-a" not in evidence.model_dump_json()


def test_serialized_fairness_binding_contains_only_aggregates() -> None:
    payload = json.loads(_strict_report().model_dump_json())

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    serialized_keys = keys(payload)

    for private_name in (
        "group_name",
        "predicted_pd",
        "observed_default",
        "application_ref",
        "decision_ref",
        "event_id",
    ):
        assert private_name not in serialized_keys


def test_legacy_validation_rejects_one_high_finding_for_use() -> None:
    report = ModelValidator().validate(
        "VALIDATION-LEGACY",
        "Credit PD",
        MODEL_VERSION,
        _metrics(gini=0.20, auc_roc=0.60),
    )

    assert report.overall_rating == "needs_improvement"
    assert report.approved_for_use is False
