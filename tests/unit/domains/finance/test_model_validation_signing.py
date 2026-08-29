"""Acceptance tests for signed model-validation report provenance."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agentguard.domains.finance.credit_risk.agent_templates import CreditDecisionPolicy
from agentguard.domains.finance.credit_risk.attribution import (
    AttributionMethod,
    AttributionResult,
)
from agentguard.domains.finance.credit_risk.model_governance import (
    InMemoryModelValidationReportSource,
    ModelFairnessStatus,
    ModelProvenanceGuardrail,
    ModelValidationSigner,
    ModelValidationStatus,
    ModelValidationVerifier,
    SignedModelValidationEnvelope,
    SignedReportModelGovernanceEvidenceProvider,
    feature_schema_digest,
)
from agentguard.domains.finance.credit_risk.model_validation import (
    BacktestEvidence,
    FairnessValidationEvidence,
    FindingSeverity,
    FindingStatus,
    GiniDefinition,
    ModelValidationReport,
    ModelValidator,
    PerformanceMetrics,
    ValidationFinding,
    ValidationSection,
)
from agentguard.guardrails import (
    GuardrailContext,
    GuardrailEffect,
    GuardrailStage,
    IdentitySnapshot,
    canonical_json_bytes,
)
from agentguard.guardrails.reason_codes import FAIR_CHECK_FAILED

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
MODEL_ID = "credit-pd"
MODEL_VERSION = "2026.08"
KEY = b"model-validation-signing-key-001"
OTHER_KEY = b"different-model-validation-key-01"
KEY_ID = "model-validation-2026-08"
FEATURE_SCHEMA_DIGEST = feature_schema_digest(("dti_ratio", "fico_score"))


def _report(
    *,
    model_id: str = MODEL_ID,
    model_version: str = MODEL_VERSION,
    revision: int = 1,
    supersedes_report_ref: str | None = None,
    validated_at: datetime = NOW,
    fairness_status: str = "passed",
    findings: tuple[ValidationFinding, ...] = (),
) -> ModelValidationReport:
    metrics = PerformanceMetrics(
        gini=0.50,
        ks_statistic=0.35,
        auc_roc=0.75,
        psi=0.05,
        accuracy=0.85,
        brier_score=0.12,
        gini_definition=GiniDefinition.ROC_DERIVED,
    )
    backtest = BacktestEvidence(
        model_id=model_id,
        model_version=model_version,
        dataset_ref="dataset-sha256:champion-sample",
        evidence_ref="backtest-sha256:champion",
        observation_started_at=validated_at - timedelta(days=90),
        observation_ended_at=validated_at - timedelta(days=30),
        evaluated_at=validated_at - timedelta(days=1),
        sample_count=1_000,
        default_count=100,
        predicted_default_rate=0.11,
        observed_default_rate=0.10,
        performance=metrics,
    )
    fairness = FairnessValidationEvidence(
        monitor_report_digest="b" * 64,
        model_id=model_id,
        model_version=model_version,
        status=fairness_status,
        window_started_at=validated_at - timedelta(days=90),
        window_ended_at=validated_at - timedelta(days=1),
        provider_id="private-fairness-store",
        provider_version="2026.08",
        audit_chain_id="audit-chain-1",
        audit_head_sequence=51,
        audit_head_event_hash="c" * 64,
        selected_event_count=1_000,
        analyzed_observation_count=1_000,
        integrity_error_count=0,
    )
    return ModelValidator().validate_evidence(
        report_id="VALIDATION-001",
        revision=revision,
        supersedes_report_ref=supersedes_report_ref,
        model_name="Credit PD",
        model_id=model_id,
        model_version=model_version,
        validator_id="independent-validator",
        feature_schema_digest=FEATURE_SCHEMA_DIGEST,
        backtest=backtest,
        fairness=fairness,
        findings=findings,
        challenge_evidence_refs=("challenge-workpaper:001",),
        validated_at=validated_at,
    )


def _envelope(**report_updates: object) -> SignedModelValidationEnvelope:
    return ModelValidationSigner(KEY_ID, KEY).sign(_report(**report_updates))  # type: ignore[arg-type]


def _finding(
    *,
    status: FindingStatus = FindingStatus.OPEN,
    closed_at: datetime | None = None,
    closure_evidence_refs: tuple[str, ...] = (),
) -> ValidationFinding:
    return ValidationFinding(
        finding_id="FINDING-HIGH-001",
        section=ValidationSection.OUTCOMES_ANALYSIS,
        severity=FindingSeverity.HIGH,
        title="High-risk validation gap",
        description="The high-risk validation gap requires explicit remediation.",
        recommendation="Close and evidence the remediation.",
        owner="model-risk-management",
        opened_at=NOW - timedelta(days=10),
        due_at=NOW + timedelta(days=20),
        status=status,
        closed_at=closed_at,
        closure_evidence_refs=closure_evidence_refs,
    )


def _manually_sign(report: ModelValidationReport) -> SignedModelValidationEnvelope:
    """Exercise provider checks independently from signer admission."""

    report_ref = report.report_ref
    unsigned = b"agentguard:model-validation-report:hmac-sha256:v1\x00" + canonical_json_bytes(
        {
            "algorithm": "HMAC-SHA256",
            "key_id": KEY_ID,
            "report": report.model_dump(mode="json"),
            "report_ref": report_ref,
            "signature_schema_version": "1",
        }
    )
    return SignedModelValidationEnvelope.model_construct(
        key_id=KEY_ID,
        report_ref=report_ref,
        report=report,
        signature=hmac.new(KEY, unsigned, hashlib.sha256).hexdigest(),
    )


def _decision_context() -> GuardrailContext:
    attribution = AttributionResult(
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        reference_id="reference-1",
        method=AttributionMethod.SCORECARD_POINTS_LOST,
        feature_names=("dti_ratio", "fico_score"),
        contributions=(),
    )
    candidate = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-001",
        application_ref="APPLICATION-001",
        pd_score=0.02,
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        attribution=attribution,
    )
    return GuardrailContext(
        trace_id="trace-1",
        invocation_id="invocation-1",
        stage=GuardrailStage.ON_DECISION,
        identity=IdentitySnapshot(agent_id="agent-1", name="Credit Agent"),
        action="decision:approve",
        resource="application/opaque-1",
        payload=candidate.to_payload(),
    )


def test_signing_is_canonical_and_deterministic() -> None:
    first = _envelope()
    second = _envelope()

    assert first == second
    assert first.report_ref == "74a0678a86dc4c194f1740417c13cb19f80aabd16aea0ba63bc619f7cbd5a1dd"
    assert first.signature == "1a4f7d130368ad8b93d85dec7f9793a1d376182725ebabc06a8904a6dbfe4067"


def test_verifier_returns_detached_verified_report() -> None:
    envelope = _envelope()

    verified = ModelValidationVerifier({KEY_ID: KEY}).verify(envelope)

    assert verified == envelope.report
    assert verified is not envelope.report


@pytest.mark.parametrize("key", [b"", b"short", b"x" * 31])
def test_signer_rejects_keys_shorter_than_32_bytes(key: bytes) -> None:
    with pytest.raises(ValueError, match="at least 32"):
        ModelValidationSigner(KEY_ID, key)


def test_verifier_rejects_tampered_report_field() -> None:
    envelope = _envelope()
    tampered = envelope.model_copy(
        update={"report": envelope.report.model_copy(update={"model_name": "Tampered"})}
    )

    with pytest.raises(ValueError, match="reference"):
        ModelValidationVerifier({KEY_ID: KEY}).verify(tampered)


def test_verifier_rejects_tampered_signature() -> None:
    envelope = _envelope()
    tampered = envelope.model_copy(update={"signature": "0" * 64})

    with pytest.raises(ValueError, match="signature"):
        ModelValidationVerifier({KEY_ID: KEY}).verify(tampered)


def test_verifier_rejects_tampered_report_digest() -> None:
    envelope = _envelope()
    tampered = envelope.model_copy(update={"report_ref": "0" * 64})

    with pytest.raises(ValueError, match="reference"):
        ModelValidationVerifier({KEY_ID: KEY}).verify(tampered)


def test_verifier_rejects_unknown_key_id() -> None:
    envelope = _envelope().model_copy(update={"key_id": "unknown-key"})

    with pytest.raises(ValueError, match="unknown"):
        ModelValidationVerifier({KEY_ID: KEY}).verify(envelope)


def test_verifier_rejects_wrong_key() -> None:
    with pytest.raises(ValueError, match="signature"):
        ModelValidationVerifier({KEY_ID: OTHER_KEY}).verify(_envelope())


@pytest.mark.parametrize(
    ("field", "value"),
    [("signature_schema_version", "2"), ("algorithm", "none")],
)
def test_envelope_schema_rejects_version_or_algorithm_tamper(
    field: str,
    value: str,
) -> None:
    payload = _envelope().model_dump(mode="python")
    payload[field] = value

    with pytest.raises(ValidationError):
        SignedModelValidationEnvelope.model_validate(payload)


@pytest.mark.asyncio
async def test_provider_projects_exact_verified_report_fields() -> None:
    envelope = _envelope()
    provider = SignedReportModelGovernanceEvidenceProvider(
        InMemoryModelValidationReportSource((envelope,)),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )

    evidence = await provider.get(MODEL_ID, MODEL_VERSION)

    assert evidence is not None
    assert evidence.model_id == MODEL_ID
    assert evidence.model_version == MODEL_VERSION
    assert evidence.validation_status is ModelValidationStatus.VALIDATED
    assert evidence.fairness_status is ModelFairnessStatus.PASSED
    assert evidence.feature_schema_digest == FEATURE_SCHEMA_DIGEST
    assert evidence.validation_ref == envelope.report_ref
    assert evidence.fairness_ref == "b" * 64
    assert evidence.validated_at == NOW
    assert evidence.expires_at == envelope.report.expires_at


@pytest.mark.asyncio
async def test_current_signed_report_allows_live_exact_model_decision() -> None:
    provider = SignedReportModelGovernanceEvidenceProvider(
        InMemoryModelValidationReportSource((_envelope(),)),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )
    guardrail = ModelProvenanceGuardrail(provider, clock=lambda: NOW)

    outcome = await guardrail.evaluate(_decision_context())

    assert outcome.effect is GuardrailEffect.ALLOW


@pytest.mark.asyncio
async def test_failed_signed_fairness_report_keeps_distinct_live_denial() -> None:
    provider = SignedReportModelGovernanceEvidenceProvider(
        InMemoryModelValidationReportSource((_envelope(fairness_status="failed"),)),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )
    guardrail = ModelProvenanceGuardrail(provider, clock=lambda: NOW)

    outcome = await guardrail.evaluate(_decision_context())

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (FAIR_CHECK_FAILED,)


@pytest.mark.asyncio
async def test_provider_isolates_exact_model_version() -> None:
    provider = SignedReportModelGovernanceEvidenceProvider(
        InMemoryModelValidationReportSource((_envelope(),)),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )

    assert await provider.get(MODEL_ID, "different") is None
    assert await provider.get("different", MODEL_VERSION) is None


@pytest.mark.asyncio
async def test_provider_rejects_tampered_source_envelope() -> None:
    tampered = _envelope().model_copy(update={"signature": "0" * 64})
    provider = SignedReportModelGovernanceEvidenceProvider(
        InMemoryModelValidationReportSource((tampered,)),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )

    assert await provider.get(MODEL_ID, MODEL_VERSION) is None


@pytest.mark.asyncio
async def test_provider_rejects_future_report() -> None:
    future = _envelope(validated_at=NOW + timedelta(microseconds=1))
    provider = SignedReportModelGovernanceEvidenceProvider(
        InMemoryModelValidationReportSource((future,)),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )

    assert await provider.get(MODEL_ID, MODEL_VERSION) is None


@pytest.mark.asyncio
async def test_provider_rejects_report_at_expiry_boundary() -> None:
    envelope = _envelope()
    assert envelope.report.expires_at is not None
    provider = SignedReportModelGovernanceEvidenceProvider(
        InMemoryModelValidationReportSource((envelope,)),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: envelope.report.expires_at,  # type: ignore[arg-type,return-value]
    )

    assert await provider.get(MODEL_ID, MODEL_VERSION) is None


@pytest.mark.asyncio
async def test_provider_converts_source_failure_to_no_evidence() -> None:
    class FailingSource:
        source_id = "failing-source"
        version = "1"

        async def get_latest(
            self, model_id: str, model_version: str
        ) -> SignedModelValidationEnvelope | None:
            raise RuntimeError("private backend diagnostic")

        async def get_revision(
            self, model_id: str, model_version: str, revision: int
        ) -> SignedModelValidationEnvelope | None:
            raise AssertionError("not reached")

    provider = SignedReportModelGovernanceEvidenceProvider(
        FailingSource(),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )

    assert await provider.get(MODEL_ID, MODEL_VERSION) is None


@pytest.mark.asyncio
async def test_provider_rejects_source_identity_change() -> None:
    class MutableSource:
        source_id = "mutable-source"
        version = "1"

        async def get_latest(
            self, model_id: str, model_version: str
        ) -> SignedModelValidationEnvelope | None:
            return _envelope()

        async def get_revision(
            self, model_id: str, model_version: str, revision: int
        ) -> SignedModelValidationEnvelope | None:
            return None

    source = MutableSource()
    provider = SignedReportModelGovernanceEvidenceProvider(
        source,
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )
    source.version = "2"

    assert await provider.get(MODEL_ID, MODEL_VERSION) is None


def test_source_rejects_revision_gap() -> None:
    first = _envelope()
    third = _envelope(
        revision=3,
        supersedes_report_ref=first.report_ref,
    )

    with pytest.raises(ValueError, match="contiguous"):
        InMemoryModelValidationReportSource((first, third))


def test_source_rejects_forked_predecessor_lineage() -> None:
    first = _envelope()
    second = _envelope(revision=2, supersedes_report_ref="0" * 64)

    with pytest.raises(ValueError, match="predecessor"):
        InMemoryModelValidationReportSource((first, second))


def test_signer_rejects_expiry_extended_beyond_derived_evidence_bound() -> None:
    report = _report()
    assert report.expires_at is not None
    extended = report.model_copy(update={"expires_at": report.expires_at + timedelta(days=1)})

    with pytest.raises(ValueError, match="expiry"):
        ModelValidationSigner(KEY_ID, KEY).sign(extended)


@pytest.mark.asyncio
async def test_provider_rejects_validly_signed_expiry_beyond_derived_evidence_bound() -> None:
    report = _report()
    assert report.expires_at is not None
    extended = report.model_copy(update={"expires_at": report.expires_at + timedelta(days=1)})
    malformed = _manually_sign(extended)

    class Source:
        source_id = "adversarial-model-validation-source"
        version = "1"

        async def get_latest(
            self, model_id: str, model_version: str
        ) -> SignedModelValidationEnvelope | None:
            return malformed

        async def get_revision(
            self, model_id: str, model_version: str, revision: int
        ) -> SignedModelValidationEnvelope | None:
            return None

    provider = SignedReportModelGovernanceEvidenceProvider(
        Source(),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )

    assert await provider.get(MODEL_ID, MODEL_VERSION) is None


def test_source_rejects_revision_that_omits_unresolved_high_finding() -> None:
    first_report = _report(findings=(_finding(),))
    first = ModelValidationSigner(KEY_ID, KEY).sign(first_report)
    second = _envelope(revision=2, supersedes_report_ref=first.report_ref)
    with pytest.raises(ValueError, match="unresolved finding"):
        InMemoryModelValidationReportSource((first, second))


@pytest.mark.asyncio
async def test_provider_accepts_revision_that_explicitly_closes_high_finding() -> None:
    first_report = _report(findings=(_finding(),))
    first = ModelValidationSigner(KEY_ID, KEY).sign(first_report)
    closed = _finding(
        status=FindingStatus.CLOSED,
        closed_at=NOW,
        closure_evidence_refs=("remediation-evidence:001",),
    )
    second = _envelope(
        revision=2,
        supersedes_report_ref=first.report_ref,
        findings=(closed,),
    )
    provider = SignedReportModelGovernanceEvidenceProvider(
        InMemoryModelValidationReportSource((first, second)),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )

    evidence = await provider.get(MODEL_ID, MODEL_VERSION)

    assert evidence is not None
    assert evidence.validation_status is ModelValidationStatus.VALIDATED


@pytest.mark.asyncio
async def test_provider_rejects_source_that_substitutes_revision_one_for_revision_two() -> None:
    first = _envelope()
    third = _envelope(revision=3, supersedes_report_ref=first.report_ref)

    class SkippingSource:
        source_id = "skipping-model-validation-source"
        version = "1"

        async def get_latest(
            self, model_id: str, model_version: str
        ) -> SignedModelValidationEnvelope | None:
            return third

        async def get_revision(
            self, model_id: str, model_version: str, revision: int
        ) -> SignedModelValidationEnvelope | None:
            assert revision == 2
            return first

    provider = SignedReportModelGovernanceEvidenceProvider(
        SkippingSource(),
        ModelValidationVerifier({KEY_ID: KEY}),
        clock=lambda: NOW,
    )

    assert await provider.get(MODEL_ID, MODEL_VERSION) is None
