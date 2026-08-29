"""Trusted model evidence must gate every live credit decision."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from agentguard.domains.finance.credit_risk.agent_templates import CreditDecisionPolicy
from agentguard.domains.finance.credit_risk.attribution import AttributionMethod, AttributionResult
from agentguard.domains.finance.credit_risk.model_governance import (
    ModelFairnessStatus,
    ModelGovernanceEvidence,
    ModelProvenanceGuardrail,
    ModelValidationStatus,
    StaticModelGovernanceEvidenceProvider,
    feature_schema_digest,
)
from agentguard.guardrails import (
    GuardrailContext,
    GuardrailEffect,
    GuardrailStage,
    IdentitySnapshot,
)
from agentguard.guardrails.reason_codes import (
    FAIR_CHECK_FAILED,
    MRM_MODEL_UNVALIDATED,
)

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)


def _attribution() -> AttributionResult:
    return AttributionResult(
        model_id="pd-model",
        model_version="1",
        reference_id="reference-1",
        method=AttributionMethod.SCORECARD_POINTS_LOST,
        feature_names=("dti_ratio", "fico_score"),
        contributions=(),
    )


def _context(*, attributes: dict[str, object] | None = None) -> GuardrailContext:
    attribution = _attribution()
    candidate = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-001",
        application_ref="APPLICATION-001",
        pd_score=0.02,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
    )
    return GuardrailContext.model_validate(
        {
            "trace_id": "trace-1",
            "invocation_id": "invocation-1",
            "stage": GuardrailStage.ON_DECISION,
            "identity": IdentitySnapshot(agent_id="agent-1", name="Credit Agent"),
            "action": "decision:approve",
            "resource": "application/opaque-1",
            "payload": candidate.to_payload(),
            "attributes": attributes or {},
        }
    )


def _evidence(
    *,
    validation_status: ModelValidationStatus = ModelValidationStatus.VALIDATED,
    fairness_status: ModelFairnessStatus = ModelFairnessStatus.PASSED,
    expires_at: datetime = NOW + timedelta(days=1),
    validated_at: datetime = NOW - timedelta(days=1),
    schema_digest: str | None = None,
) -> ModelGovernanceEvidence:
    return ModelGovernanceEvidence(
        model_id="pd-model",
        model_version="1",
        validation_status=validation_status,
        fairness_status=fairness_status,
        feature_schema_digest=schema_digest or feature_schema_digest(_attribution().feature_names),
        validation_ref=hashlib.sha256(b"validation-report").hexdigest(),
        fairness_ref=hashlib.sha256(b"fairness-report").hexdigest(),
        validated_at=validated_at,
        expires_at=expires_at,
    )


def _guardrail(*items: ModelGovernanceEvidence) -> ModelProvenanceGuardrail:
    return ModelProvenanceGuardrail(
        StaticModelGovernanceEvidenceProvider(items),
        clock=lambda: NOW,
    )


@pytest.mark.asyncio
async def test_current_exact_model_evidence_allows() -> None:
    outcome = await _guardrail(_evidence()).evaluate(_context())
    assert outcome.effect is GuardrailEffect.ALLOW


@pytest.mark.asyncio
async def test_model_control_skips_notice_boundary() -> None:
    outcome = await _guardrail().evaluate(_context().model_copy(update={"action": "notice:issue"}))
    assert outcome.effect is GuardrailEffect.ALLOW


@pytest.mark.asyncio
async def test_missing_or_stale_model_evidence_denies() -> None:
    missing = await _guardrail().evaluate(_context())
    stale = await _guardrail(_evidence(expires_at=NOW)).evaluate(_context())

    assert missing.reason_codes == (MRM_MODEL_UNVALIDATED,)
    assert stale.reason_codes == (MRM_MODEL_UNVALIDATED,)


@pytest.mark.asyncio
async def test_future_model_evidence_denies() -> None:
    outcome = await _guardrail(
        _evidence(
            validated_at=NOW + timedelta(microseconds=1),
            expires_at=NOW + timedelta(days=1),
        )
    ).evaluate(_context())

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (MRM_MODEL_UNVALIDATED,)


@pytest.mark.asyncio
async def test_failed_fairness_evidence_has_distinct_denial() -> None:
    outcome = await _guardrail(_evidence(fairness_status=ModelFairnessStatus.FAILED)).evaluate(
        _context()
    )

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == (FAIR_CHECK_FAILED,)


@pytest.mark.asyncio
async def test_insufficient_fairness_data_is_not_live_validation() -> None:
    outcome = await _guardrail(
        _evidence(fairness_status=ModelFairnessStatus.INSUFFICIENT_DATA)
    ).evaluate(_context())
    assert outcome.reason_codes == (MRM_MODEL_UNVALIDATED,)


@pytest.mark.asyncio
async def test_feature_schema_digest_mismatch_denies() -> None:
    outcome = await _guardrail(_evidence(schema_digest="0" * 64)).evaluate(_context())
    assert outcome.reason_codes == (MRM_MODEL_UNVALIDATED,)


@pytest.mark.asyncio
async def test_caller_attributes_cannot_supply_trusted_model_evidence() -> None:
    outcome = await _guardrail().evaluate(
        _context(
            attributes={
                "model_validated": True,
                "fairness_passed": True,
                "validation_ref": "caller-controlled",
            }
        )
    )
    assert outcome.reason_codes == (MRM_MODEL_UNVALIDATED,)


def test_provider_rejects_duplicate_exact_model_evidence() -> None:
    evidence = _evidence()
    with pytest.raises(ValueError, match="duplicate"):
        StaticModelGovernanceEvidenceProvider((evidence, evidence))
