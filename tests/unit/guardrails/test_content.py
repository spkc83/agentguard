from __future__ import annotations

import re

import pytest

from agentguard.guardrails import (
    EvidenceSnapshot,
    GuardrailChain,
    GuardrailContext,
    GuardrailEffect,
    GuardrailStage,
    IdentitySnapshot,
    MessagePayload,
    OutputSchemaGuardrail,
    PiiEgressGuardrail,
    PiiInputGuardrail,
    SecretEgressGuardrail,
    ToolCallPayload,
    ToolResultPayload,
    detect_pii,
    mask_pii,
    thaw_payload,
)


def _context(stage: GuardrailStage, payload: object) -> GuardrailContext:
    return GuardrailContext(
        trace_id="trace",
        invocation_id="invocation",
        stage=stage,
        identity=IdentitySnapshot(agent_id="agent", name="Agent", roles=["reader"]),
        action="tool:call",
        resource="tool/result",
        payload=payload,
    )


def test_evidence_snapshot_is_redacted_and_digest_is_deterministic() -> None:
    first = EvidenceSnapshot.capture(
        {
            "b": "SSN 123-45-6789",
            "a": ["person@example.com"],
            "api_key": "not-safe",
        }
    )
    second = EvidenceSnapshot.capture(
        {
            "api_key": "not-safe",
            "a": ["person@example.com"],
            "b": "SSN 123-45-6789",
        }
    )

    assert first.digest == second.digest
    assert re.fullmatch(r"[0-9a-f]{64}", first.digest)
    assert "123-45-6789" not in str(thaw_payload(first.value))
    assert "person@example.com" not in str(thaw_payload(first.value))
    assert "not-safe" not in str(thaw_payload(first.value))
    assert first.model_dump(mode="json")["value"]["api_key"] == "[REDACTED]"


def test_snapshot_can_digest_full_value_and_retain_only_safe_projection() -> None:
    raw = {
        "pd_score": 0.42,
        "feature_names": ["fico_score", "dti_ratio"],
        "applicant": "Alex Example",
    }
    safe = {"decision_ref": "a" * 64, "outcome": "decline"}

    snapshot = EvidenceSnapshot.capture_redacted(raw, safe)

    assert thaw_payload(snapshot.value) == safe
    assert snapshot.digest == EvidenceSnapshot.capture(raw).digest
    assert "fico_score" not in str(snapshot.model_dump(mode="json"))


def test_pii_detection_and_masking_cover_financial_pii_recursively() -> None:
    value = {
        "items": [
            "SSNs 123-45-6789 and 123456789",
            {"routing": "routing number 021000021", "account": "account 123456789012"},
        ],
        "contact": "person@example.com, phone (212) 555-0100, DOB 01/02/1980",
    }

    matches = detect_pii(value)
    masked = thaw_payload(mask_pii(value))

    assert {match.pii_type for match in matches} >= {
        "ssn",
        "routing_number",
        "account_number",
        "email",
        "phone",
        "dob",
    }
    assert "123-45-6789" not in str(masked)
    assert "123456789" not in str(masked)
    assert "person@example.com" not in str(masked)


def test_phone_detector_does_not_mask_ordinary_loan_amounts() -> None:
    text = "Requested loan amount 2500000000 and annual income $150,000"

    assert detect_pii(text) == ()
    assert thaw_payload(mask_pii(text)) == text


def test_invalid_ssns_are_not_treated_as_pii() -> None:
    text = "invalid identifiers 000-12-3456, 666-12-3456, 912-12-3456, 123-00-4567"

    assert detect_pii(text) == ()


def test_numeric_pii_is_only_masked_under_contextual_keys() -> None:
    value = {
        "loan_amount": 2500000000,
        "account_number": 123456789012,
        "routing_number": 21000021,
    }

    matches = detect_pii(value)
    masked = thaw_payload(mask_pii(value))

    assert {match.pii_type for match in matches} == {"account_number", "routing_number"}
    assert masked["loan_amount"] == 2500000000
    assert masked["account_number"] == "XXXXXXXX9012"
    assert masked["routing_number"] == "XXXXXXXXX"


def test_stateless_content_guardrails_have_stable_resume_bindings() -> None:
    guardrails = (PiiInputGuardrail(), PiiEgressGuardrail(), SecretEgressGuardrail())

    assert [guardrail.resume_fingerprint for guardrail in guardrails] == [
        "agentguard.guardrails.content:PiiInputGuardrail:1",
        "agentguard.guardrails.content:PiiEgressGuardrail:1",
        "agentguard.guardrails.content:SecretEgressGuardrail:1",
    ]
    assert GuardrailChain(guardrails).resumable


def test_callable_output_schema_guardrail_is_not_implicitly_resumable() -> None:
    guardrail = OutputSchemaGuardrail(lambda _value: True)

    assert not hasattr(guardrail, "resume_fingerprint")
    assert not GuardrailChain([guardrail]).resumable


@pytest.mark.asyncio
async def test_input_pii_guard_transforms_before_execution_boundary() -> None:
    guard = PiiInputGuardrail()
    context = _context(
        GuardrailStage.INPUT,
        ToolCallPayload(arguments={"customer": {"ssn": "123-45-6789"}}),
    )

    outcome = await guard.evaluate(context)

    assert outcome.effect is GuardrailEffect.TRANSFORM
    assert outcome.reason_codes == ("PII.INPUT_REDACTED",)
    assert isinstance(outcome.replacement_payload, ToolCallPayload)
    assert outcome.replacement_payload.arguments["customer"]["ssn"] == "XXX-XX-6789"


@pytest.mark.asyncio
async def test_post_pii_egress_denies_instead_of_transforming() -> None:
    guard = PiiEgressGuardrail()
    context = _context(
        GuardrailStage.POST_TOOL,
        ToolResultPayload(result="exfiltrated: SSN 123-45-6789"),
    )

    outcome = await guard.evaluate(context)

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == ("PII.EGRESS_DENIED",)
    assert outcome.replacement_payload is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "result",
    [
        {"api_key": "not-safe"},
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        "-----BEGIN PRIVATE KEY-----\nsecret",
    ],
)
async def test_secret_egress_is_denied(result: object) -> None:
    outcome = await SecretEgressGuardrail().evaluate(
        _context(GuardrailStage.POST_TOOL, ToolResultPayload(result=result))
    )

    assert outcome.effect is GuardrailEffect.DENY
    assert outcome.reason_codes == ("SECRET.EGRESS_DENIED",)


@pytest.mark.asyncio
async def test_optional_output_schema_validator_denies_invalid_results() -> None:
    guard = OutputSchemaGuardrail(lambda value: isinstance(value, dict) and "id" in value)

    denied = await guard.evaluate(
        _context(GuardrailStage.POST_TOOL, ToolResultPayload(result={"name": "missing id"}))
    )
    allowed = await guard.evaluate(
        _context(GuardrailStage.POST_TOOL, ToolResultPayload(result={"id": 1}))
    )

    assert denied.effect is GuardrailEffect.DENY
    assert denied.reason_codes == ("OUTPUT.SCHEMA_INVALID",)
    assert allowed.effect is GuardrailEffect.ALLOW


@pytest.mark.asyncio
async def test_message_input_guard_preserves_message_payload_type() -> None:
    outcome = await PiiInputGuardrail().evaluate(
        _context(GuardrailStage.INPUT, MessagePayload(message="email person@example.com"))
    )

    assert isinstance(outcome.replacement_payload, MessagePayload)
