from __future__ import annotations

import math
from typing import Any

import pytest
from pydantic import BaseModel

from agentguard.guardrails import (
    DecisionPayload,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    IdentitySnapshot,
    MessagePayload,
    ToolCallPayload,
    ToolResultPayload,
    canonical_json_bytes,
    normalize_payload,
    thaw_payload,
    validate_transformation,
)


class _JsonModel(BaseModel):
    value: int


def test_payloads_are_deeply_immutable_and_isolated_from_callers() -> None:
    arguments = {"nested": [{"value": 1}]}
    roles = ["analyst"]
    metadata = {"team": {"name": "risk"}}
    result = {"nested": [{"value": 1}]}
    message_value = {"parts": ["hello"]}
    identity = IdentitySnapshot(agent_id="agent-1", name="credit", roles=roles, metadata=metadata)
    payload = ToolCallPayload(arguments=arguments)
    tool_result = ToolResultPayload(result=result)
    message = MessagePayload(message=message_value)

    arguments["nested"][0]["value"] = 2
    roles.append("admin")
    metadata["team"]["name"] = "changed"
    result["nested"][0]["value"] = 2
    message_value["parts"][0] = "changed"

    assert payload.arguments["nested"][0]["value"] == 1
    assert identity.roles == ("analyst",)
    assert identity.metadata["team"]["name"] == "risk"
    assert tool_result.result["nested"][0]["value"] == 1
    assert message.message["parts"][0] == "hello"

    with pytest.raises(TypeError):
        payload.arguments["nested"][0]["value"] = 3
    with pytest.raises(TypeError):
        payload.arguments["nested"][0] = {"value": 3}
    with pytest.raises(TypeError):
        message.message["parts"][0] = "changed"
    with pytest.raises(Exception):
        identity.agent_id = "other"


def test_decision_payload_is_deeply_immutable_and_serializable() -> None:
    payload = DecisionPayload(
        domain="credit_risk",
        decision_id="decision-001",
        outcome="decline",
        body={"model": {"id": "pd-model", "version": "1"}, "reasons": ["AG-001"]},
    )

    assert payload.model_dump(mode="json") == {
        "kind": "decision",
        "domain": "credit_risk",
        "decision_id": "decision-001",
        "outcome": "decline",
        "body": {
            "model": {"id": "pd-model", "version": "1"},
            "reasons": ["AG-001"],
        },
    }
    with pytest.raises(TypeError):
        payload.body["model"]["id"] = "changed"
    with pytest.raises(Exception):
        payload.decision_id = "changed"


def test_thaw_payload_returns_fresh_fully_mutable_copies() -> None:
    payload = ToolCallPayload(arguments={"nested": [{"value": 1}]})

    first = thaw_payload(payload.arguments)
    second = thaw_payload(payload.arguments)
    first["nested"][0]["value"] = 2

    assert second == {"nested": [{"value": 1}]}
    assert payload.arguments["nested"][0]["value"] == 1


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_normalization_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        normalize_payload({"value": value})


def test_normalization_rejects_cycles_unknown_values_and_non_string_keys() -> None:
    cyclic: list[Any] = []
    cyclic.append(cyclic)

    for value, match in [
        (cyclic, "cycle"),
        ({1: "value"}, "string"),
        ({"value": object()}, "JSON"),
    ]:
        with pytest.raises((TypeError, ValueError), match=match):
            normalize_payload(value)


def test_normalization_rejects_nfkc_key_collisions() -> None:
    with pytest.raises(ValueError, match="collision"):
        normalize_payload({"K": 1, "K": 2})


def test_normalization_enforces_depth_item_and_byte_limits() -> None:
    at_limit: Any = "leaf"
    for _ in range(20):
        at_limit = [at_limit]
    normalize_payload(at_limit)

    too_deep = [at_limit]
    with pytest.raises(ValueError, match="depth"):
        normalize_payload(too_deep)
    with pytest.raises(ValueError, match="items"):
        normalize_payload([None] * 10_001)
    with pytest.raises(ValueError, match="bytes"):
        normalize_payload("x" * (1024 * 1024 + 1))


def test_normalization_supports_pydantic_json_dump_and_canonical_bytes() -> None:
    normalized = normalize_payload({"model": _JsonModel(value=3)})
    payload = ToolCallPayload(arguments={"nested": [1]})

    assert thaw_payload(normalized) == {"model": {"value": 3}}
    assert payload.model_dump(mode="json") == {
        "kind": "tool_call",
        "arguments": {"nested": [1]},
    }
    assert canonical_json_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_context_and_payload_contracts_are_frozen() -> None:
    context = GuardrailContext(
        trace_id="trace",
        invocation_id="invocation",
        stage=GuardrailStage.PRE_TOOL,
        identity=IdentitySnapshot(agent_id="a", name="A", roles=["reader"]),
        action="tool:read",
        resource="records/1",
        payload=ToolResultPayload(result={"ok": True}),
        attributes={"request": {"channel": "api"}},
    )

    with pytest.raises(TypeError):
        context.attributes["request"]["channel"] = "internal"
    with pytest.raises(Exception):
        context.stage = GuardrailStage.POST_TOOL


def test_outcomes_enforce_reason_and_transformation_contracts() -> None:
    denied = GuardrailOutcome(
        effect=GuardrailEffect.DENY,
        reason_codes=("TEST.EXCEPTION",),
    )
    assert denied.reason_codes == ("TEST.EXCEPTION",)
    assert isinstance(denied.effect.value, str)

    with pytest.raises(ValueError, match="reason"):
        GuardrailOutcome(effect=GuardrailEffect.DENY)
    with pytest.raises(ValueError, match="replacement"):
        GuardrailOutcome(effect=GuardrailEffect.TRANSFORM)
    with pytest.raises(ValueError, match="stable"):
        GuardrailOutcome(
            effect=GuardrailEffect.DENY,
            reason_codes=("free form reason",),
        )


@pytest.mark.parametrize(
    "typo",
    ["RBAC.PERMISION_DENIED", "RESOURCE.UNRESOLVE", "GUARDRAIL.TIMOUT"],
)
def test_reserved_runtime_namespace_rejects_unregistered_codes(typo: str) -> None:
    with pytest.raises(ValueError, match="registered"):
        GuardrailOutcome(effect=GuardrailEffect.DENY, reason_codes=(typo,))


def test_custom_reason_namespace_is_allowed() -> None:
    outcome = GuardrailOutcome(
        effect=GuardrailEffect.DENY,
        reason_codes=("TEST.CUSTOM",),
    )
    assert outcome.reason_codes == ("TEST.CUSTOM",)


def test_transformation_stage_legality_is_reusable() -> None:
    replacement = MessagePayload(message="masked")
    validate_transformation(GuardrailStage.POST_MESSAGE, GuardrailEffect.TRANSFORM, replacement)

    with pytest.raises(ValueError, match="not legal"):
        validate_transformation(
            GuardrailStage.PRE_MESSAGE,
            GuardrailEffect.TRANSFORM,
            replacement,
        )


def test_on_decision_transformation_is_illegal() -> None:
    replacement = DecisionPayload(
        domain="credit_risk",
        decision_id="decision-001",
        outcome="decline",
        body={},
    )

    with pytest.raises(ValueError, match="not legal"):
        validate_transformation(
            GuardrailStage.ON_DECISION,
            GuardrailEffect.TRANSFORM,
            replacement,
        )
