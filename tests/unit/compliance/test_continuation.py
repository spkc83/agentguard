from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from agentguard.compliance.continuation import (
    ApprovalDisposition,
    ApproverAuthenticator,
    ApproverPrincipal,
    ContinuationProtector,
    PostExecutionContinuation,
    PreExecutionContinuation,
    ProtectedContinuation,
    SealedContinuation,
    WorkloadAuthenticationBinding,
    canonical_continuation_aad,
    parse_protected_continuation,
)
from agentguard.compliance.engine import PolicyBundleSnapshot
from agentguard.compliance.execution_journal import ProtectedExecutionOutcome
from agentguard.core import AuthenticatedAgentPrincipal, SignedAuditReference
from agentguard.guardrails import (
    ChainCursor,
    DecisionPayload,
    EvaluatedDecision,
    ExecutorRef,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    ToolCallPayload,
    ToolResultPayload,
    canonical_json_bytes,
)
from agentguard.models import AgentIdentity, PermissionContext

FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "continuation"


def _fixture_bytes(name: str) -> bytes:
    return (FIXTURE_DIR / name).read_bytes().rstrip(b"\n")


def _authentication_binding(*, agent_id: str = "agent-1") -> WorkloadAuthenticationBinding:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return WorkloadAuthenticationBinding(
        principal=AuthenticatedAgentPrincipal(
            agent_id=agent_id,
            method="signed-workload-token",
            authority="https://identity.example.test",
            credential_digest="d" * 64,
            issued_at=now - timedelta(minutes=1),
            not_before=now - timedelta(seconds=30),
            authenticated_at=now,
            expires_at=now + timedelta(minutes=5),
        ),
        registry_id="registry-1",
        registry_revision=4,
        record_revision=3,
        credential_epoch=2,
        audit_reference=SignedAuditReference(
            event_id="e" * 64,
            event_hash="f" * 64,
            chain_id="audit-chain-1",
            sequence=7,
            key_id="audit-key-1",
        ),
    )


def _continuation() -> PreExecutionContinuation:
    payload = ToolCallPayload.model_validate({"arguments": {"query": "safe"}})
    escalation = EvaluatedDecision(
        guardrail_id="approval",
        guardrail_version="1",
        decision=GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("HITL.APPROVAL_REQUIRED",),
        ),
        duration_ms=1.0,
        enforced=True,
    )
    cursor = ChainCursor(
        chain_fingerprint="a" * 64,
        stage=GuardrailStage.PRE_TOOL,
        next_entry_index=1,
        triggering_guardrail_id="approval",
        triggering_guardrail_version="1",
        decisions=(escalation,),
        payload=payload,
    )
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return PreExecutionContinuation(
        escalation_id="esc-1",
        invocation_id="inv-1",
        trace_id="trace-1",
        agent_id="agent-1",
        action="tool:search",
        resource="search",
        permission_context=PermissionContext(
            agent=AgentIdentity(agent_id="agent-1", name="Agent", roles=["operator"]),
            requested_action="tool:search",
            resource="search",
            granted=True,
            reason="approved before escalation",
        ),
        stage=GuardrailStage.PRE_TOOL,
        payload=payload,
        payload_digest=hashlib.sha256(
            canonical_json_bytes(payload.model_dump(mode="json"))
        ).hexdigest(),
        policy_bundle_version=f"sha256:{'b' * 64}",
        policy_bundle_snapshot=None,
        policy_results=(),
        input_decisions=(),
        pre_runtime_outcomes=(),
        guardrail_cursor=cursor,
        executor_ref=ExecutorRef(executor_id="search", version="1", fingerprint="f" * 64),
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def _post_continuation(*, with_cursor: bool = True) -> PostExecutionContinuation:
    payload = ToolResultPayload(result={"answer": "safe"})
    escalation = EvaluatedDecision(
        guardrail_id="output-approval",
        guardrail_version="2",
        decision=GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("HITL.APPROVAL_REQUIRED",),
        ),
        duration_ms=2.0,
        enforced=True,
    )
    cursor = ChainCursor(
        chain_fingerprint="c" * 64,
        stage=GuardrailStage.POST_TOOL,
        next_entry_index=2,
        triggering_guardrail_id="output-approval",
        triggering_guardrail_version="2",
        decisions=(escalation,),
        payload=payload,
    )
    now = datetime(2026, 1, 1, tzinfo=UTC)
    snapshot = PolicyBundleSnapshot(
        version=f"sha256:{'b' * 64}",
        policy_sets=(),
    )
    return PostExecutionContinuation(
        escalation_id="esc-post-1",
        invocation_id="inv-1",
        trace_id="trace-1",
        agent_id="agent-1",
        action="tool:search",
        resource="search",
        permission_context=PermissionContext(
            agent=AgentIdentity(agent_id="agent-1", name="Agent", roles=["operator"]),
            requested_action="tool:search",
            resource="search",
            granted=True,
            reason="approved before execution",
        ),
        stage=GuardrailStage.POST_TOOL,
        payload=payload,
        payload_digest=hashlib.sha256(
            canonical_json_bytes(payload.model_dump(mode="json"))
        ).hexdigest(),
        policy_bundle_version=snapshot.version,
        policy_bundle_snapshot=snapshot,
        policy_results=(),
        prior_outcomes=(GuardrailOutcome(effect=GuardrailEffect.ALLOW),),
        prior_guardrail_decisions=(),
        guardrail_cursor=cursor if with_cursor else None,
        chain_fingerprint="c" * 64,
        execution_duration_ms=42.5,
        execution_completed_at=now,
        created_at=now + timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )


def _decision_post_continuation() -> PostExecutionContinuation:
    continuation = _post_continuation(with_cursor=False)
    payload = DecisionPayload.model_validate(
        {
            "domain": "credit_risk",
            "decision_id": "decision-001",
            "outcome": "decline",
            "body": {"score": 620},
        }
    )
    cursor = ChainCursor(
        chain_fingerprint=continuation.chain_fingerprint,
        stage=GuardrailStage.ON_DECISION,
        next_entry_index=2,
        triggering_guardrail_id="output-approval",
        triggering_guardrail_version="2",
        decisions=(
            EvaluatedDecision(
                guardrail_id="output-approval",
                guardrail_version="2",
                decision=GuardrailOutcome(
                    effect=GuardrailEffect.ESCALATE,
                    reason_codes=("HITL.APPROVAL_REQUIRED",),
                ),
                duration_ms=2.0,
                enforced=True,
            ),
        ),
        payload=payload,
    )
    return PostExecutionContinuation.model_validate(
        {
            **continuation.model_dump(),
            "stage": GuardrailStage.ON_DECISION,
            "payload": payload,
            "payload_digest": hashlib.sha256(
                canonical_json_bytes(payload.model_dump(mode="json"))
            ).hexdigest(),
            "guardrail_cursor": cursor,
        }
    )


def test_approval_contracts_are_frozen_exact_and_runtime_checkable() -> None:
    principal = ApproverPrincipal(
        approver_id="reviewer-1", capabilities=frozenset({"hitl:approve"})
    )

    assert ApprovalDisposition.APPROVE.value == "approve"
    assert principal.capabilities == frozenset({"hitl:approve"})
    with pytest.raises(ValidationError):
        ApproverPrincipal.model_validate({"approver_id": "reviewer-1", "unexpected": True})
    with pytest.raises(ValidationError):
        ApproverPrincipal.model_validate({"approver_id": "reviewer-1", "capabilities": {"admin"}})
    with pytest.raises(ValidationError):
        principal.approver_id = "attacker"

    class Authenticator:
        async def authenticate(self, credential: object) -> ApproverPrincipal:
            return principal

    assert isinstance(Authenticator(), ApproverAuthenticator)


def test_continuation_protector_is_injected_and_runtime_checkable() -> None:
    class Protector:
        async def seal(self, plaintext: bytes, *, aad: bytes) -> SealedContinuation:
            return SealedContinuation(
                algorithm="test-aead",
                key_id="test-key",
                nonce=b"nonce",
                ciphertext=plaintext + aad,
            )

        async def open(self, sealed: SealedContinuation, *, aad: bytes) -> bytes:
            return sealed.ciphertext.removesuffix(aad)

    assert isinstance(Protector(), ContinuationProtector)


def test_pre_execution_continuation_round_trips_and_is_deeply_immutable() -> None:
    continuation = _continuation()
    restored = PreExecutionContinuation.model_validate_json(continuation.model_dump_json())

    assert restored == continuation
    assert restored.guardrail_cursor.chain_fingerprint == "a" * 64
    assert isinstance(restored.payload, ToolCallPayload)
    with pytest.raises(TypeError):
        restored.payload.arguments["query"] = "changed"  # type: ignore[index]
    with pytest.raises(ValidationError):
        PreExecutionContinuation.model_validate(
            {**continuation.model_dump(), "payload_digest": "0" * 64}
        )


def test_v1_continuation_compatibility_rejects_authentication_binding() -> None:
    continuation = _continuation()

    assert continuation.schema_version == 1
    assert continuation.authentication_binding is None
    with pytest.raises(ValidationError, match="schema v1"):
        PreExecutionContinuation.model_validate(
            {
                **continuation.model_dump(),
                "authentication_binding": _authentication_binding(),
            }
        )


def test_v1_pre_and_post_json_match_frozen_golden_bytes() -> None:
    assert _continuation().model_dump_json().encode() == _fixture_bytes("v1-pre.json")
    assert _post_continuation().model_dump_json().encode() == _fixture_bytes("v1-post.json")


def test_v1_post_serialization_stays_exact_when_nested_in_journal_plaintext() -> None:
    continuation = _post_continuation(with_cursor=False)
    outcome = ProtectedExecutionOutcome(
        escalation_id=continuation.escalation_id,
        claim_id="claim-1",
        invocation_id=continuation.invocation_id,
        admission_payload_digest="a" * 64,
        policy_bundle_version=continuation.policy_bundle_version,
        chain_fingerprint=continuation.chain_fingerprint,
        continuation=continuation,
    )

    serialized = outcome.model_dump_json().encode()
    assert serialized == _fixture_bytes("v1-journal-outcome.json")


@pytest.mark.parametrize("factory", [_continuation, _post_continuation])
def test_v2_continuation_requires_matching_authentication_binding(
    factory: object,
) -> None:
    continuation = cast("Any", factory)()

    with pytest.raises(ValidationError, match="requires authentication binding"):
        type(continuation).model_validate({**continuation.model_dump(), "schema_version": 2})
    with pytest.raises(ValidationError, match="does not match continuation agent"):
        type(continuation).model_validate(
            {
                **continuation.model_dump(),
                "schema_version": 2,
                "authentication_binding": _authentication_binding(agent_id="agent-2"),
            }
        )


def test_v2_authentication_binding_round_trips_and_is_deeply_immutable() -> None:
    continuation = PreExecutionContinuation.model_validate(
        {
            **_continuation().model_dump(),
            "schema_version": 2,
            "authentication_binding": _authentication_binding(),
        }
    )
    restored = PreExecutionContinuation.model_validate_json(continuation.model_dump_json())

    assert restored == continuation
    assert restored.authentication_binding is not None
    with pytest.raises(ValidationError):
        restored.authentication_binding.credential_epoch = 3
    with pytest.raises(ValidationError):
        restored.authentication_binding.principal.agent_id = "agent-2"
    with pytest.raises(ValidationError):
        WorkloadAuthenticationBinding.model_validate(
            {
                **restored.authentication_binding.model_dump(),
                "registry_id": " registry-1",
            }
        )


@pytest.mark.parametrize("factory", [_continuation, _post_continuation])
def test_v3_evidence_fields_round_trip_and_reject_tampering(factory: object) -> None:
    continuation = cast("Any", factory)()
    linked = type(continuation).model_validate(
        {
            **continuation.model_dump(),
            "schema_version": 3,
            "subject_ref": {"namespace": "credit-application", "value": "application-001"},
            "links": (
                {
                    "relation": "decision",
                    "target": {"namespace": "credit-decision", "value": "decision-001"},
                },
            ),
            "redacted_evidence": {"decision_id": "decision-001"},
        }
    )

    restored = type(linked).model_validate_json(linked.model_dump_json())
    assert restored == linked
    with pytest.raises(ValidationError, match="must be unique"):
        type(linked).model_validate(
            {
                **linked.model_dump(),
                "links": (*linked.links, linked.links[0]),
            }
        )
    with pytest.raises(ValidationError, match="canonical printable text"):
        type(linked).model_validate(
            {
                **linked.model_dump(),
                "subject_ref": {"namespace": " credit-application", "value": "application-001"},
            }
        )


@pytest.mark.parametrize("factory", [_continuation, _post_continuation])
def test_v3_requires_extended_evidence(factory: object) -> None:
    continuation = cast("Any", factory)()
    with pytest.raises(ValidationError, match="requires evidence fields"):
        type(continuation).model_validate({**continuation.model_dump(), "schema_version": 3})


def test_post_execution_continuation_round_trips_without_executor_reference() -> None:
    continuation = _post_continuation()
    restored = PostExecutionContinuation.model_validate_json(continuation.model_dump_json())

    assert restored == continuation
    assert isinstance(restored.payload, ToolResultPayload)
    assert restored.payload.result == {"answer": "safe"}
    assert restored.guardrail_cursor is not None
    assert restored.guardrail_cursor.chain_fingerprint == restored.chain_fingerprint
    assert "executor_ref" not in type(restored).model_fields
    with pytest.raises(TypeError):
        cast("Any", restored.payload.result)["answer"] = "changed"


def test_decision_post_continuation_round_trips_with_exact_payload_kind() -> None:
    continuation = _decision_post_continuation()
    restored = PostExecutionContinuation.model_validate_json(continuation.model_dump_json())

    assert restored == continuation
    assert isinstance(restored.payload, DecisionPayload)
    assert restored.stage is GuardrailStage.ON_DECISION


@pytest.mark.parametrize(
    ("stage", "payload"),
    [
        (GuardrailStage.ON_DECISION, ToolResultPayload(result={"answer": "safe"})),
        (
            GuardrailStage.POST_TOOL,
            DecisionPayload.model_validate(
                {
                    "domain": "credit_risk",
                    "decision_id": "decision-001",
                    "outcome": "decline",
                    "body": {},
                }
            ),
        ),
    ],
)
def test_post_execution_continuation_rejects_stage_payload_mismatch(
    stage: GuardrailStage,
    payload: ToolResultPayload | DecisionPayload,
) -> None:
    continuation = _post_continuation(with_cursor=False)

    with pytest.raises(ValidationError, match="require"):
        PostExecutionContinuation.model_validate(
            {
                **continuation.model_dump(),
                "stage": stage,
                "payload": payload,
                "payload_digest": hashlib.sha256(
                    canonical_json_bytes(payload.model_dump(mode="json"))
                ).hexdigest(),
            }
        )


def test_post_execution_continuation_allows_absent_guardrail_cursor() -> None:
    continuation = _post_continuation(with_cursor=False)

    assert continuation.guardrail_cursor is None


def test_post_execution_continuation_rejects_non_result_payload() -> None:
    continuation = _post_continuation(with_cursor=False)

    with pytest.raises(ValidationError):
        PostExecutionContinuation.model_validate(
            {
                **continuation.model_dump(),
                "payload": ToolCallPayload.model_validate({"arguments": {"query": "unsafe"}}),
            }
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("stage", GuardrailStage.PRE_TOOL, "post_tool, post_message, and on_decision"),
        ("payload_digest", "0" * 64, "payload_digest"),
        ("chain_fingerprint", "d" * 64, "cursor chain fingerprint"),
        (
            "execution_completed_at",
            datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC),
            "execution_completed_at",
        ),
    ],
)
def test_post_execution_continuation_rejects_mismatched_bound_state(
    field: str,
    value: object,
    message: str,
) -> None:
    continuation = _post_continuation()

    with pytest.raises(ValidationError, match=message):
        PostExecutionContinuation.model_validate({**continuation.model_dump(), field: value})


def test_post_execution_continuation_rejects_subject_snapshot_and_cursor_mismatch() -> None:
    continuation = _post_continuation()
    wrong_permission = continuation.permission_context.model_copy(update={"resource": "other"})
    wrong_snapshot = continuation.policy_bundle_snapshot.model_copy(
        update={"version": f"sha256:{'d' * 64}"}
    )
    assert continuation.guardrail_cursor is not None
    wrong_cursor = continuation.guardrail_cursor.model_copy(
        update={"stage": GuardrailStage.POST_MESSAGE}
    )

    for update, message in (
        ({"permission_context": wrong_permission}, "permission context"),
        ({"policy_bundle_snapshot": wrong_snapshot}, "policy bundle snapshot"),
        ({"guardrail_cursor": wrong_cursor}, "cursor stage"),
    ):
        with pytest.raises(ValidationError, match=message):
            PostExecutionContinuation.model_validate({**continuation.model_dump(), **update})


def test_protected_continuation_parser_discriminates_pre_and_post() -> None:
    pre: ProtectedContinuation = parse_protected_continuation(_continuation().model_dump_json())
    post: ProtectedContinuation = parse_protected_continuation(
        _post_continuation().model_dump_json().encode()
    )

    assert isinstance(pre, PreExecutionContinuation)
    assert isinstance(post, PostExecutionContinuation)
    with pytest.raises(ValidationError):
        parse_protected_continuation(
            _post_continuation()
            .model_dump_json()
            .replace(
                '"post_execution_continuation"',
                '"pre_execution_continuation"',
                1,
            )
        )


@pytest.mark.parametrize("stage", [GuardrailStage.INPUT, GuardrailStage.POST_TOOL])
def test_pre_execution_continuation_rejects_non_pre_execution_stages(
    stage: GuardrailStage,
) -> None:
    continuation = _continuation()
    with pytest.raises(ValidationError):
        PreExecutionContinuation.model_validate({**continuation.model_dump(), "stage": stage})


def test_pre_execution_continuation_rejects_cursor_or_time_mismatch() -> None:
    continuation = _continuation()
    with pytest.raises(ValidationError, match="cursor stage"):
        PreExecutionContinuation.model_validate(
            {**continuation.model_dump(), "stage": GuardrailStage.PRE_MESSAGE}
        )
    with pytest.raises(ValidationError, match="expires_at"):
        PreExecutionContinuation.model_validate(
            {**continuation.model_dump(), "expires_at": continuation.created_at}
        )


def test_pre_execution_continuation_rejects_policy_snapshot_version_mismatch() -> None:
    continuation = _continuation()
    with pytest.raises(ValidationError, match="policy bundle snapshot"):
        PreExecutionContinuation.model_validate(
            {
                **continuation.model_dump(),
                "policy_bundle_snapshot": {
                    "version": f"sha256:{'c' * 64}",
                    "policy_sets": (),
                },
            }
        )


def test_canonical_aad_binds_exact_schema_kind_and_escalation_id() -> None:
    assert canonical_continuation_aad("esc-1") == _fixture_bytes("v1-pre.aad.json")
    assert canonical_continuation_aad("esc-1") != canonical_continuation_aad("esc-2")
    assert canonical_continuation_aad(
        "esc-post-1", kind="post_execution_continuation"
    ) == _fixture_bytes("v1-post.aad.json")
    assert canonical_continuation_aad("esc-1") != canonical_continuation_aad(
        "esc-1", kind="post_execution_continuation"
    )
    assert canonical_continuation_aad("esc-1", schema_version=2) == (
        b'{"escalation_id":"esc-1","kind":"pre_execution_continuation","schema_version":2}'
    )
    assert canonical_continuation_aad("esc-1", schema_version=2) != (
        canonical_continuation_aad("esc-1")
    )
    assert canonical_continuation_aad("esc-1", schema_version=3) == (
        b'{"escalation_id":"esc-1","kind":"pre_execution_continuation","schema_version":3}'
    )
    with pytest.raises(ValueError):
        canonical_continuation_aad("")
    with pytest.raises(ValueError, match="unsupported continuation kind"):
        canonical_continuation_aad("esc-1", kind="unknown")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="unsupported continuation schema version"):
        canonical_continuation_aad("esc-1", schema_version=4)  # type: ignore[arg-type]


def test_sealed_continuation_is_frozen_and_rejects_unknown_fields() -> None:
    sealed = SealedContinuation(
        algorithm="aes-gcm",
        key_id="key-1",
        nonce=b"nonce",
        ciphertext=b"ciphertext",
    )
    assert sealed.schema_version == 1
    with pytest.raises(ValidationError):
        SealedContinuation(
            algorithm="aes-gcm",
            key_id="key-1",
            nonce=b"nonce",
            ciphertext=b"ciphertext",
            plaintext=b"forbidden",  # type: ignore[call-arg]
        )
