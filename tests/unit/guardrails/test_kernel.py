"""Behavioral contract tests for the unified governance kernel."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.escalation_store import EscalationStatus, EscalationStore
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.circuit_breaker import CircuitBreaker
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import (
    CircuitOpenError,
    EscalationRequiredError,
    PermissionDeniedError,
)
from agentguard.guardrails import (
    DecisionPayload,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    ToolCallPayload,
    ToolResultPayload,
)
from agentguard.guardrails.kernel import GovernanceKernel
from agentguard.guardrails.normalization import canonical_json_bytes
from agentguard.integrations._pipeline import run_governed
from agentguard.models import (
    AuditEvent,
    AuditLink,
    EvidenceRef,
    PermissionContext,
    PolicyResult,
)

if TYPE_CHECKING:
    from pathlib import Path


def _rbac_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="operator",
                permissions=[
                    Permission(
                        action="tool:test",
                        resource="allowed/item",
                        effect="allow",
                    )
                ],
            )
        ]
    )


def _normalized_event(event: AuditEvent) -> dict[str, Any]:
    """Remove only nondeterministic correlation and signing fields."""

    return event.model_dump(
        exclude={
            "event_id",
            "timestamp",
            "duration_ms",
            "event_hash",
            "prev_hash",
            "trace_id",
            "invocation_id",
            "chain_id",
        }
    )


class _StaticPolicyEngine:
    bundle_version = "test-bundle-v1"

    def __init__(self, result: PolicyResult) -> None:
        self._result = result

    async def evaluate_stage(self, _event: AuditEvent, stage: str) -> list[PolicyResult]:
        return [self._result] if stage == "pre_tool" else []


async def _register_operator(registry: AgentRegistry) -> str:
    identity = await registry.register(name="Operator", roles=["operator"])
    return identity.agent_id


class _EscalatingGuardrail:
    id = "manual-approval"
    version = "1"

    def __init__(self, stage: GuardrailStage) -> None:
        self.stages = frozenset({stage})

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("GUARDRAIL.INTERNAL_ERROR",),
        )


class _DecisionGuardrail:
    id = "decision-guardrail"
    version = "1"
    stages = frozenset({GuardrailStage.ON_DECISION})

    def __init__(self, outcome: GuardrailOutcome) -> None:
        self.outcome = outcome
        self.contexts: list[GuardrailContext] = []

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        self.contexts.append(context)
        return self.outcome


class _BlockingDecisionGuardrail:
    id = "blocking-decision-guardrail"
    version = "1"
    stages = frozenset({GuardrailStage.ON_DECISION})

    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


def _decision(*, outcome: str = "decline") -> DecisionPayload:
    return DecisionPayload.model_validate(
        {
            "domain": "credit_risk",
            "decision_id": "decision-001",
            "outcome": outcome,
            "body": {"score": 620},
        }
    )


@pytest.mark.parametrize("effect", [GuardrailEffect.ALLOW, GuardrailEffect.WARN])
async def test_decision_result_uses_on_decision_and_preserves_typed_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    effect: GuardrailEffect,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-decision-preserve-padded-")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    decision = _decision()
    guardrail = _DecisionGuardrail(GuardrailOutcome(effect=effect))
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit,
        policy_engine=None,
        guardrails=(guardrail,),
    )

    delivered = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/item",
        executor=lambda _payload: asyncio.sleep(0, result=decision),
    )

    assert delivered is decision
    assert len(guardrail.contexts) == 1
    assert guardrail.contexts[0].stage is GuardrailStage.ON_DECISION
    assert guardrail.contexts[0].payload == decision
    snapshot = await audit.read_verified(require_checkpoint=True)
    assert snapshot.verification.attestable
    delivery = next(event for event in snapshot.events if event.event_type == "delivery_completed")
    assert delivery.guardrail_evaluations[0].stage == "on_decision"
    assert delivery.guardrail_evaluations[0].enforced


async def test_decision_delivery_signs_links_and_only_explicit_redacted_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-decision-evidence-links-p")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    decision = _decision()
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit,
        policy_engine=None,
        guardrails=(),
    )
    subject_ref = EvidenceRef(namespace="credit-application", value="application-001")
    links = (
        AuditLink(
            relation="decision",
            target=EvidenceRef(namespace="credit-decision", value="decision-001"),
        ),
    )

    delivered = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/item",
        executor=lambda _payload: asyncio.sleep(0, result=decision),
        subject_ref=subject_ref,
        links=links,
        redacted_evidence={"decision_id": "decision-001", "outcome": "decline"},
    )

    assert delivered is decision
    delivery = next(
        event
        for event in (await audit.read_verified(require_checkpoint=True)).events
        if event.event_type == "delivery_completed"
    )
    assert delivery.subject_ref == subject_ref
    assert delivery.links == links
    assert (
        delivery.payload_digest
        == hashlib.sha256(canonical_json_bytes(decision.model_dump(mode="json"))).hexdigest()
    )
    assert delivery.payload_redacted == {
        "value": {"decision_id": "decision-001", "outcome": "decline"}
    }
    assert "score" not in delivery.model_dump_json()


async def test_decision_transform_fails_closed_without_delivering_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-decision-transform-padded")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    replacement = _decision(outcome="refer")
    guardrail = _DecisionGuardrail(
        GuardrailOutcome(
            effect=GuardrailEffect.TRANSFORM,
            replacement_payload=replacement,
        )
    )
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit,
        policy_engine=None,
        guardrails=(guardrail,),
    )

    with pytest.raises(PermissionDeniedError):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result=_decision()),
        )

    events = (await audit.read_verified(require_checkpoint=True)).events
    assert events[-1].event_type == "delivery_denied"
    assert events[-1].reason_codes == ("GUARDRAIL.INTERNAL_ERROR",)
    evaluation = events[-1].guardrail_evaluations[0]
    assert evaluation.stage == "on_decision"
    assert evaluation.effect == "deny"


@pytest.mark.parametrize(
    "outcome",
    [
        GuardrailOutcome(
            effect=GuardrailEffect.DENY,
            reason_codes=("TEST.DECISION_DENIED",),
        ),
        GuardrailOutcome(
            effect=GuardrailEffect.TRANSFORM,
            replacement_payload=ToolResultPayload(result={"invalid": True}),
        ),
    ],
)
async def test_decision_deny_and_type_mismatch_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: GuardrailOutcome,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-decision-deny-padded-abcd")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        policy_engine=None,
        guardrails=(_DecisionGuardrail(outcome),),
    )

    with pytest.raises(PermissionDeniedError):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result=_decision()),
        )


async def test_unvalidated_decision_evidence_is_digest_only_on_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-unvalidated-evidence-denial")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit_dir = tmp_path / "audit"
    audit = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit,
        policy_engine=None,
        guardrails=(
            _DecisionGuardrail(
                GuardrailOutcome(
                    effect=GuardrailEffect.DENY,
                    reason_codes=("TEST.DECISION_DENIED",),
                )
            ),
        ),
    )

    with pytest.raises(PermissionDeniedError):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result=_decision()),
            redacted_evidence={"name": "Ada Lovelace", "address": "1 Secret Lane"},
        )

    events = (await audit.read_verified(require_checkpoint=True)).events
    denial = next(event for event in events if event.event_type == "delivery_denied")
    assert denial.payload_redacted == {"value": {}}
    serialized = "".join(path.read_text() for path in audit_dir.rglob("*.jsonl"))
    assert "Ada Lovelace" not in serialized
    assert "1 Secret Lane" not in serialized


async def test_unvalidated_decision_evidence_is_digest_only_on_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-unvalidated-evidence-cancel")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit_dir = tmp_path / "audit"
    audit = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    guardrail = _BlockingDecisionGuardrail()
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit,
        policy_engine=None,
        guardrails=(guardrail,),
    )

    call = asyncio.create_task(
        kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result=_decision()),
            redacted_evidence={"name": "Ada Lovelace", "address": "1 Secret Lane"},
        )
    )
    await asyncio.wait_for(guardrail.started.wait(), timeout=1)
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call

    events = (await audit.read_verified(require_checkpoint=True)).events
    cancelled = next(
        event
        for event in events
        if event.event_type == "delivery_denied" and event.reason_codes == ("DELIVERY.CANCELLED",)
    )
    assert cancelled.payload_redacted == {"value": {}}
    serialized = "".join(path.read_text() for path in audit_dir.rglob("*.jsonl"))
    assert "Ada Lovelace" not in serialized
    assert "1 Secret Lane" not in serialized


async def test_direct_allowed_call_preserves_typed_artifacts_in_signed_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-typed-artifacts-padded-ab")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    policy_result = PolicyResult(
        rule_id="TEST-ALLOW-001",
        rule_name="Expected test operation",
        passed=True,
        severity="low",
        evidence={"source": "kernel-contract"},
        remediation="none",
        effect="warn",
    )
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit_log,
        policy_engine=_StaticPolicyEngine(policy_result),  # type: ignore[arg-type]
        guardrails=(),
    )

    result = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/item",
        payload=ToolCallPayload.model_validate({"arguments": {"value": 1}}),
        executor=lambda _payload: asyncio.sleep(0, result="ok"),
    )

    assert result == "ok"
    snapshot = await audit_log.read_verified(require_checkpoint=True)
    assert snapshot.verification.valid
    assert snapshot.verification.attestable
    assert all(event.event_hash for event in snapshot.events)
    assert all(isinstance(event.permission_context, PermissionContext) for event in snapshot.events)
    assert all(
        isinstance(result, PolicyResult)
        for event in snapshot.events
        for result in event.policy_results
    )
    assert any(policy_result in event.policy_results for event in snapshot.events)


async def test_direct_denial_carries_subject_and_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-denial-evidence-links-pad")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit,
        policy_engine=None,
        guardrails=(),
    )
    subject_ref = EvidenceRef(namespace="credit-application", value="application-denied")
    links = (
        AuditLink(
            relation="decision",
            target=EvidenceRef(namespace="credit-decision", value="decision-denied"),
        ),
    )

    with pytest.raises(PermissionDeniedError):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="denied/item",
            executor=lambda _payload: asyncio.sleep(0, result="unreachable"),
            subject_ref=subject_ref,
            links=links,
        )

    denial = (await audit.read_verified(require_checkpoint=True)).events[-1]
    assert denial.result == "denied"
    assert denial.subject_ref == subject_ref
    assert denial.links == links


async def test_evidence_inputs_fail_closed_before_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-invalid-evidence-padded-a")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit,
        policy_engine=None,
        guardrails=(),
    )
    calls = 0

    async def executor(_payload: object) -> str:
        nonlocal calls
        calls += 1
        return "unreachable"

    duplicate = AuditLink(
        relation="decision",
        target=EvidenceRef(namespace="credit-decision", value="decision-001"),
    )
    with pytest.raises(ValueError, match="must be unique"):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=executor,
            links=(duplicate, duplicate),
        )
    with pytest.raises(TypeError):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=executor,
            redacted_evidence={"unsafe-set"},
        )

    assert calls == 0
    assert not (await audit.read_verified()).events


async def test_kernel_and_legacy_shim_emit_equivalent_lifecycle_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-lifecycle-equivalence-pad")
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    rbac = _rbac_engine()
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    policy = PolicyEngine(policy_dirs=[policy_dir])
    kernel_dir = tmp_path / "kernel"
    legacy_dir = tmp_path / "legacy"
    kernel_dir.mkdir()
    legacy_dir.mkdir()
    kernel_audit = AppendOnlyAuditLog(FileAuditBackend(kernel_dir))
    legacy_audit = AppendOnlyAuditLog(FileAuditBackend(legacy_dir))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=rbac,
        audit_log=kernel_audit,
        policy_engine=policy,
        guardrails=(),
    )
    payload = ToolCallPayload.model_validate({"arguments": {"value": 1}})

    kernel_result = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/item",
        payload=payload,
        executor=lambda _payload: asyncio.sleep(0, result={"status": "ok"}),
    )
    legacy_result = await run_governed(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/item",
        registry=registry,
        rbac_engine=rbac,
        audit_log=legacy_audit,
        policy_engine=policy,
        guardrails=(),
        payload=payload,
        executor=lambda _payload: asyncio.sleep(0, result={"status": "ok"}),
    )

    assert kernel_result == legacy_result == {"status": "ok"}
    kernel_events = (await kernel_audit.read_verified()).events
    legacy_events = (await legacy_audit.read_verified()).events
    expected_lifecycle = [
        ("admission", "allowed", ()),
        ("execution_completed", "allowed", ()),
        ("delivery_completed", "allowed", ()),
    ]
    assert [
        (event.event_type, event.result, event.reason_codes) for event in kernel_events
    ] == expected_lifecycle
    assert all(event.permission_context.granted for event in kernel_events)
    assert all(event.action == "tool:test" for event in kernel_events)
    assert all(event.resource == "allowed/item" for event in kernel_events)
    assert [_normalized_event(event) for event in kernel_events] == [
        _normalized_event(event) for event in legacy_events
    ]


async def test_policy_reload_is_pinned_per_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-policy-reload-pinning-pad")
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    policy_file = policy_dir / "runtime.yaml"

    def policy_document(pattern: str) -> str:
        return f"""\
schema_version: 2
name: Runtime
version: "1"
rules:
  - id: RELOAD-POST-01
    name: Block selected output
    severity: high
    description: Reload pinning test
    stage: post_tool
    applies_to: all
    on_fail: deny
    check:
      type: content_scan
      targets: [tool_result]
      patterns: ["{pattern}"]
    remediation: Return an approved result.
"""

    policy_file.write_text(policy_document("never-match"))
    engine = PolicyEngine(policy_dirs=[policy_dir])
    old_version = engine.bundle_version
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit_log,
        policy_engine=engine,
        guardrails=(),
    )
    executor_started = asyncio.Event()
    release_executor = asyncio.Event()

    async def delayed_executor(_payload: object) -> str:
        executor_started.set()
        await release_executor.wait()
        return "blocked-output"

    first = asyncio.create_task(
        kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=delayed_executor,
        )
    )
    await asyncio.wait_for(executor_started.wait(), timeout=1)
    policy_file.write_text(policy_document("blocked-output"))
    reload_result = await engine.reload()
    new_version = engine.bundle_version
    release_executor.set()

    assert await first == "blocked-output"
    assert reload_result.changed is True
    assert new_version != old_version

    with pytest.raises(PermissionDeniedError):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="blocked-output"),
        )

    events = await FileAuditBackend(audit_dir).read_all()
    invocations: dict[str, list[AuditEvent]] = {}
    for event in events:
        invocations.setdefault(event.invocation_id, []).append(event)
    assert len(invocations) == 2
    completed = next(
        invocation_events
        for invocation_events in invocations.values()
        if invocation_events[-1].event_type == "delivery_completed"
    )
    denied = next(
        invocation_events
        for invocation_events in invocations.values()
        if invocation_events[-1].event_type == "delivery_denied"
    )
    assert {event.policy_bundle_version for event in completed} == {old_version}
    assert {event.policy_bundle_version for event in denied} == {new_version}


async def test_half_open_concurrency_admits_one_executor_after_admission_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-half-open-padded-abcdefgh")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    breaker = CircuitBreaker(
        name="kernel-half-open",
        failure_threshold=1,
        recovery_timeout=0,
    )

    async def _open_breaker() -> None:
        raise RuntimeError("open breaker")

    with pytest.raises(RuntimeError, match="open breaker"):
        await breaker.call(_open_breaker)

    empty_policy_dir = tmp_path / "empty-policies"
    empty_policy_dir.mkdir()
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit_log,
        policy_engine=PolicyEngine(policy_dirs=[empty_policy_dir]),
        guardrails=(),
        circuit_breaker=breaker,
    )
    executor_started = asyncio.Event()
    release_executor = asyncio.Event()
    executor_calls = 0
    admission_observed: list[bool] = []

    async def _execute(_payload: object) -> str:
        nonlocal executor_calls
        executor_calls += 1
        events = await FileAuditBackend(audit_dir).read_all()
        admissions = [event for event in events if event.event_type == "admission"]
        admitted_invocation = admissions[0].invocation_id if admissions else None
        admission_observed.append(
            len(admissions) == 1
            and not any(
                event.invocation_id == admitted_invocation and event.event_type != "admission"
                for event in events
            )
        )
        executor_started.set()
        await release_executor.wait()
        return "ok"

    async def _invoke() -> str:
        result = await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=_execute,
        )
        assert isinstance(result, str)
        return result

    first = asyncio.create_task(_invoke())
    second = asyncio.create_task(_invoke())
    await asyncio.wait_for(executor_started.wait(), timeout=1)
    await asyncio.sleep(0)
    release_executor.set()
    outcomes = await asyncio.gather(first, second, return_exceptions=True)

    assert executor_calls == 1
    assert admission_observed == [True]
    assert outcomes.count("ok") == 1
    assert sum(isinstance(outcome, CircuitOpenError) for outcome in outcomes) == 1
    events = await FileAuditBackend(audit_dir).read_all()
    assert sum(event.event_type == "admission" for event in events) == 1


async def test_kernel_propagates_guardrail_cancellation_without_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-guardrail-cancellation-pa")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    evaluation_started = asyncio.Event()
    executor_called = False

    class BlockingGuardrail:
        id = "blocking"
        version = "1"
        stages = frozenset({GuardrailStage.INPUT})

        async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
            evaluation_started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    async def executor(_payload: object) -> str:
        nonlocal executor_called
        executor_called = True
        return "unreachable"

    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
        policy_engine=None,
        guardrails=(BlockingGuardrail(),),
    )
    call = asyncio.create_task(
        kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=executor,
        )
    )
    await asyncio.wait_for(evaluation_started.wait(), timeout=1)
    call.cancel()

    with pytest.raises(asyncio.CancelledError):
        await call

    assert not executor_called
    assert await FileAuditBackend(audit_dir).read_all() == []


async def test_post_guardrail_cancellation_commits_delivery_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-guardrail-cancellation")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    evaluation_started = asyncio.Event()

    class BlockingPostGuardrail:
        id = "blocking-post"
        version = "1"
        stages = frozenset({GuardrailStage.POST_TOOL})

        async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
            evaluation_started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
        policy_engine=None,
        guardrails=(BlockingPostGuardrail(),),
    )
    call = asyncio.create_task(
        kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="executed"),
        )
    )
    await asyncio.wait_for(evaluation_started.wait(), timeout=1)
    call.cancel()

    with pytest.raises(asyncio.CancelledError):
        await call

    events = await FileAuditBackend(audit_dir).read_all()
    assert [(event.event_type, event.result) for event in events] == [
        ("admission", "allowed"),
        ("execution_completed", "allowed"),
        ("delivery_denied", "denied"),
    ]
    assert events[-1].reason_codes == ("DELIVERY.CANCELLED",)


async def test_post_policy_cancellation_commits_delivery_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-policy-cancellation-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    evaluation_started = asyncio.Event()

    class BlockingPostPolicy:
        bundle_version = "blocking-policy-v1"

        async def evaluate_stage(self, _event: AuditEvent, stage: str) -> list[PolicyResult]:
            if stage != "post_tool":
                return []
            evaluation_started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
        policy_engine=BlockingPostPolicy(),  # type: ignore[arg-type]
        guardrails=(),
    )
    call = asyncio.create_task(
        kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="executed"),
        )
    )
    await asyncio.wait_for(evaluation_started.wait(), timeout=1)
    call.cancel()

    with pytest.raises(asyncio.CancelledError):
        await call

    events = await FileAuditBackend(audit_dir).read_all()
    assert [(event.event_type, event.result) for event in events] == [
        ("admission", "allowed"),
        ("execution_completed", "allowed"),
        ("delivery_denied", "denied"),
    ]
    assert events[-1].reason_codes == ("DELIVERY.CANCELLED",)


async def test_repeated_cancellation_waits_for_delivery_terminal_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-repeated-cancellation-pad")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    evaluation_started = asyncio.Event()
    delivery_write_started = asyncio.Event()
    release_delivery_write = asyncio.Event()
    inner_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))

    class DelayedDeliveryAudit:
        async def write(self, event: AuditEvent) -> AuditEvent:
            if event.event_type == "delivery_denied":
                delivery_write_started.set()
                await release_delivery_write.wait()
            return await inner_log.write(event)

        async def write_once(self, event: AuditEvent) -> AuditEvent:
            if event.event_type == "delivery_denied":
                delivery_write_started.set()
                await release_delivery_write.wait()
            return await inner_log.write_once(event)

    class BlockingPostGuardrail:
        id = "blocking-post"
        version = "1"
        stages = frozenset({GuardrailStage.POST_TOOL})

        async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
            evaluation_started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=DelayedDeliveryAudit(),  # type: ignore[arg-type]
        policy_engine=None,
        guardrails=(BlockingPostGuardrail(),),
    )
    call = asyncio.create_task(
        kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="executed"),
        )
    )
    await asyncio.wait_for(evaluation_started.wait(), timeout=1)
    call.cancel()
    await asyncio.wait_for(delivery_write_started.wait(), timeout=1)
    call.cancel()
    await asyncio.sleep(0)

    assert not call.done()
    assert [event.event_type for event in await FileAuditBackend(audit_dir).read_all()] == [
        "admission",
        "execution_completed",
    ]

    release_delivery_write.set()
    with pytest.raises(asyncio.CancelledError):
        await call

    assert [event.event_type for event in await FileAuditBackend(audit_dir).read_all()] == [
        "admission",
        "execution_completed",
        "delivery_denied",
    ]


async def test_durable_escalation_persists_before_exposing_approval_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-durable-hitl-padded-abcde")
    now = datetime(2026, 8, 26, 12, tzinfo=UTC)
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    store_dir = tmp_path / "escalations"
    store = EscalationStore(store_dir, signing_key=b"h" * 32, clock=lambda: now)
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit_log,
        policy_engine=None,
        guardrails=(_EscalatingGuardrail(GuardrailStage.PRE_TOOL),),
        escalation_store=store,
        escalation_ttl=timedelta(minutes=10),
    )
    subject_ref = EvidenceRef(namespace="credit-application", value="application-escalated")
    links = (
        AuditLink(
            relation="decision",
            target=EvidenceRef(namespace="credit-decision", value="decision-escalated"),
        ),
    )

    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="unreachable"),
            subject_ref=subject_ref,
            links=links,
        )

    error = caught.value
    assert error.escalation_id
    assert len(error.approval_token) == 43
    assert error.expires_at == now + timedelta(minutes=10)
    record = await store.get(error.escalation_id)
    assert record.status is EscalationStatus.PENDING

    events = (await audit_log.read_verified(require_checkpoint=True)).events
    assert len(events) == 1
    event = events[0]
    assert event.event_id == f"hitl:{error.escalation_id}:requested"
    assert event.event_type == "escalation_requested"
    assert event.hash_schema_version == 8
    assert event.hitl_evidence is not None
    assert event.hitl_evidence.escalation_id == error.escalation_id
    assert event.hitl_evidence.expires_at == error.expires_at
    assert event.subject_ref == subject_ref
    assert event.links == links
    assert all(
        error.approval_token not in path.read_text() for path in audit_dir.glob("audit-*.jsonl")
    )
    assert error.approval_token not in next(store_dir.glob("*.json")).read_text()


async def test_failed_escalation_audit_never_exposes_unbacked_token(tmp_path: Path) -> None:
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    store = EscalationStore(tmp_path / "escalations", signing_key=b"h" * 32)

    class FailingAudit:
        async def write(self, _event: AuditEvent) -> AuditEvent:
            raise RuntimeError("audit unavailable")

        async def write_once(self, _event: AuditEvent) -> AuditEvent:
            raise RuntimeError("audit unavailable")

    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=FailingAudit(),  # type: ignore[arg-type]
        policy_engine=None,
        guardrails=(_EscalatingGuardrail(GuardrailStage.PRE_TOOL),),
        escalation_store=store,
    )

    with pytest.raises(RuntimeError, match="audit unavailable"):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="unreachable"),
        )

    records = await store.list_records()
    assert len(records) == 1
    assert records[0].status is EscalationStatus.PENDING


async def test_durable_post_tool_escalation_is_nonterminal_and_never_reexecutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-hitl-padded-abcdefgh")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    store = EscalationStore(tmp_path / "escalations", signing_key=b"h" * 32)
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit_log,
        policy_engine=None,
        guardrails=(_EscalatingGuardrail(GuardrailStage.POST_TOOL),),
        escalation_store=store,
    )
    executor_calls = 0

    async def executor(_payload: object) -> str:
        nonlocal executor_calls
        executor_calls += 1
        return "executed"

    with pytest.raises(EscalationRequiredError):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=executor,
        )

    assert executor_calls == 1
    events = (await audit_log.read_verified(require_checkpoint=True)).events
    assert [event.event_type for event in events] == [
        "admission",
        "execution_completed",
        "escalation_requested",
    ]
    assert not any(event.event_type == "delivery_escalated" for event in events)


async def test_cancellation_during_post_escalation_store_create_commits_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-hitl-create-cancel-p")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    store = EscalationStore(tmp_path / "escalations", signing_key=b"h" * 32)
    create_started = asyncio.Event()
    release_create = asyncio.Event()
    original_create = store._create_sync

    loop = asyncio.get_running_loop()

    def thread_create(escalation_id: str, ttl: timedelta) -> object:
        create_started.set()
        asyncio.run_coroutine_threadsafe(release_create.wait(), loop).result(timeout=2)
        return original_create(escalation_id, ttl)

    monkeypatch.setattr(store, "_create_sync", thread_create)
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit_log,
        policy_engine=None,
        guardrails=(_EscalatingGuardrail(GuardrailStage.POST_TOOL),),
        escalation_store=store,
    )
    call = asyncio.create_task(
        kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="executed"),
        )
    )
    await asyncio.wait_for(create_started.wait(), timeout=1)
    call.cancel()
    release_create.set()

    with pytest.raises(asyncio.CancelledError):
        await call

    events = (await audit_log.read_verified(require_checkpoint=True)).events
    assert [event.event_type for event in events] == [
        "admission",
        "execution_completed",
        "escalation_requested",
        "delivery_denied",
    ]
    assert events[-1].reason_codes == ("DELIVERY.CANCELLED",)
    assert len(await store.list_records()) == 1


async def test_cancellation_during_post_escalation_audit_commits_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-hitl-audit-cancel-pa")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    inner_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    request_started = asyncio.Event()
    release_request = asyncio.Event()

    class BlockingRequestAudit:
        async def write(self, event: AuditEvent) -> AuditEvent:
            if event.event_type == "escalation_requested":
                request_started.set()
                await release_request.wait()
            return await inner_log.write(event)

        async def write_once(self, event: AuditEvent) -> AuditEvent:
            if event.event_type == "escalation_requested":
                request_started.set()
                await release_request.wait()
            return await inner_log.write_once(event)

    store = EscalationStore(tmp_path / "escalations", signing_key=b"h" * 32)
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=BlockingRequestAudit(),  # type: ignore[arg-type]
        policy_engine=None,
        guardrails=(_EscalatingGuardrail(GuardrailStage.POST_TOOL),),
        escalation_store=store,
    )
    call = asyncio.create_task(
        kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="executed"),
        )
    )
    await asyncio.wait_for(request_started.wait(), timeout=1)
    call.cancel()
    release_request.set()

    with pytest.raises(asyncio.CancelledError):
        await call

    events = (await inner_log.read_verified(require_checkpoint=True)).events
    assert [event.event_type for event in events] == [
        "admission",
        "execution_completed",
        "escalation_requested",
        "delivery_denied",
    ]
    assert events[-1].reason_codes == ("DELIVERY.CANCELLED",)


async def test_post_escalation_store_failure_commits_delivery_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-hitl-store-failure-p")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _register_operator(registry)
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    store = EscalationStore(tmp_path / "escalations", signing_key=b"h" * 32)

    async def fail_create(_escalation_id: str, *, ttl: timedelta) -> object:
        del ttl
        raise OSError("disk full")

    monkeypatch.setattr(store, "create", fail_create)
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac_engine(),
        audit_log=audit_log,
        policy_engine=None,
        guardrails=(_EscalatingGuardrail(GuardrailStage.POST_TOOL),),
        escalation_store=store,
    )

    with pytest.raises(OSError, match="disk full"):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="executed"),
        )

    events = (await audit_log.read_verified(require_checkpoint=True)).events
    assert [event.event_type for event in events] == [
        "admission",
        "execution_completed",
        "delivery_denied",
    ]
    assert events[-1].reason_codes == ("GUARDRAIL.INTERNAL_ERROR",)
