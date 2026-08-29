"""Behavioral contract for kernel-level shadow guardrail execution."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from agentguard.compliance.engine import PolicyEngine
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.guardrails import (
    ChainMode,
    DecisionPayload,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    ToolCallPayload,
    ToolResultPayload,
)
from agentguard.guardrails.kernel import GovernanceKernel
from agentguard.integrations._pipeline import run_governed
from agentguard.models import AuditEvent, PolicyResult

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path


class _Guardrail:
    version = "1"
    timeout_ms = 10

    def __init__(
        self,
        guardrail_id: str,
        stages: frozenset[GuardrailStage],
        evaluator: Callable[[GuardrailContext], Awaitable[GuardrailOutcome]],
    ) -> None:
        self.id = guardrail_id
        self.stages = stages
        self._evaluator = evaluator
        self.contexts: list[GuardrailContext] = []

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        self.contexts.append(context)
        return await self._evaluator(context)


class _DenyPolicyEngine:
    bundle_version = "shadow-policy-test"

    async def evaluate_stage(self, _event: AuditEvent, stage: str) -> list[PolicyResult]:
        if stage != "pre_tool":
            return []
        return [
            PolicyResult(
                rule_id="TEST-POLICY-DENY",
                rule_name="Policy enforcement remains active",
                passed=False,
                severity="high",
                evidence={"source": "test"},
                remediation="Do not execute",
                effect="deny",
            )
        ]


async def _outcome(
    effect: GuardrailEffect,
    *,
    reason_codes: tuple[str, ...] = (),
    replacement_payload: ToolCallPayload | ToolResultPayload | DecisionPayload | None = None,
) -> GuardrailOutcome:
    return GuardrailOutcome(
        effect=effect,
        reason_codes=reason_codes,
        replacement_payload=replacement_payload,
    )


async def test_shadow_decision_transform_is_rejected_but_preserves_original_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = DecisionPayload.model_validate(
        {
            "domain": "credit_risk",
            "decision_id": "decision-001",
            "outcome": "decline",
            "body": {"score": 620},
        }
    )
    replacement = original.model_copy(update={"outcome": "refer"})
    guardrail = _Guardrail(
        "shadow-decision-transform",
        frozenset({GuardrailStage.ON_DECISION}),
        lambda _context: _outcome(
            GuardrailEffect.TRANSFORM,
            replacement_payload=replacement,
        ),
    )
    kernel, audit, agent_id = await _setup(tmp_path, monkeypatch, (guardrail,))

    delivered = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/original",
        executor=lambda _payload: asyncio.sleep(0, result=original),
    )

    assert delivered is original
    assert guardrail.contexts[0].stage is GuardrailStage.ON_DECISION
    assert guardrail.contexts[0].payload == original
    delivery = next(
        event
        for event in (await audit.read_verified(require_checkpoint=True)).events
        if event.event_type == "delivery_completed"
    )
    evaluation = delivery.guardrail_evaluations[0]
    assert not evaluation.enforced
    assert evaluation.effect == "deny"
    assert evaluation.reason_codes == ("GUARDRAIL.INTERNAL_ERROR",)


def _rbac() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="operator",
                permissions=[
                    Permission(
                        action="tool:test",
                        resource="allowed/original",
                        effect="allow",
                    )
                ],
            )
        ]
    )


async def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    guardrails: tuple[_Guardrail, ...],
) -> tuple[GovernanceKernel, AppendOnlyAuditLog, str]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "shadow-kernel-tests-padded-abcde")
    audit_dir = tmp_path / "audit"
    policy_dir = tmp_path / "policies"
    audit_dir.mkdir()
    policy_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    audit = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac(),
        audit_log=audit,
        policy_engine=PolicyEngine(policy_dirs=[policy_dir]),
        guardrails=guardrails,
        chain_mode=ChainMode.SHADOW,
    )
    return kernel, audit, identity.agent_id


@pytest.mark.parametrize(
    "effect",
    [GuardrailEffect.TRANSFORM, GuardrailEffect.DENY, GuardrailEffect.ESCALATE],
)
async def test_shadow_input_decisions_preserve_original_resolver_and_executor_payload(
    effect: GuardrailEffect,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replacement = ToolCallPayload(arguments={"resource": "changed"})
    decision = _Guardrail(
        "input-decision",
        frozenset({GuardrailStage.INPUT}),
        lambda _context: _outcome(
            effect,
            reason_codes=("TEST.WOULD_BLOCK",)
            if effect in {GuardrailEffect.DENY, GuardrailEffect.ESCALATE}
            else (),
            replacement_payload=replacement if effect is GuardrailEffect.TRANSFORM else None,
        ),
    )
    continued = _Guardrail(
        "continued",
        frozenset({GuardrailStage.INPUT}),
        lambda _context: _outcome(GuardrailEffect.ALLOW),
    )
    kernel, _, agent_id = await _setup(tmp_path, monkeypatch, (decision, continued))
    resolver_inputs: list[object] = []
    executor_inputs: list[ToolCallPayload] = []

    def resolve(native: object) -> str:
        resolver_inputs.append(native)
        return "allowed/original"

    async def execute(payload: object) -> str:
        assert isinstance(payload, ToolCallPayload)
        executor_inputs.append(payload)
        return "executed"

    result = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource=resolve,
        payload=ToolCallPayload(arguments={"resource": "original"}),
        executor=execute,
    )

    assert result == "executed"
    assert resolver_inputs == [{"resource": "original"}]
    assert executor_inputs == [ToolCallPayload(arguments={"resource": "original"})]
    assert len(continued.contexts) == 1


@pytest.mark.parametrize("failure", ["timeout", "internal_error"])
async def test_shadow_input_failures_do_not_block_and_continue_chain(
    failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(_context: GuardrailContext) -> GuardrailOutcome:
        if failure == "internal_error":
            raise RuntimeError("guardrail failed")
        await asyncio.sleep(1)
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)

    failing = _Guardrail("failing", frozenset({GuardrailStage.INPUT}), fail)
    continued = _Guardrail(
        "continued",
        frozenset({GuardrailStage.INPUT}),
        lambda _context: _outcome(GuardrailEffect.ALLOW),
    )
    kernel, _, agent_id = await _setup(tmp_path, monkeypatch, (failing, continued))

    result = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/original",
        payload=ToolCallPayload(arguments={"value": "original"}),
        executor=lambda _payload: asyncio.sleep(0, result="executed"),
    )

    assert result == "executed"
    assert len(continued.contexts) == 1


@pytest.mark.parametrize(
    "effect",
    [GuardrailEffect.TRANSFORM, GuardrailEffect.DENY, GuardrailEffect.ESCALATE],
)
async def test_shadow_post_decisions_preserve_original_return_value(
    effect: GuardrailEffect,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = _Guardrail(
        "post-decision",
        frozenset({GuardrailStage.POST_TOOL}),
        lambda _context: _outcome(
            effect,
            reason_codes=("TEST.WOULD_BLOCK",)
            if effect in {GuardrailEffect.DENY, GuardrailEffect.ESCALATE}
            else (),
            replacement_payload=ToolResultPayload(result={"value": "changed"})
            if effect is GuardrailEffect.TRANSFORM
            else None,
        ),
    )
    continued = _Guardrail(
        "continued",
        frozenset({GuardrailStage.POST_TOOL}),
        lambda _context: _outcome(GuardrailEffect.ALLOW),
    )
    kernel, _, agent_id = await _setup(tmp_path, monkeypatch, (decision, continued))
    original = {"value": "original"}

    result = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/original",
        payload=ToolCallPayload(arguments={"value": 1}),
        executor=lambda _payload: asyncio.sleep(0, result=original),
    )

    assert result is original
    assert len(continued.contexts) == 1


async def test_shadow_lifecycle_persists_stage_scoped_unenforced_evaluations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardrails = tuple(
        _Guardrail(
            f"{stage.value}-guardrail",
            frozenset({stage}),
            lambda _context: _outcome(
                GuardrailEffect.DENY,
                reason_codes=("TEST.WOULD_DENY",),
            ),
        )
        for stage in (
            GuardrailStage.INPUT,
            GuardrailStage.PRE_TOOL,
            GuardrailStage.POST_TOOL,
        )
    )
    kernel, audit, agent_id = await _setup(tmp_path, monkeypatch, guardrails)

    result = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/original",
        payload=ToolCallPayload(arguments={"value": 1}),
        executor=lambda _payload: asyncio.sleep(0, result={"ok": True}),
    )

    assert result == {"ok": True}
    snapshot = await audit.read_verified(require_checkpoint=True)
    assert snapshot.verification.valid
    assert snapshot.verification.attestable
    events = snapshot.events
    assert [event.event_type for event in events] == [
        "admission",
        "execution_completed",
        "delivery_completed",
    ]
    assert all(event.chain_mode == "shadow" for event in events)
    assert all("TEST.WOULD_DENY" not in event.reason_codes for event in events)

    admission_evaluations = events[0].model_dump()["guardrail_evaluations"]
    execution_evaluations = events[1].model_dump()["guardrail_evaluations"]
    delivery_evaluations = events[2].model_dump()["guardrail_evaluations"]
    assert [item["stage"] for item in admission_evaluations] == ["input", "pre_tool"]
    assert execution_evaluations == ()
    assert [item["stage"] for item in delivery_evaluations] == ["post_tool"]
    assert all(not item["enforced"] for item in admission_evaluations)
    assert all(not item["enforced"] for item in delivery_evaluations)
    assert [item["guardrail_id"] for item in admission_evaluations] == [
        "input-guardrail",
        "pre_tool-guardrail",
    ]


async def test_legacy_run_governed_propagates_shadow_chain_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "shadow-run-governed-padded-abcde")
    audit_dir = tmp_path / "audit"
    policy_dir = tmp_path / "policies"
    audit_dir.mkdir()
    policy_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    guardrail = _Guardrail(
        "would-deny",
        frozenset({GuardrailStage.PRE_TOOL}),
        lambda _context: _outcome(GuardrailEffect.DENY, reason_codes=("TEST.WOULD_DENY",)),
    )

    result = await run_governed(
        agent_id=identity.agent_id,
        action="tool:test",
        resource="allowed/original",
        registry=registry,
        rbac_engine=_rbac(),
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
        policy_engine=PolicyEngine(policy_dirs=[policy_dir]),
        guardrails=(guardrail,),
        chain_mode=ChainMode.SHADOW,
        payload=ToolCallPayload(arguments={"value": 1}),
        executor=lambda _payload: asyncio.sleep(0, result="executed"),
    )

    assert result == "executed"


async def test_shadow_chain_mode_does_not_disable_policy_enforcement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "shadow-policy-enforcement-padded")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac(),
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
        policy_engine=_DenyPolicyEngine(),  # type: ignore[arg-type]
        guardrails=(),
        chain_mode=ChainMode.SHADOW,
    )
    executor_called = False

    async def execute(_payload: object) -> str:
        nonlocal executor_called
        executor_called = True
        return "executed"

    with pytest.raises(PermissionDeniedError, match="TEST-POLICY-DENY"):
        await kernel.guarded_tool_call(
            agent_id=identity.agent_id,
            action="tool:test",
            resource="allowed/original",
            payload=ToolCallPayload(arguments={"value": 1}),
            executor=execute,
        )

    assert not executor_called
