"""Shadow-mode propagation contract for first-party framework adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, Mock

import pytest

from agentguard.compliance.engine import PolicyEngine
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.guardrails import (
    ChainMode,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
)
from agentguard.guardrails.kernel import GovernanceKernel
from agentguard.integrations.a2a_middleware import GovernedA2AClient
from agentguard.integrations.crewai import GovernedCrewAITool
from agentguard.integrations.google_adk import GovernedAdkTool
from agentguard.integrations.langgraph import GovernedLangGraphToolNode
from agentguard.integrations.mcp_middleware import GovernedMcpClient

if TYPE_CHECKING:
    from pathlib import Path


class _WouldDeny:
    id = "would-deny"
    version = "1"
    stages = frozenset(
        {
            GuardrailStage.PRE_TOOL,
            GuardrailStage.PRE_MESSAGE,
        }
    )

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.DENY,
            reason_codes=("TEST.WOULD_DENY",),
        )


class _McpSession:
    def __init__(self) -> None:
        self.call_tool = AsyncMock(return_value={"adapter": "mcp"})


class _A2ATransport:
    def __init__(self) -> None:
        self.send = AsyncMock(return_value={"adapter": "a2a"})


class _LangGraphTool:
    name = "lang"

    def __init__(self) -> None:
        self.ainvoke = AsyncMock(return_value={"adapter": "langgraph"})


class _CrewAITool:
    name = "crew"

    def __init__(self) -> None:
        self._run = Mock(return_value={"adapter": "crewai"})


class _AdkTool:
    name = "adk"

    def __init__(self) -> None:
        self.run_async = AsyncMock(return_value={"adapter": "adk"})


def _rbac() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="adapter-user",
                permissions=[
                    Permission(action="tool:mcp", resource="allowed/mcp", effect="allow"),
                    Permission(action="a2a:send:peer", resource="agent/peer", effect="allow"),
                    Permission(action="tool:lang", resource="allowed/lang", effect="allow"),
                    Permission(action="tool:crew", resource="allowed/crew", effect="allow"),
                    Permission(action="tool:adk", resource="allowed/adk", effect="allow"),
                ],
            )
        ]
    )


async def _legacy_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, PolicyEngine, str]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"shadow-adapter-{name}-abcdefghijklmnop")
    audit_dir = tmp_path / f"audit-{name}"
    policy_dir = tmp_path / f"policies-{name}"
    audit_dir.mkdir()
    policy_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Adapter Agent", roles=["adapter-user"])
    return (
        registry,
        _rbac(),
        AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
        PolicyEngine(policy_dirs=[policy_dir]),
        identity.agent_id,
    )


async def _exercise_legacy_adapter(
    adapter: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> object:
    registry, rbac, audit, policy, agent_id = await _legacy_dependencies(
        tmp_path, monkeypatch, adapter
    )
    common: dict[str, Any] = {
        "agent_id": agent_id,
        "registry": registry,
        "rbac_engine": rbac,
        "audit_log": audit,
        "policy_engine": policy,
        "guardrails": (_WouldDeny(),),
        "chain_mode": ChainMode.SHADOW,
    }
    if adapter == "mcp":
        client = GovernedMcpClient(
            session=_McpSession(), resources={"mcp": "allowed/mcp"}, **common
        )
        return await client.call_tool("mcp", {"value": 1})
    if adapter == "a2a":
        client = GovernedA2AClient(transport=_A2ATransport(), **common)
        return await client.send_message("peer", {"value": 1})
    if adapter == "langgraph":
        tool = GovernedLangGraphToolNode(
            tools=[_LangGraphTool()], resources={"lang": "allowed/lang"}, **common
        )
        return await tool.ainvoke("lang", {"value": 1})
    if adapter == "crewai":
        tool = GovernedCrewAITool(tool=_CrewAITool(), resource="allowed/crew", **common)
        return await tool.arun(value=1)
    tool = GovernedAdkTool(tool=_AdkTool(), resource="allowed/adk", **common)
    return await tool.run_async(args={"value": 1})


@pytest.mark.parametrize(
    ("adapter", "expected"),
    [
        ("mcp", {"adapter": "mcp"}),
        ("a2a", {"adapter": "a2a"}),
        ("langgraph", {"adapter": "langgraph"}),
        ("crewai", {"adapter": "crewai"}),
        ("adk", {"adapter": "adk"}),
    ],
)
async def test_legacy_adapter_propagates_shadow_chain_mode(
    adapter: str,
    expected: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert await _exercise_legacy_adapter(adapter, tmp_path, monkeypatch) == expected


async def test_mcp_shadow_denial_is_durable_without_blocking_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, rbac, audit, policy, agent_id = await _legacy_dependencies(
        tmp_path, monkeypatch, "mcp-durable"
    )
    session = _McpSession()
    client = GovernedMcpClient(
        session=session,
        agent_id=agent_id,
        registry=registry,
        rbac_engine=rbac,
        audit_log=audit,
        policy_engine=policy,
        guardrails=(_WouldDeny(),),
        chain_mode=ChainMode.SHADOW,
        resources={"mcp": "allowed/mcp"},
    )

    result = await client.call_tool("mcp", {"value": 1})

    assert result == {"adapter": "mcp"}
    session.call_tool.assert_awaited_once()
    snapshot = await audit.read_verified(require_checkpoint=True)
    assert snapshot.verification.valid
    admission = next(event for event in snapshot.events if event.event_type == "admission")
    evaluations = admission.model_dump()["guardrail_evaluations"]
    assert len(evaluations) == 1
    assert evaluations[0]["guardrail_id"] == "would-deny"
    assert evaluations[0]["effect"] == "deny"
    assert evaluations[0]["reason_codes"] == ("TEST.WOULD_DENY",)
    assert evaluations[0]["enforced"] is False
    assert "TEST.WOULD_DENY" not in admission.reason_codes


def _mixed_constructor(adapter: str, kernel: GovernanceKernel) -> object:
    common: dict[str, Any] = {
        "agent_id": "agent",
        "kernel": kernel,
        "chain_mode": ChainMode.SHADOW,
    }
    if adapter == "mcp":
        return GovernedMcpClient(session=_McpSession(), resources={"mcp": "allowed/mcp"}, **common)
    if adapter == "a2a":
        return GovernedA2AClient(transport=_A2ATransport(), **common)
    if adapter == "langgraph":
        return GovernedLangGraphToolNode(
            tools=[_LangGraphTool()], resources={"lang": "allowed/lang"}, **common
        )
    if adapter == "crewai":
        return GovernedCrewAITool(tool=_CrewAITool(), resource="allowed/crew", **common)
    return GovernedAdkTool(tool=_AdkTool(), resource="allowed/adk", **common)


@pytest.mark.parametrize("adapter", ["mcp", "a2a", "langgraph", "crewai", "adk"])
async def test_supplied_kernel_rejects_explicit_adapter_chain_mode(
    adapter: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, rbac, audit, policy, _ = await _legacy_dependencies(
        tmp_path, monkeypatch, f"mixed-{adapter}"
    )
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=rbac,
        audit_log=audit,
        policy_engine=policy,
        guardrails=(),
        chain_mode=ChainMode.SHADOW,
    )

    with pytest.raises(ValueError, match="kernel cannot be combined"):
        _mixed_constructor(adapter, kernel)
