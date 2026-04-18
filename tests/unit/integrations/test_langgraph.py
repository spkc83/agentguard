"""Tests for agentguard.integrations.langgraph — governed LangGraph tool node."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.circuit_breaker import CircuitBreaker
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations.langgraph import GovernedLangGraphToolNode

if TYPE_CHECKING:
    from pathlib import Path


class FakeLangChainTool:
    """Fake LangChain tool for testing."""

    def __init__(self, name: str, result: Any = "tool_result") -> None:
        self.name = name
        self.ainvoke = AsyncMock(return_value=result)


def _build_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="analyst",
                permissions=[
                    Permission(action="tool:credit_check", resource="*", effect="allow"),
                    Permission(action="tool:*", resource="admin/*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _lg_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, FakeLangChainTool]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-lg")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    engine = _build_engine()
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    tool = FakeLangChainTool("credit_check", result={"score": 720})
    return registry, engine, audit, tool


class TestGovernedLangGraphToolNode:
    async def test_allowed_tool_call(self, _lg_setup: Any) -> None:
        registry, engine, audit, tool = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        node = GovernedLangGraphToolNode(
            tools=[tool],
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        result = await node.ainvoke("credit_check", {"bureau": "experian"})
        assert result == {"score": 720}
        tool.ainvoke.assert_called_once_with({"bureau": "experian"})

    async def test_denied_tool_call(self, _lg_setup: Any) -> None:
        registry, engine, audit, tool = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        admin_tool = FakeLangChainTool("admin_delete")
        node = GovernedLangGraphToolNode(
            tools=[tool, admin_tool],
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await node.ainvoke("admin_delete", {}, resource="admin/users")
        admin_tool.ainvoke.assert_not_called()

    async def test_tool_not_found(self, _lg_setup: Any) -> None:
        registry, engine, audit, tool = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        node = GovernedLangGraphToolNode(
            tools=[tool],
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(KeyError, match="nonexistent"):
            await node.ainvoke("nonexistent", {})

    async def test_with_circuit_breaker(self, _lg_setup: Any) -> None:
        registry, engine, audit, tool = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        breaker = CircuitBreaker(name="lg-test", failure_threshold=3)

        node = GovernedLangGraphToolNode(
            tools=[tool],
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            circuit_breaker=breaker,
        )
        result = await node.ainvoke("credit_check", {"x": 1})
        assert result == {"score": 720}

    async def test_audit_events_written(self, _lg_setup: Any, tmp_path: Path) -> None:
        registry, engine, audit, tool = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        node = GovernedLangGraphToolNode(
            tools=[tool],
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        await node.ainvoke("credit_check", {})

        # Read back audit events
        backend = FileAuditBackend(directory=tmp_path / "audit")
        events = await backend.read_all()
        assert len(events) >= 1
        assert events[0].action == "tool:credit_check"
        assert events[0].result == "allowed"
