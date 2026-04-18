"""Tests for agentguard.integrations.google_adk — governed ADK tool."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.circuit_breaker import CircuitBreaker
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations.google_adk import GovernedAdkTool

if TYPE_CHECKING:
    from pathlib import Path


class FakeAdkTool:
    """Fake Google ADK tool for testing."""

    def __init__(self, name: str, result: Any = "adk_result") -> None:
        self.name = name
        self.run_async = AsyncMock(return_value=result)


def _build_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="analyst",
                permissions=[
                    Permission(action="tool:lookup", resource="*", effect="allow"),
                    Permission(action="tool:*", resource="restricted/*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _adk_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, FakeAdkTool, Path]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-adk")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    engine = _build_engine()
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    tool = FakeAdkTool("lookup", result={"status": "ok"})
    return registry, engine, audit, tool, audit_dir


class TestGovernedAdkTool:
    async def test_allowed_tool_call(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedAdkTool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        result = await governed.run_async(args={"key": "value"}, tool_context=None)
        assert result == {"status": "ok"}
        tool.run_async.assert_called_once_with(args={"key": "value"}, tool_context=None)

    async def test_denied_tool_call(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedAdkTool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="restricted/data",
        )
        with pytest.raises(PermissionDeniedError):
            await governed.run_async(args={})
        tool.run_async.assert_not_called()

    async def test_resource_override(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedAdkTool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="restricted/data",
        )
        # Override to a non-restricted resource
        result = await governed.run_async(args={"x": 1}, resource="public/data")
        assert result == {"status": "ok"}

    async def test_with_circuit_breaker(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        breaker = CircuitBreaker(name="adk-test", failure_threshold=3)

        governed = GovernedAdkTool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            circuit_breaker=breaker,
        )
        result = await governed.run_async(args={})
        assert result == {"status": "ok"}

    async def test_audit_events_written(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, audit_dir = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedAdkTool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        await governed.run_async(args={"q": "test"})

        backend = FileAuditBackend(directory=audit_dir)
        events = await backend.read_all()
        assert len(events) >= 1
        assert events[0].action == "tool:lookup"
        assert events[0].result == "allowed"

    async def test_name_proxied(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedAdkTool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        assert governed.name == "lookup"
