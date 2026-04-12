"""Tests for agentguard.integrations.mcp_middleware — governed MCP tool calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.circuit_breaker import CircuitBreaker
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations.mcp_middleware import GovernedMcpClient

if TYPE_CHECKING:
    from pathlib import Path


class FakeMcpSession:
    """Fake MCP session for testing."""

    def __init__(self) -> None:
        self.call_tool = AsyncMock(return_value={"result": "credit_score=720"})


def _build_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="credit-analyst",
                permissions=[
                    Permission(action="tool:*", resource="bureau/*", effect="allow"),
                    Permission(action="tool:*", resource="admin/*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _mcp_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[
    AgentRegistry, RBACEngine, AppendOnlyAuditLog, CircuitBreaker, FakeMcpSession, Path
]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-abc")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    engine = _build_engine()
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    breaker = CircuitBreaker(name="mcp-test", failure_threshold=3, recovery_timeout=1.0)
    session = FakeMcpSession()
    return registry, engine, audit, breaker, session, audit_dir


class TestGovernedMcpClient:
    async def test_allowed_tool_call(self, _mcp_setup: Any) -> None:
        registry, engine, audit, breaker, session, _ = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        client = GovernedMcpClient(
            session=session,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            circuit_breaker=breaker,
        )
        result = await client.call_tool(
            "credit_check", {"bureau": "experian"}, resource="bureau/experian"
        )
        assert result == {"result": "credit_score=720"}
        session.call_tool.assert_called_once_with("credit_check", {"bureau": "experian"})

    async def test_denied_tool_call(self, _mcp_setup: Any) -> None:
        registry, engine, audit, breaker, session, _ = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        client = GovernedMcpClient(
            session=session,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            circuit_breaker=breaker,
        )
        with pytest.raises(PermissionDeniedError):
            await client.call_tool("delete_all", {}, resource="admin/users")
        session.call_tool.assert_not_called()

    async def test_audit_events_written(self, _mcp_setup: Any) -> None:
        registry, engine, audit, breaker, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        client = GovernedMcpClient(
            session=session,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            circuit_breaker=breaker,
        )
        await client.call_tool("credit_check", {}, resource="bureau/experian")

        backend = FileAuditBackend(directory=audit_dir)
        events = await backend.read_all()
        assert len(events) >= 1
        assert events[0].result == "allowed"

    async def test_denied_audit_event(self, _mcp_setup: Any) -> None:
        registry, engine, audit, breaker, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        client = GovernedMcpClient(
            session=session,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            circuit_breaker=breaker,
        )
        with pytest.raises(PermissionDeniedError):
            await client.call_tool("nuke", {}, resource="admin/delete")

        backend = FileAuditBackend(directory=audit_dir)
        events = await backend.read_all()
        assert len(events) == 1
        assert events[0].result == "denied"

    async def test_without_circuit_breaker(self, _mcp_setup: Any) -> None:
        registry, engine, audit, _, session, _ = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        client = GovernedMcpClient(
            session=session,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        result = await client.call_tool("credit_check", {}, resource="bureau/experian")
        assert result == {"result": "credit_score=720"}
