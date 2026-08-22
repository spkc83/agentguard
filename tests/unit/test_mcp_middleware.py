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
from agentguard.integrations._pipeline import UNRESOLVED_RESOURCE
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
                    Permission(action="tool:*", resource="public/*", effect="allow"),
                    Permission(action="tool:*", resource="admin/*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _mcp_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, CircuitBreaker, FakeMcpSession, Path]:
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
            resources={"credit_check": lambda a: f"bureau/{a['bureau']}"},
            circuit_breaker=breaker,
        )
        result = await client.call_tool("credit_check", {"bureau": "experian"})
        assert result == {"result": "credit_score=720"}
        session.call_tool.assert_called_once_with("credit_check", {"bureau": "experian"})

    async def test_audit_events_written(self, _mcp_setup: Any) -> None:
        registry, engine, audit, breaker, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        client = GovernedMcpClient(
            session=session,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resources={"credit_check": "bureau/experian"},
            circuit_breaker=breaker,
        )
        await client.call_tool("credit_check", {})

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) >= 1
        assert events[0].result == "allowed"
        assert events[0].resource == "bureau/experian"

    async def test_without_circuit_breaker(self, _mcp_setup: Any) -> None:
        registry, engine, audit, _, session, _ = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        client = GovernedMcpClient(
            session=session,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resources={"credit_check": "bureau/experian"},
        )
        result = await client.call_tool("credit_check", {})
        assert result == {"result": "credit_score=720"}

    async def test_default_arguments_reach_the_resolver(self, _mcp_setup: Any) -> None:
        """``arguments=None`` becomes ``{}`` for the tool and the resolver alike."""
        registry, engine, audit, _, session, _ = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])
        seen: list[Any] = []

        def _resolver(call_input: Any) -> str:
            seen.append(call_input)
            return "bureau/experian"

        client = GovernedMcpClient(
            session=session,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resources={"credit_check": _resolver},
        )
        await client.call_tool("credit_check")
        assert seen == [{}]
        session.call_tool.assert_called_once_with("credit_check", {})


class TestMcpResourceIsNotAgentSupplied:
    def _client(self, setup: Any, agent_id: str, resources: Any) -> GovernedMcpClient:
        registry, engine, audit, _, session, _ = setup
        return GovernedMcpClient(
            session=session,
            agent_id=agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resources=resources,
        )

    async def test_call_time_resource_kwarg_rejected(self, _mcp_setup: Any) -> None:
        """(a)"""
        registry, _, _, _, session, _ = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])
        client = self._client(_mcp_setup, agent.agent_id, {"delete_all": "admin/users"})

        with pytest.raises(TypeError):
            await client.call_tool(  # type: ignore[call-arg]
                "delete_all", {}, resource="public/report"
            )
        session.call_tool.assert_not_called()

    async def test_unconfigured_tool_is_denied_and_audited(self, _mcp_setup: Any) -> None:
        """(b) An MCP tool with no resolver cannot be called at all."""
        registry, _, _, _, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])
        client = self._client(_mcp_setup, agent.agent_id, {})

        with pytest.raises(PermissionDeniedError) as excinfo:
            await client.call_tool("delete_all", {})
        assert excinfo.value.resource == UNRESOLVED_RESOURCE
        session.call_tool.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
        assert events[0].resource == UNRESOLVED_RESOURCE

    async def test_raising_resolver_is_denied_and_audited(self, _mcp_setup: Any) -> None:
        """(c)"""
        registry, _, _, _, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        def _boom(_: Any) -> str:
            raise KeyError("missing argument")

        client = self._client(_mcp_setup, agent.agent_id, {"credit_check": _boom})
        with pytest.raises(PermissionDeniedError):
            await client.call_tool("credit_check", {})
        session.call_tool.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == UNRESOLVED_RESOURCE

    @pytest.mark.parametrize("bad", ["", "   ", "../admin/x", "/admin/x", "admin/*", "*"])
    async def test_uncanonical_resolver_result_is_denied(self, _mcp_setup: Any, bad: str) -> None:
        """(d)"""
        registry, _, _, _, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])
        client = self._client(_mcp_setup, agent.agent_id, {"credit_check": lambda _: bad})

        with pytest.raises(PermissionDeniedError):
            await client.call_tool("credit_check", {})
        session.call_tool.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].resource == UNRESOLVED_RESOURCE

    async def test_honest_resolver_hits_deny_rule(self, _mcp_setup: Any) -> None:
        """(e)"""
        registry, _, _, _, session, _ = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])
        client = self._client(
            _mcp_setup, agent.agent_id, {"delete_all": lambda a: f"admin/{a['target']}"}
        )

        with pytest.raises(PermissionDeniedError) as excinfo:
            await client.call_tool("delete_all", {"target": "users"})
        assert excinfo.value.resource == "admin/users"
        session.call_tool.assert_not_called()

    async def test_case_variant_resource_still_denied(self, _mcp_setup: Any) -> None:
        """(f)"""
        registry, _, _, _, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])
        client = self._client(
            _mcp_setup, agent.agent_id, {"delete_all": lambda a: f"Admin/{a['target']}"}
        )

        with pytest.raises(PermissionDeniedError):
            await client.call_tool("delete_all", {"target": "Users"})
        session.call_tool.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "admin/users"

    async def test_allowed_resource_executes(self, _mcp_setup: Any) -> None:
        """(g)"""
        registry, _, _, _, session, _ = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])
        client = self._client(_mcp_setup, agent.agent_id, {"delete_all": lambda _: "public/report"})

        assert await client.call_tool("delete_all", {}) == {"result": "credit_score=720"}
        session.call_tool.assert_called_once()

    async def test_async_resolver(self, _mcp_setup: Any) -> None:
        """(h)"""
        registry, _, _, _, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])

        async def _resolver(call_input: Any) -> str:
            return f"bureau/{call_input['bureau']}"

        client = self._client(_mcp_setup, agent.agent_id, {"credit_check": _resolver})
        await client.call_tool("credit_check", {"bureau": "equifax"})

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "bureau/equifax"

    async def test_static_string_resolver(self, _mcp_setup: Any) -> None:
        """(i)"""
        registry, _, _, _, session, audit_dir = _mcp_setup
        agent = await registry.register(name="Bot", roles=["credit-analyst"])
        client = self._client(_mcp_setup, agent.agent_id, {"credit_check": "Bureau/Experian"})

        await client.call_tool("credit_check", {})
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "bureau/experian"
