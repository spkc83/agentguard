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
from agentguard.integrations._pipeline import UNRESOLVED_RESOURCE
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
            resource="public/data",
        )
        result = await governed.run_async(args={"key": "value"}, tool_context=None)
        assert result == {"status": "ok"}
        tool.run_async.assert_called_once_with(args={"key": "value"}, tool_context=None)

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
            resource="public/data",
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
            resource="public/data",
        )
        await governed.run_async(args={"q": "test"})

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) >= 1
        assert events[0].action == "tool:lookup"
        assert events[0].result == "allowed"
        assert events[0].resource == "public/data"

    async def test_name_proxied(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedAdkTool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="public/data",
        )
        assert governed.name == "lookup"

    async def test_resource_is_required(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        with pytest.raises(TypeError):
            GovernedAdkTool(  # type: ignore[call-arg]
                tool=tool,
                agent_id=agent.agent_id,
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
            )

    async def test_resolver_receives_args(self, _adk_setup: Any) -> None:
        registry, engine, audit, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        seen: list[Any] = []

        def _resolver(call_input: Any) -> str:
            seen.append(call_input)
            return "public/data"

        governed = GovernedAdkTool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource=_resolver,
        )
        await governed.run_async(args={"q": 1})
        assert seen == [{"q": 1}]


class TestAdkResourceIsNotAgentSupplied:
    def _governed(self, setup: Any, agent_id: str, resource: Any) -> GovernedAdkTool:
        registry, engine, audit, tool, _ = setup
        return GovernedAdkTool(
            tool=tool,
            agent_id=agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource=resource,
        )

    async def test_call_time_resource_kwarg_rejected(self, _adk_setup: Any) -> None:
        """(a) The per-call ``resource=`` override is gone."""
        registry, _, _, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        governed = self._governed(_adk_setup, agent.agent_id, "restricted/data")

        with pytest.raises(TypeError):
            await governed.run_async(args={}, resource="public/data")  # type: ignore[call-arg]
        tool.run_async.assert_not_called()

    async def test_raising_resolver_is_denied_and_audited(self, _adk_setup: Any) -> None:
        """(b)/(c)"""
        registry, _, _, tool, audit_dir = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        def _boom(_: Any) -> str:
            raise ValueError("resolver exploded")

        governed = self._governed(_adk_setup, agent.agent_id, _boom)
        with pytest.raises(PermissionDeniedError) as excinfo:
            await governed.run_async(args={})
        assert excinfo.value.resource == UNRESOLVED_RESOURCE
        tool.run_async.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
        assert events[0].resource == UNRESOLVED_RESOURCE

    @pytest.mark.parametrize("bad", ["", "   ", "../restricted/x", "/restricted/x", "*"])
    async def test_uncanonical_resolver_result_is_denied(self, _adk_setup: Any, bad: str) -> None:
        """(d)"""
        registry, _, _, tool, audit_dir = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        governed = self._governed(_adk_setup, agent.agent_id, lambda _: bad)

        with pytest.raises(PermissionDeniedError):
            await governed.run_async(args={})
        tool.run_async.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].resource == UNRESOLVED_RESOURCE

    async def test_honest_resolver_hits_deny_rule(self, _adk_setup: Any) -> None:
        """(e)"""
        registry, _, _, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        governed = self._governed(_adk_setup, agent.agent_id, lambda a: f"restricted/{a['id']}")

        with pytest.raises(PermissionDeniedError) as excinfo:
            await governed.run_async(args={"id": "data"})
        assert excinfo.value.resource == "restricted/data"
        tool.run_async.assert_not_called()

    async def test_case_variant_resource_still_denied(self, _adk_setup: Any) -> None:
        """(f)"""
        registry, _, _, tool, audit_dir = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        governed = self._governed(_adk_setup, agent.agent_id, lambda a: f"Restricted/{a['id']}")

        with pytest.raises(PermissionDeniedError):
            await governed.run_async(args={"id": "Data"})
        tool.run_async.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "restricted/data"

    async def test_allowed_resource_executes(self, _adk_setup: Any) -> None:
        """(g)"""
        registry, _, _, tool, _ = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        governed = self._governed(_adk_setup, agent.agent_id, lambda a: f"public/{a['id']}")

        assert await governed.run_async(args={"id": "data"}) == {"status": "ok"}
        tool.run_async.assert_called_once()

    async def test_async_resolver(self, _adk_setup: Any) -> None:
        """(h)"""
        registry, _, _, tool, audit_dir = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        async def _resolver(call_input: Any) -> str:
            return f"public/{call_input['id']}"

        governed = self._governed(_adk_setup, agent.agent_id, _resolver)
        assert await governed.run_async(args={"id": "records"}) == {"status": "ok"}

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "public/records"

    async def test_static_string_resolver(self, _adk_setup: Any) -> None:
        """(i)"""
        registry, _, _, tool, audit_dir = _adk_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        governed = self._governed(_adk_setup, agent.agent_id, "Public/Data")

        assert await governed.run_async(args={}) == {"status": "ok"}
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "public/data"
