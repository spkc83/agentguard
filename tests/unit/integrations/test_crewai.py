"""Tests for agentguard.integrations.crewai — governed CrewAI tool."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.circuit_breaker import CircuitBreaker
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations._pipeline import UNRESOLVED_RESOURCE
from agentguard.integrations.crewai import GovernedCrewAITool

if TYPE_CHECKING:
    from pathlib import Path


class FakeCrewAITool:
    """Fake CrewAI tool for testing."""

    def __init__(self, name: str, result: Any = "crewai_result") -> None:
        self.name = name
        self._run = MagicMock(return_value=result)


def _build_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="analyst",
                permissions=[
                    Permission(action="tool:search", resource="*", effect="allow"),
                    Permission(action="tool:admin_op", resource="*", effect="allow"),
                    Permission(action="tool:*", resource="admin/*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _crew_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, FakeCrewAITool, Path]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-crew")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    engine = _build_engine()
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    tool = FakeCrewAITool("search", result={"data": "found"})
    return registry, engine, audit, tool, audit_dir


class TestGovernedCrewAITool:
    async def test_allowed_tool_call(self, _crew_setup: Any) -> None:
        registry, engine, audit, tool, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedCrewAITool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="index/public",
        )
        result = await governed.run("query text")
        assert result == {"data": "found"}
        tool._run.assert_called_once_with("query text")

    async def test_name_proxied(self, _crew_setup: Any) -> None:
        registry, engine, audit, tool, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedCrewAITool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="index/public",
        )
        assert governed.name == "search"

    async def test_with_circuit_breaker(self, _crew_setup: Any) -> None:
        registry, engine, audit, tool, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        breaker = CircuitBreaker(name="crew-test", failure_threshold=3)

        governed = GovernedCrewAITool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="index/public",
            circuit_breaker=breaker,
        )
        result = await governed.run("test")
        assert result == {"data": "found"}

    async def test_audit_events_written(self, _crew_setup: Any) -> None:
        registry, engine, audit, tool, audit_dir = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedCrewAITool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="index/public",
        )
        await governed.run("query")

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) >= 1
        assert events[0].action == "tool:search"
        assert events[0].resource == "index/public"

    async def test_resource_is_required(self, _crew_setup: Any) -> None:
        """There is no implicit ``"*"`` default any more."""
        registry, engine, audit, tool, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        with pytest.raises(TypeError):
            GovernedCrewAITool(  # type: ignore[call-arg]
                tool=tool,
                agent_id=agent.agent_id,
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
            )

    async def test_resolver_receives_args_and_kwargs(self, _crew_setup: Any) -> None:
        registry, engine, audit, tool, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        seen: list[Any] = []

        def _resolver(call_input: Any) -> str:
            seen.append(call_input)
            return "index/public"

        governed = GovernedCrewAITool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource=_resolver,
        )
        await governed.run("q", limit=5)
        assert seen == [{"args": ("q",), "kwargs": {"limit": 5}}]
        tool._run.assert_called_once_with("q", limit=5)


class TestCrewAIResourceIsNotAgentSupplied:
    def _governed(self, setup: Any, agent_id: str, resource: Any, tool: Any) -> GovernedCrewAITool:
        registry, engine, audit, _, _ = setup
        return GovernedCrewAITool(
            tool=tool,
            agent_id=agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource=resource,
        )

    async def test_call_time_resource_kwarg_rejected(self, _crew_setup: Any) -> None:
        """(a) ``_resource=`` was the escape hatch; it is now a hard error."""
        registry, _, _, _, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeCrewAITool("admin_op")
        governed = self._governed(_crew_setup, agent.agent_id, "admin/settings", admin_tool)

        with pytest.raises(TypeError, match="_resource is no longer accepted"):
            await governed.run("delete", _resource="public/report")
        admin_tool._run.assert_not_called()

    async def test_raising_resolver_is_denied_and_audited(self, _crew_setup: Any) -> None:
        """(b)/(c) An unresolvable resource denies before the tool is touched."""
        registry, _, _, _, audit_dir = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeCrewAITool("admin_op")

        def _boom(_: Any) -> str:
            raise RuntimeError("resolver exploded")

        governed = self._governed(_crew_setup, agent.agent_id, _boom, admin_tool)
        with pytest.raises(PermissionDeniedError) as excinfo:
            await governed.run("delete")
        assert excinfo.value.resource == UNRESOLVED_RESOURCE
        admin_tool._run.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
        assert events[0].resource == UNRESOLVED_RESOURCE

    @pytest.mark.parametrize("bad", ["", "   ", "../admin/x", "/admin/x", "admin/*", "*"])
    async def test_uncanonical_resolver_result_is_denied(self, _crew_setup: Any, bad: str) -> None:
        """(d)"""
        registry, _, _, _, audit_dir = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeCrewAITool("admin_op")
        governed = self._governed(_crew_setup, agent.agent_id, lambda _: bad, admin_tool)

        with pytest.raises(PermissionDeniedError):
            await governed.run("delete")
        admin_tool._run.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].resource == UNRESOLVED_RESOURCE

    async def test_static_bad_resource_is_denied(self, _crew_setup: Any) -> None:
        """(d) A static wildcard configured by the integrator is rejected too."""
        registry, _, _, _, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeCrewAITool("admin_op")
        governed = self._governed(_crew_setup, agent.agent_id, "*", admin_tool)

        with pytest.raises(PermissionDeniedError) as excinfo:
            await governed.run("delete")
        assert excinfo.value.resource == UNRESOLVED_RESOURCE
        admin_tool._run.assert_not_called()

    async def test_honest_resolver_hits_deny_rule(self, _crew_setup: Any) -> None:
        """(e)"""
        registry, _, _, _, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeCrewAITool("admin_op")
        governed = self._governed(
            _crew_setup, agent.agent_id, lambda c: f"admin/{c['kwargs']['target']}", admin_tool
        )

        with pytest.raises(PermissionDeniedError) as excinfo:
            await governed.run(target="settings")
        assert excinfo.value.resource == "admin/settings"
        admin_tool._run.assert_not_called()

    async def test_case_variant_resource_still_denied(self, _crew_setup: Any) -> None:
        """(f)"""
        registry, _, _, _, audit_dir = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeCrewAITool("admin_op")
        governed = self._governed(_crew_setup, agent.agent_id, "Admin/Settings", admin_tool)

        with pytest.raises(PermissionDeniedError):
            await governed.run("delete")
        admin_tool._run.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "admin/settings"

    async def test_allowed_resource_executes(self, _crew_setup: Any) -> None:
        """(g)"""
        registry, _, _, _, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeCrewAITool("admin_op", result="done")
        governed = self._governed(_crew_setup, agent.agent_id, "public/report", admin_tool)

        assert await governed.run("read") == "done"
        admin_tool._run.assert_called_once_with("read")

    async def test_async_resolver(self, _crew_setup: Any) -> None:
        """(h)"""
        registry, _, _, tool, audit_dir = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        async def _resolver(call_input: Any) -> str:
            return f"index/{call_input['args'][0]}"

        governed = self._governed(_crew_setup, agent.agent_id, _resolver, tool)
        assert await governed.run("public") == {"data": "found"}

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "index/public"

    async def test_static_string_resolver(self, _crew_setup: Any) -> None:
        """(i)"""
        registry, _, _, tool, audit_dir = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        governed = self._governed(_crew_setup, agent.agent_id, "Index/Public", tool)

        assert await governed.run("q") == {"data": "found"}
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "index/public"
