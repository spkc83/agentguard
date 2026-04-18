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
        )
        result = await governed.run("query text")
        assert result == {"data": "found"}
        tool._run.assert_called_once_with("query text")

    async def test_denied_tool_call(self, _crew_setup: Any) -> None:
        registry, engine, audit, _, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        admin_tool = FakeCrewAITool("admin_op")
        governed = GovernedCrewAITool(
            tool=admin_tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="admin/settings",
        )
        with pytest.raises(PermissionDeniedError):
            await governed.run("delete")
        admin_tool._run.assert_not_called()

    async def test_name_proxied(self, _crew_setup: Any) -> None:
        registry, engine, audit, tool, _ = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        governed = GovernedCrewAITool(
            tool=tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
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
        )
        await governed.run("query")

        backend = FileAuditBackend(directory=audit_dir)
        events = await backend.read_all()
        assert len(events) >= 1
        assert events[0].action == "tool:search"

    async def test_denied_audit_event(self, _crew_setup: Any) -> None:
        registry, engine, audit, _, audit_dir = _crew_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        admin_tool = FakeCrewAITool("admin_op")
        governed = GovernedCrewAITool(
            tool=admin_tool,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resource="admin/settings",
        )
        with pytest.raises(PermissionDeniedError):
            await governed.run()

        backend = FileAuditBackend(directory=audit_dir)
        events = await backend.read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
