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
from agentguard.integrations._pipeline import UNRESOLVED_RESOURCE
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
                    Permission(action="tool:admin_delete", resource="*", effect="allow"),
                    Permission(action="tool:*", resource="admin/*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _lg_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, FakeLangChainTool, Path]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-lg-padded-abcdefghijklm")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    engine = _build_engine()
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    tool = FakeLangChainTool("credit_check", result={"score": 720})
    return registry, engine, audit, tool, audit_dir


class TestGovernedLangGraphToolNode:
    async def test_allowed_tool_call(self, _lg_setup: Any) -> None:
        registry, engine, audit, tool, _ = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        node = GovernedLangGraphToolNode(
            tools=[tool],
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resources={"credit_check": lambda a: f"bureau/{a['bureau']}"},
        )
        result = await node.ainvoke("credit_check", {"bureau": "experian"})
        assert result == {"score": 720}
        tool.ainvoke.assert_called_once_with({"bureau": "experian"})

    async def test_with_circuit_breaker(self, _lg_setup: Any) -> None:
        registry, engine, audit, tool, _ = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        breaker = CircuitBreaker(name="lg-test", failure_threshold=3)

        node = GovernedLangGraphToolNode(
            tools=[tool],
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resources={"credit_check": "bureau/experian"},
            circuit_breaker=breaker,
        )
        result = await node.ainvoke("credit_check", {"x": 1})
        assert result == {"score": 720}

    async def test_audit_events_written(self, _lg_setup: Any) -> None:
        registry, engine, audit, tool, audit_dir = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        node = GovernedLangGraphToolNode(
            tools=[tool],
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resources={"credit_check": "bureau/experian"},
        )
        await node.ainvoke("credit_check", {})

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) >= 1
        assert events[0].action == "tool:credit_check"
        assert events[0].result == "allowed"
        assert events[0].resource == "bureau/experian"


class TestLangGraphResourceIsNotAgentSupplied:
    """The governed party must not be able to name its own RBAC subject.

    The node is configured so that ``admin_delete`` is allowed on ``*`` and
    denied on ``admin/*``; the only thing standing between the agent and the
    deny rule is that the resource is derived, not supplied.
    """

    def _node(
        self,
        setup: Any,
        agent_id: str,
        resources: Any,
        tools: list[Any] | None = None,
    ) -> GovernedLangGraphToolNode:
        registry, engine, audit, tool, _ = setup
        return GovernedLangGraphToolNode(
            tools=tools if tools is not None else [tool],
            agent_id=agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            resources=resources,
        )

    async def test_call_time_resource_kwarg_rejected(self, _lg_setup: Any) -> None:
        """(a) The old escape hatch is gone at the signature level."""
        registry, _, _, tool, _ = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        node = self._node(_lg_setup, agent.agent_id, {"credit_check": "bureau/experian"})

        with pytest.raises(TypeError):
            await node.ainvoke(  # type: ignore[call-arg]
                "credit_check", {}, resource="public/report"
            )
        tool.ainvoke.assert_not_called()

    async def test_unknown_tool_is_denied_and_audited(self, _lg_setup: Any) -> None:
        """(b) An unregistered tool is a governed denial, not a KeyError."""
        registry, _, _, tool, audit_dir = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        node = self._node(_lg_setup, agent.agent_id, {"credit_check": "bureau/experian"})

        with pytest.raises(PermissionDeniedError) as excinfo:
            await node.ainvoke("nonexistent", {})
        assert excinfo.value.resource == UNRESOLVED_RESOURCE
        tool.ainvoke.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
        assert events[0].resource == UNRESOLVED_RESOURCE
        assert events[0].action == "tool:nonexistent"

    async def test_missing_resolver_is_denied_and_audited(self, _lg_setup: Any) -> None:
        """(b) A registered tool with no configured resolver is unresolvable."""
        registry, _, _, tool, audit_dir = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        node = self._node(_lg_setup, agent.agent_id, {})

        with pytest.raises(PermissionDeniedError):
            await node.ainvoke("credit_check", {})
        tool.ainvoke.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
        assert events[0].resource == UNRESOLVED_RESOURCE

    async def test_raising_resolver_is_denied_and_audited(self, _lg_setup: Any) -> None:
        """(c) A resolver that blows up denies rather than leaking through."""
        registry, _, _, tool, audit_dir = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        def _boom(_: Any) -> str:
            raise RuntimeError("resolver exploded")

        node = self._node(_lg_setup, agent.agent_id, {"credit_check": _boom})

        with pytest.raises(PermissionDeniedError):
            await node.ainvoke("credit_check", {})
        tool.ainvoke.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].resource == UNRESOLVED_RESOURCE

    @pytest.mark.parametrize("bad", ["", "   ", "../admin/x", "/admin/x", "admin/*", "*"])
    async def test_uncanonical_resolver_result_is_denied(self, _lg_setup: Any, bad: str) -> None:
        """(d) A resolver cannot emit a wildcard, an absolute path, or an escape."""
        registry, _, _, tool, audit_dir = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        node = self._node(_lg_setup, agent.agent_id, {"credit_check": lambda _: bad})

        with pytest.raises(PermissionDeniedError) as excinfo:
            await node.ainvoke("credit_check", {})
        assert excinfo.value.resource == UNRESOLVED_RESOURCE
        tool.ainvoke.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
        assert events[0].resource == UNRESOLVED_RESOURCE

    async def test_honest_resolver_hits_deny_rule(self, _lg_setup: Any) -> None:
        """(e) A truthfully derived admin resource is denied."""
        registry, _, _, tool, _ = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeLangChainTool("admin_delete")
        node = self._node(
            _lg_setup,
            agent.agent_id,
            {"admin_delete": lambda a: f"admin/{a['target']}"},
            tools=[tool, admin_tool],
        )

        with pytest.raises(PermissionDeniedError) as excinfo:
            await node.ainvoke("admin_delete", {"target": "users"})
        assert excinfo.value.resource == "admin/users"
        admin_tool.ainvoke.assert_not_called()

    async def test_case_variant_resource_still_denied(self, _lg_setup: Any) -> None:
        """(f) ``Admin/Users`` must not evade ``deny tool:* on admin/*``."""
        registry, _, _, tool, audit_dir = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeLangChainTool("admin_delete")
        node = self._node(
            _lg_setup,
            agent.agent_id,
            {"admin_delete": lambda a: f"Admin/{a['target']}"},
            tools=[tool, admin_tool],
        )

        with pytest.raises(PermissionDeniedError):
            await node.ainvoke("admin_delete", {"target": "Users"})
        admin_tool.ainvoke.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].result == "denied"
        assert events[0].resource == "admin/users"

    async def test_agent_input_cannot_redirect_a_derived_resource(self, _lg_setup: Any) -> None:
        """The whole point: hostile tool input reaches the resolver, not RBAC."""
        registry, _, _, tool, _ = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        admin_tool = FakeLangChainTool("admin_delete")
        node = self._node(
            _lg_setup,
            agent.agent_id,
            {"admin_delete": lambda a: f"admin/{a['target']}"},
            tools=[tool, admin_tool],
        )

        # The agent tries to name a resource its policy allows.
        with pytest.raises(PermissionDeniedError):
            await node.ainvoke("admin_delete", {"target": "users", "resource": "public/report"})
        admin_tool.ainvoke.assert_not_called()

    async def test_allowed_resource_executes(self, _lg_setup: Any) -> None:
        """(g) A benign derived resource still runs."""
        registry, _, _, tool, _ = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        node = self._node(_lg_setup, agent.agent_id, {"credit_check": lambda _: "public/report"})

        assert await node.ainvoke("credit_check", {}) == {"score": 720}
        tool.ainvoke.assert_called_once()

    async def test_async_resolver(self, _lg_setup: Any) -> None:
        """(h) Async resolvers are awaited."""
        registry, _, _, tool, audit_dir = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])

        async def _resolver(call_input: Any) -> str:
            return f"bureau/{call_input['bureau']}"

        node = self._node(_lg_setup, agent.agent_id, {"credit_check": _resolver})
        assert await node.ainvoke("credit_check", {"bureau": "equifax"}) == {"score": 720}

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "bureau/equifax"

    async def test_static_string_resolver(self, _lg_setup: Any) -> None:
        """(i) A static resource string is a valid resolver."""
        registry, _, _, tool, audit_dir = _lg_setup
        agent = await registry.register(name="Bot", roles=["analyst"])
        node = self._node(_lg_setup, agent.agent_id, {"credit_check": "Bureau/Experian"})

        assert await node.ainvoke("credit_check", {}) == {"score": 720}
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].resource == "bureau/experian"
