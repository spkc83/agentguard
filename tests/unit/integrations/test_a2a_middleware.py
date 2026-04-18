"""Tests for agentguard.integrations.a2a_middleware — governed A2A client."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.circuit_breaker import CircuitBreaker
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations.a2a_middleware import GovernedA2AClient

if TYPE_CHECKING:
    from pathlib import Path


class FakeA2ATransport:
    """Fake A2A transport for testing."""

    def __init__(self) -> None:
        self.send = AsyncMock(return_value={"response": "acknowledged"})


def _build_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="coordinator",
                permissions=[
                    Permission(action="a2a:send:*", resource="agent/*", effect="allow"),
                ],
            ),
            Role(
                name="restricted",
                permissions=[
                    Permission(action="a2a:send:*", resource="agent/secret-*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _a2a_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, FakeA2ATransport, Path]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-a2a")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    engine = _build_engine()
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    transport = FakeA2ATransport()
    return registry, engine, audit, transport, audit_dir


class TestGovernedA2AClient:
    async def test_allowed_message(self, _a2a_setup: Any) -> None:
        registry, engine, audit, transport, _ = _a2a_setup
        agent = await registry.register(name="Coordinator", roles=["coordinator"])

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        result = await client.send_message("agent-002", {"task": "analyze"})
        assert result == {"response": "acknowledged"}
        transport.send.assert_called_once_with("agent-002", {"task": "analyze"})

    async def test_denied_message(self, _a2a_setup: Any) -> None:
        registry, engine, audit, transport, _ = _a2a_setup
        agent = await registry.register(name="Bot", roles=["coordinator", "restricted"])

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message("secret-agent", {"task": "spy"})
        transport.send.assert_not_called()

    async def test_audit_events_written(self, _a2a_setup: Any) -> None:
        registry, engine, audit, transport, audit_dir = _a2a_setup
        agent = await registry.register(name="Coordinator", roles=["coordinator"])

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        await client.send_message("agent-002", {"task": "test"})

        backend = FileAuditBackend(directory=audit_dir)
        events = await backend.read_all()
        assert len(events) >= 1
        assert events[0].action == "a2a:send:agent-002"
        assert events[0].resource == "agent/agent-002"

    async def test_denied_audit_event(self, _a2a_setup: Any) -> None:
        registry, engine, audit, transport, audit_dir = _a2a_setup
        agent = await registry.register(name="Bot", roles=["coordinator", "restricted"])

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message("secret-agent", {})

        backend = FileAuditBackend(directory=audit_dir)
        events = await backend.read_all()
        assert len(events) == 1
        assert events[0].result == "denied"

    async def test_with_circuit_breaker(self, _a2a_setup: Any) -> None:
        registry, engine, audit, transport, _ = _a2a_setup
        agent = await registry.register(name="Coordinator", roles=["coordinator"])
        breaker = CircuitBreaker(name="a2a-test", failure_threshold=3)

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            circuit_breaker=breaker,
        )
        result = await client.send_message("agent-003", {"msg": "hi"})
        assert result == {"response": "acknowledged"}
