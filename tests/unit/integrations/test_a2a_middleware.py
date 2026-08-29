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
from agentguard.guardrails import (
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    MessagePayload,
)
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
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-a2a-padded-abcdefghijkl")
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

    async def test_case_variant_target_cannot_evade_deny(self, _a2a_setup: Any) -> None:
        """``Secret-Ops`` must still hit ``deny a2a:send:* on agent/secret-*``.

        The A2A resource is already derived (``agent/{target}``), but the target
        name itself is caller-controlled, so canonicalisation is what stops a
        cased variant from slipping past the deny rule.
        """
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
            await client.send_message("Secret-Ops", {"task": "spy"})
        transport.send.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
        assert events[0].resource == "agent/secret-ops"

    @pytest.mark.parametrize("target", ["", " ", "\t"])
    async def test_empty_target_is_unresolvable(self, _a2a_setup: Any, target: str) -> None:
        """An empty target must be an ``<unresolved>`` denial, not ``agent``.

        ``f"agent/{''}"`` would normalise to the bare resource ``agent``,
        which a ``deny * on agent/*`` rule does not match — so the denial
        must come from unresolvability, not incidentally from RBAC.
        """
        registry, engine, audit, transport, audit_dir = _a2a_setup
        agent = await registry.register(name="Coordinator", roles=["coordinator"])

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message(target, {"task": "x"})
        transport.send.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[-1].result == "denied"
        assert events[-1].resource == "<unresolved>"

    async def test_multi_segment_target_is_unresolvable(self, _a2a_setup: Any) -> None:
        """A slash-bearing target must not mint resources outside one agent name."""
        registry, engine, audit, transport, audit_dir = _a2a_setup
        agent = await registry.register(name="Coordinator", roles=["coordinator"])

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message("team/agent-003", {"task": "x"})
        transport.send.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[-1].resource == "<unresolved>"

    async def test_traversal_target_cannot_escape_agent_namespace(self, _a2a_setup: Any) -> None:
        """``../admin`` as a target must not escape the ``agent/`` namespace."""
        registry, engine, audit, transport, audit_dir = _a2a_setup
        agent = await registry.register(name="Coordinator", roles=["coordinator"])

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message("../admin", {"task": "x"})
        transport.send.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[-1].result == "denied"
        assert events[-1].resource == "<unresolved>"
        assert events[-1].action == "a2a:send:<unresolved>"

    async def test_interior_traversal_cannot_eat_namespace_prefix(self, _a2a_setup: Any) -> None:
        """``agent/../peer`` must not become ``peer`` and slip past ``deny agent/*``."""
        registry, _, audit, transport, audit_dir = _a2a_setup
        engine = RBACEngine(
            roles=[
                Role(
                    name="kill-switch",
                    permissions=[
                        Permission(action="*", resource="*", effect="allow"),
                        Permission(action="*", resource="agent/*", effect="deny"),
                    ],
                )
            ]
        )
        agent = await registry.register(name="Coordinator", roles=["kill-switch"])
        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message("../peer", {"task": "x"})
        transport.send.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[-1].resource == "<unresolved>"

    async def test_action_axis_case_variant_cannot_evade_deny(self, _a2a_setup: Any) -> None:
        """``Treasury-Agent`` must hit ``deny a2a:send:treasury-agent`` — the target is
        caller-controlled and is embedded in the action, so it is canonicalised too."""
        registry, _, audit, transport, audit_dir = _a2a_setup
        engine = RBACEngine(
            roles=[
                Role(
                    name="coordinator",
                    permissions=[
                        Permission(action="a2a:send:*", resource="*", effect="allow"),
                        Permission(action="a2a:send:treasury-agent", resource="*", effect="deny"),
                    ],
                )
            ]
        )
        agent = await registry.register(name="Coordinator", roles=["coordinator"])
        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message("Treasury-Agent", {"task": "x"})
        transport.send.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[-1].action == "a2a:send:treasury-agent"
        assert events[-1].resource == "agent/treasury-agent"

    @pytest.mark.parametrize(
        "target",
        ["./treasury-agent", "treasury-agent/", "treasury-agent/.", " treasury-agent "],
    )
    async def test_action_axis_path_variant_cannot_evade_deny(
        self, _a2a_setup: Any, target: str
    ) -> None:
        """Path-shape variants of the target must hit the same action-axis deny.

        The target is canonicalised ONCE and embedded in both the action and
        the resource; if each axis canonicalised independently, ``./peer``
        would carry a variant action string past an exact-action deny rule
        while the resource collapsed to the canonical form.
        """
        registry, _, audit, transport, audit_dir = _a2a_setup
        engine = RBACEngine(
            roles=[
                Role(
                    name="coordinator",
                    permissions=[
                        Permission(action="a2a:send:*", resource="*", effect="allow"),
                        Permission(action="a2a:send:treasury-agent", resource="*", effect="deny"),
                    ],
                )
            ]
        )
        agent = await registry.register(name="Coordinator", roles=["coordinator"])
        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message(target, {"task": "x"})
        transport.send.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[-1].action == "a2a:send:treasury-agent"
        assert events[-1].resource == "agent/treasury-agent"

    async def test_input_target_transform_recomputes_action_and_resource(
        self, _a2a_setup: Any
    ) -> None:
        """Authorization must use the transformed target, not the caller's original target."""
        registry, engine, audit, transport, audit_dir = _a2a_setup
        agent = await registry.register(name="Bot", roles=["coordinator", "restricted"])

        class _RetargetToSecret:
            id = "retarget-to-secret"
            version = "1"
            stages = frozenset({GuardrailStage.INPUT})

            async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
                assert isinstance(context.payload, MessagePayload)
                return GuardrailOutcome(
                    effect=GuardrailEffect.TRANSFORM,
                    reason_codes=("TEST.TARGET_TRANSFORMED",),
                    replacement_payload=MessagePayload(
                        target="secret-agent",
                        message=context.payload.message,
                    ),
                )

        client = GovernedA2AClient(
            transport=transport,
            agent_id=agent.agent_id,
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            guardrails=(_RetargetToSecret(),),
        )
        with pytest.raises(PermissionDeniedError):
            await client.send_message("agent-002", {"task": "benign"})

        transport.send.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[-1].action == "a2a:send:secret-agent"
        assert events[-1].resource == "agent/secret-agent"
