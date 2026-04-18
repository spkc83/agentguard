"""Tests for agentguard.integrations._pipeline — shared governance pipeline.

Covers the error-event logging contract that applies to all adapters.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations._pipeline import run_governed

if TYPE_CHECKING:
    from pathlib import Path


def _build_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="user",
                permissions=[
                    Permission(action="tool:*", resource="allowed/*", effect="allow"),
                    Permission(action="tool:*", resource="blocked/*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _pipeline_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, Path]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-pipeline")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    engine = _build_engine()
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    return registry, engine, audit, audit_dir


class TestPipeline:
    async def test_success_path_writes_one_allowed_event(
        self, _pipeline_setup: Any
    ) -> None:
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        result = await run_governed(
            agent_id=agent.agent_id,
            action="tool:test",
            resource="allowed/x",
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            executor=executor,
        )
        assert result == "ok"
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "allowed"

    async def test_deny_path_writes_denied_event_and_raises(
        self, _pipeline_setup: Any
    ) -> None:
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        with pytest.raises(PermissionDeniedError):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="blocked/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )
        executor.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"

    async def test_executor_exception_writes_error_event(
        self, _pipeline_setup: Any
    ) -> None:
        """Per ADR-004: if execution fails, a follow-up error event must be written."""
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(side_effect=RuntimeError("downstream failure"))

        with pytest.raises(RuntimeError, match="downstream failure"):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="allowed/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 2
        assert events[0].result == "allowed"
        assert events[1].result == "error"
        # Error event should have non-zero duration (measured)
        assert events[1].duration_ms >= 0.0
        # Pre-event and error-event must share the same trace_id
        assert events[0].trace_id == events[1].trace_id

    async def test_tracer_invoked_when_provided(self, _pipeline_setup: Any) -> None:
        registry, engine, audit, _ = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        # Fake tracer that records span invocations
        span_calls: list[tuple[str, dict[str, Any] | None]] = []

        class _FakeTracer:
            def span(self, name: str, attributes: dict[str, Any] | None = None) -> Any:
                span_calls.append((name, attributes))
                from contextlib import nullcontext

                return nullcontext()

        await run_governed(
            agent_id=agent.agent_id,
            action="tool:test",
            resource="allowed/x",
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            executor=executor,
            tracer=_FakeTracer(),
        )
        assert len(span_calls) == 1
        assert span_calls[0][0] == "agentguard.tool_call"
        attrs = span_calls[0][1]
        assert attrs is not None
        assert attrs["action"] == "tool:test"
        assert attrs["resource"] == "allowed/x"

    async def test_audit_events_chain_on_error(self, _pipeline_setup: Any) -> None:
        """Error event must link into the HMAC chain with the preceding pre-event."""
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(side_effect=ValueError("boom"))

        with pytest.raises(ValueError, match="boom"):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="allowed/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )

        # Verify chain integrity after error event
        verification = await audit.verify_chain()
        assert verification.valid
        assert verification.event_count == 2
