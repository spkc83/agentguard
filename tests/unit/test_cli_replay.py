"""Tests for CLI audit replay command."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def _write_events(log_dir: Path, count: int = 3) -> None:
    identity = AgentIdentity(agent_id="replay-agent", name="Replay Test", roles=["readonly"])
    ctx = PermissionContext(
        agent=identity, requested_action="tool:test", resource="res", granted=True
    )

    async def _inner() -> None:
        backend = FileAuditBackend(directory=log_dir)
        log = AppendOnlyAuditLog(backend=backend)
        for i in range(count):
            event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(UTC),
                agent_id="replay-agent",
                action=f"tool:action_{i}",
                resource=f"res-{i}",
                permission_context=ctx,
                result="allowed" if i % 2 == 0 else "denied",
                duration_ms=float(i * 10),
                trace_id=str(uuid.uuid4()),
            )
            await log.write(event)

    asyncio.run(_inner())


@pytest.mark.usefixtures("_set_audit_key")
def test_replay_shows_events(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=3)
    result = runner.invoke(app, ["audit", "replay", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "tool:action_0" in result.output
    assert "tool:action_1" in result.output
    assert "tool:action_2" in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_replay_empty_log(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    result = runner.invoke(app, ["audit", "replay", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "no audit events" in result.output.lower()


@pytest.mark.usefixtures("_set_audit_key")
def test_replay_shows_result_and_agent(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=2)
    result = runner.invoke(app, ["audit", "replay", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "replay-agent" in result.output
    assert "Event 1/" in result.output
