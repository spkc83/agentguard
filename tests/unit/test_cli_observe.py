"""Tests for `agentguard observe ...` CLI commands (dashboard, replay, summary)."""

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
    identity = AgentIdentity(agent_id="obs-agent", name="Observe Test", roles=["analyst"])
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
                agent_id="obs-agent",
                action=f"tool:action_{i % 2}",
                resource=f"res-{i}",
                permission_context=ctx,
                result="allowed" if i % 2 == 0 else "denied",
                duration_ms=float(i * 10 + 1),
                trace_id=str(uuid.uuid4()),
            )
            await log.write(event)

    asyncio.run(_inner())


@pytest.mark.usefixtures("_set_audit_key")
def test_dashboard_markdown(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=4)
    result = runner.invoke(app, ["observe", "dashboard", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "AgentGuard Dashboard" in result.output
    assert "Events analyzed" in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_dashboard_json(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=3)
    result = runner.invoke(
        app,
        ["observe", "dashboard", "--log-dir", str(log_dir), "--output-format", "json"],
    )
    assert result.exit_code == 0
    assert '"total_events"' in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_observe_replay_filtered(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=4)
    result = runner.invoke(
        app,
        ["observe", "replay", "--log-dir", str(log_dir), "--result", "denied"],
    )
    assert result.exit_code == 0
    assert "DENIED" in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_observe_replay_no_match(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=2)
    result = runner.invoke(
        app,
        ["observe", "replay", "--log-dir", str(log_dir), "--agent-id", "nonexistent"],
    )
    assert result.exit_code == 0
    assert "no events match" in result.output.lower()


@pytest.mark.usefixtures("_set_audit_key")
def test_observe_summary(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=4)
    result = runner.invoke(app, ["observe", "summary", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "Total events" in result.output
    assert "By result" in result.output
