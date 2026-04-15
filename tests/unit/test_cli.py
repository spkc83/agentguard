"""Tests for the AgentGuard CLI."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext

runner = CliRunner()


def test_help() -> None:
    """CLI --help exits cleanly."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "governance" in result.output.lower()


def test_audit_help() -> None:
    """Audit subcommand --help exits cleanly."""
    result = runner.invoke(app, ["audit", "--help"])
    assert result.exit_code == 0
    assert "show" in result.output.lower()
    assert "verify" in result.output.lower()


@pytest.mark.usefixtures("_set_audit_key")
def test_audit_show_empty(tmp_path: Path) -> None:
    """Audit show with empty directory prints no-events message."""
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    result = runner.invoke(app, ["audit", "show", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "no audit events" in result.output.lower()


@pytest.mark.usefixtures("_set_audit_key")
def test_audit_verify_empty(tmp_path: Path) -> None:
    """Audit verify on empty directory succeeds with 0 events."""
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    result = runner.invoke(app, ["audit", "verify", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "verified" in result.output.lower()


def test_policy_validate() -> None:
    """Policy validate loads built-in rules and shows table."""
    result = runner.invoke(app, ["policy", "validate"])
    assert result.exit_code == 0
    assert "rule" in result.output.lower()


def test_verify_rbac() -> None:
    """Verify rbac without config shows usage message."""
    result = runner.invoke(app, ["verify", "rbac"])
    assert result.exit_code == 0
    assert "config" in result.output.lower()


def _write_events(log_dir: Path, count: int = 3) -> None:
    """Helper: write audit events to a log directory."""
    identity = AgentIdentity(agent_id="cli-test-agent", name="CLI Test", roles=["readonly"])
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
                agent_id="cli-test-agent",
                action="tool:test",
                resource=f"res-{i}",
                permission_context=ctx,
                result="allowed",
                duration_ms=1.0,
                trace_id=str(uuid.uuid4()),
            )
            await log.write(event)

    asyncio.run(_inner())


@pytest.mark.usefixtures("_set_audit_key")
def test_audit_show_with_events(tmp_path: Path) -> None:
    """Audit show renders a table when events exist."""
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=3)
    result = runner.invoke(app, ["audit", "show", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "3 total" in result.output
    assert "tool:test" in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_audit_show_filter_by_agent(tmp_path: Path) -> None:
    """Audit show --agent-id filters correctly."""
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=2)
    result = runner.invoke(
        app, ["audit", "show", "--log-dir", str(log_dir), "--agent-id", "nonexistent"]
    )
    assert result.exit_code == 0
    assert "no audit events" in result.output.lower()


@pytest.mark.usefixtures("_set_audit_key")
def test_audit_verify_with_events(tmp_path: Path) -> None:
    """Audit verify succeeds on valid chain."""
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=5)
    result = runner.invoke(app, ["audit", "verify", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "verified" in result.output.lower()
    assert "5 events" in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_audit_verify_detects_tampering(tmp_path: Path) -> None:
    """Audit verify exits with code 1 on tampered log."""
    import json

    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _write_events(log_dir, count=3)

    # Tamper with the log
    log_files = list(log_dir.glob("*.jsonl"))
    assert len(log_files) == 1
    lines = log_files[0].read_text().strip().split("\n")
    tampered = json.loads(lines[1])
    tampered["action"] = "tool:HACKED"
    lines[1] = json.dumps(tampered)
    log_files[0].write_text("\n".join(lines) + "\n")

    result = runner.invoke(app, ["audit", "verify", "--log-dir", str(log_dir)])
    assert result.exit_code == 1
    assert "tamper" in result.output.lower()
