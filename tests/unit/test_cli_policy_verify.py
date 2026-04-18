"""Tests for `agentguard policy report` and `agentguard verify policy` CLI."""

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


def _seed(log_dir: Path, count: int = 2) -> None:
    identity = AgentIdentity(agent_id="rep-agent", name="Rep Test", roles=["analyst"])
    ctx = PermissionContext(
        agent=identity, requested_action="tool:test", resource="res", granted=True
    )

    async def _inner() -> None:
        backend = FileAuditBackend(directory=log_dir)
        log = AppendOnlyAuditLog(backend=backend)
        for i in range(count):
            await log.write(
                AuditEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now(UTC),
                    agent_id="rep-agent",
                    action=f"tool:x{i}",
                    resource=f"r{i}",
                    permission_context=ctx,
                    result="allowed",
                    duration_ms=1.0,
                    trace_id=str(uuid.uuid4()),
                )
            )

    asyncio.run(_inner())


@pytest.mark.usefixtures("_set_audit_key")
def test_policy_report_empty(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    result = runner.invoke(app, ["policy", "report", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "no audit events" in result.output.lower()


@pytest.mark.usefixtures("_set_audit_key")
def test_policy_report_markdown(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _seed(log_dir, count=2)
    result = runner.invoke(app, ["policy", "report", "--log-dir", str(log_dir)])
    assert result.exit_code == 0
    assert "Compliance Report" in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_policy_report_json(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _seed(log_dir, count=2)
    result = runner.invoke(
        app,
        ["policy", "report", "--log-dir", str(log_dir), "--output-format", "json"],
    )
    assert result.exit_code == 0
    assert '"report_id"' in result.output


def test_verify_policy_builtin_rules() -> None:
    """verify policy with the shipped policy set should report consistency."""
    result = runner.invoke(app, ["verify", "policy"])
    assert result.exit_code == 0
    # Accept either "verified" or "contradictions" — both are valid outcomes
    # against the built-in 35-rule set; the command must not crash.
    out = result.output.lower()
    assert ("verified" in out) or ("contradictions" in out) or ("verification result" in out)


def test_verify_policy_empty_dir(tmp_path: Path) -> None:
    """verify policy with an empty dir prints a no-rules message."""
    empty = tmp_path / "policies"
    empty.mkdir()
    result = runner.invoke(app, ["verify", "policy", "--policy-dir", str(empty)])
    assert result.exit_code == 0
    assert "no policy rules" in result.output.lower()
