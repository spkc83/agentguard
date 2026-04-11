"""Tests for the AgentGuard CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli import app

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
    """Policy validate placeholder."""
    result = runner.invoke(app, ["policy", "validate"])
    assert result.exit_code == 0
    assert "v0.3.0" in result.output


def test_verify_rbac() -> None:
    """Verify rbac placeholder."""
    result = runner.invoke(app, ["verify", "rbac"])
    assert result.exit_code == 0
    assert "v0.3.0" in result.output
