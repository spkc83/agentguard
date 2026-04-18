"""Tests for `agentguard verify rbac` CLI with config file loading."""

from __future__ import annotations

from typing import TYPE_CHECKING

from typer.testing import CliRunner

from agentguard.cli import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def test_verify_rbac_no_config() -> None:
    """Without --config, CLI prints usage hint."""
    result = runner.invoke(app, ["verify", "rbac"])
    assert result.exit_code == 0
    assert "no rbac config" in result.output.lower()


def test_verify_rbac_missing_config(tmp_path: Path) -> None:
    """Missing file exits with code 1."""
    result = runner.invoke(
        app, ["verify", "rbac", "--config", str(tmp_path / "nonexistent.yaml")]
    )
    assert result.exit_code == 1


def test_verify_rbac_no_escalation(tmp_path: Path) -> None:
    """Without admin role, no other role grants the target — verified unsat."""
    config = tmp_path / "rbac.yaml"
    config.write_text(
        """
roles:
  - name: analyst
    permissions:
      - {action: "tool:read", resource: "data/*", effect: allow}
  - name: admin
    permissions:
      - {action: "tool:admin", resource: "admin/*", effect: allow}
target_permission:
  action: "tool:admin"
  resource: "admin/*"
forbidden_roles: ["admin"]
"""
    )
    result = runner.invoke(app, ["verify", "rbac", "--config", str(config)])
    assert result.exit_code == 0
    assert "RBAC verified" in result.output


def test_verify_rbac_escalation_detected(tmp_path: Path) -> None:
    """Two roles grant the target — forbidding one still leaves the other path. sat -> exit 1."""
    config = tmp_path / "rbac.yaml"
    config.write_text(
        """
roles:
  - name: analyst
    permissions:
      - {action: "tool:admin", resource: "admin/*", effect: allow}
  - name: admin
    permissions:
      - {action: "tool:admin", resource: "admin/*", effect: allow}
target_permission:
  action: "tool:admin"
  resource: "admin/*"
forbidden_roles: ["admin"]
"""
    )
    result = runner.invoke(app, ["verify", "rbac", "--config", str(config)])
    assert result.exit_code == 1
    assert "PRIVILEGE ESCALATION DETECTED" in result.output


def test_verify_rbac_target_not_present(tmp_path: Path) -> None:
    """Target permission not referenced by any role exits with error."""
    config = tmp_path / "rbac.yaml"
    config.write_text(
        """
roles:
  - name: analyst
    permissions:
      - {action: "tool:read", resource: "data/*", effect: allow}
target_permission:
  action: "tool:doesnotexist"
  resource: "nowhere/*"
forbidden_roles: ["analyst"]
"""
    )
    result = runner.invoke(app, ["verify", "rbac", "--config", str(config)])
    assert result.exit_code == 1
    assert "not referenced" in result.output.lower()


def test_verify_rbac_no_roles(tmp_path: Path) -> None:
    """Empty roles list prints no-roles warning."""
    config = tmp_path / "rbac.yaml"
    config.write_text("roles: []\n")
    result = runner.invoke(app, ["verify", "rbac", "--config", str(config)])
    assert result.exit_code == 0
    assert "no roles defined" in result.output.lower()
