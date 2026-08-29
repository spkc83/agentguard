"""CLI `verify` commands must degrade gracefully when the `verify` extra is absent.

Deliberately NOT gated by ``pytest.importorskip("z3")`` — these tests describe the
z3-free environment and must run in it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from typer.testing import CliRunner

from agentguard.cli import app

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

runner = CliRunner()


def _flat(text: str) -> str:
    """Collapse rich console wrapping so substring assertions are stable."""
    return " ".join(text.lower().split())


def _break_z3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate z3-solver not being installed (it is an optional extra)."""

    def _raise() -> None:
        raise ImportError(
            "z3-solver is required for formal verification. Install with: pip install z3-solver"
        )

    monkeypatch.setattr("agentguard.compliance.z3_models._import_z3", _raise)


def test_verify_rbac_without_z3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the verify extra, `verify rbac` exits 1 with an install hint."""
    _break_z3(monkeypatch)
    config = tmp_path / "rbac.yaml"
    config.write_text(
        """
roles:
  - name: analyst
    permissions:
      - {action: "tool:admin", resource: "admin/*", effect: allow}
target_permission:
  action: "tool:admin"
  resource: "admin/*"
forbidden_roles: ["analyst"]
"""
    )
    result = runner.invoke(app, ["verify", "rbac", "--config", str(config)])
    assert result.exit_code == 1
    out = _flat(result.output)
    assert "z3-solver is required" in out
    assert "pip install 'agentguard[verify]'" in out


def test_verify_policy_without_z3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Policy checks are explicitly unsupported, independent of the optional verifier extra."""
    _break_z3(monkeypatch)
    result = runner.invoke(app, ["verify", "policy"])
    assert result.exit_code == 2
    out = _flat(result.output)
    assert "unsupported" in out
    assert "severity" in out
