"""Tests for `agentguard policy report` and `agentguard verify policy` CLI."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.core.audit import AppendOnlyAuditLog, AuditCheckpoint, FileAuditBackend
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext

if TYPE_CHECKING:
    from pathlib import Path

pytest.importorskip("z3")

runner = CliRunner()


def _seed(log_dir: Path, count: int = 2) -> Path:
    identity = AgentIdentity(agent_id="rep-agent", name="Rep Test", roles=["analyst"])
    ctx = PermissionContext(
        agent=identity, requested_action="tool:test", resource="res", granted=True
    )

    async def _inner() -> AuditCheckpoint:
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
        checkpoint = await log.export_checkpoint()
        assert checkpoint is not None
        return checkpoint

    checkpoint = asyncio.run(_inner())
    trusted_path = log_dir.parent / f"{log_dir.name}-trusted-head.json"
    trusted_path.write_text(checkpoint.model_dump_json())
    return trusted_path


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
    trusted = _seed(log_dir, count=2)
    result = runner.invoke(
        app,
        [
            "policy",
            "report",
            "--log-dir",
            str(log_dir),
            "--trusted-checkpoint",
            str(trusted),
        ],
    )
    assert result.exit_code == 0
    assert "Compliance Report" in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_policy_report_json(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    trusted = _seed(log_dir, count=2)
    result = runner.invoke(
        app,
        [
            "policy",
            "report",
            "--log-dir",
            str(log_dir),
            "--output-format",
            "json",
            "--trusted-checkpoint",
            str(trusted),
        ],
    )
    assert result.exit_code == 0
    assert '"report_id"' in result.output


@pytest.mark.usefixtures("_set_audit_key")
def test_policy_report_refuses_unanchored_local_checkpoint(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    _seed(log_dir, count=1)

    result = runner.invoke(app, ["policy", "report", "--log-dir", str(log_dir)])

    assert result.exit_code == 1
    assert "verified_unanchored" in result.output


def test_verify_policy_builtin_rules() -> None:
    """verify policy never fabricates authorization effects from severity."""
    result = runner.invoke(app, ["verify", "policy"])
    assert result.exit_code == 2
    assert "unsupported" in result.output.lower()
    assert "severity" in result.output.lower()


def test_verify_policy_empty_dir(tmp_path: Path) -> None:
    """verify policy with an empty dir prints a no-rules message."""
    empty = tmp_path / "policies"
    empty.mkdir()
    result = runner.invoke(app, ["verify", "policy", "--policy-dir", str(empty)])
    assert result.exit_code == 0
    assert "no policy rules" in result.output.lower()


def test_verify_rbac_unknown_is_non_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "rbac.yaml"
    config.write_text(
        """
roles:
  - name: analyst
    permissions:
      - {action: 'tool:read', resource: 'data/*', effect: allow}
target_permission: {action: 'tool:read', resource: 'data/*'}
"""
    )
    from agentguard.compliance.formal_verifier import FormalVerifier, VerificationResult

    monkeypatch.setattr(
        FormalVerifier,
        "verify_rbac_escalation",
        lambda *_args, **_kwargs: VerificationResult(
            property_name="RBAC", status="unknown", details={"reason": "unsupported"}
        ),
    )
    result = runner.invoke(app, ["verify", "rbac", "--config", str(config)])
    assert result.exit_code == 2
    assert "unknown" in result.output.lower()


def test_verify_rbac_preserves_inherited_roles(tmp_path: Path) -> None:
    config = tmp_path / "rbac-inheritance.yaml"
    config.write_text(
        """
roles:
  - name: base
    permissions:
      - {action: 'tool:admin', resource: 'admin/*', effect: allow}
  - name: analyst
    inherited_roles: [base]
    permissions: []
  - name: target-catalog
    permissions:
      - {action: 'tool:admin', resource: 'admin/*', effect: deny}
target_permission: {action: 'tool:admin', resource: 'admin/*'}
forbidden_roles: [base, target-catalog]
"""
    )

    result = runner.invoke(app, ["verify", "rbac", "--config", str(config)])

    assert result.exit_code == 1
    assert "privilege escalation detected" in result.output.lower()
