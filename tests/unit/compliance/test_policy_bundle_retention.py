"""Bounded policy-generation retention must fail attestation, never substitute."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 -- pytest resolves fixture annotations at runtime

import pytest

from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.reporter import ComplianceReporter
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.exceptions import AuditAttestationError
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext, PolicyResult

pytestmark = pytest.mark.usefixtures("_set_audit_key")


def _policy_document(*, rule_id: str, pattern: str) -> str:
    return f"""\
schema_version: 2
name: Retention
version: "1"
rules:
  - id: {rule_id}
    name: Block selected action
    severity: high
    description: Retention acceptance rule
    stage: pre_tool
    applies_to: all
    on_fail: deny
    check:
      type: action_blocklist
      patterns: ["{pattern}"]
    remediation: Use an approved action.
"""


def _write_policy(directory: Path, *, rule_id: str, pattern: str) -> None:
    (directory / "policy.yaml").write_text(_policy_document(rule_id=rule_id, pattern=pattern))


async def _generations(engine: PolicyEngine, directory: Path, count: int) -> list[str]:
    """Reload `count` distinct policy generations and return their versions."""

    versions = [engine.bundle_version]
    for index in range(count):
        _write_policy(directory, rule_id=f"GEN-{index:02d}", pattern=f"tool:gen{index}")
        await engine.reload()
        versions.append(engine.bundle_version)
    return versions


def _stamped_event(version: str, rule_id: str) -> AuditEvent:
    identity = AgentIdentity(agent_id="agent-1", name="Retention Bot", roles=["operator"])
    return AuditEvent(
        event_id="evt-retention",
        timestamp=datetime.now(UTC),
        agent_id="agent-1",
        action="tool:credit_check",
        resource="bureau/experian",
        permission_context=PermissionContext(
            agent=identity,
            requested_action="tool:credit_check",
            resource="bureau/experian",
            granted=True,
            reason="test",
        ),
        result="allowed",
        duration_ms=5.0,
        trace_id="trace-retention",
        policy_bundle_version=version,
        policy_results=[
            PolicyResult(
                rule_id=rule_id,
                rule_name="Block selected action",
                passed=True,
                severity="high",
                evidence={},
                remediation="Use an approved action.",
                effect="allow",
            )
        ],
    )


async def test_history_is_unbounded_by_default(tmp_path: Path) -> None:
    policies = tmp_path / "policies"
    policies.mkdir()
    _write_policy(policies, rule_id="GEN-INIT", pattern="tool:init")
    engine = PolicyEngine(policy_dirs=[policies])

    versions = await _generations(engine, policies, 4)

    assert all(engine.resolve_bundle(version) is not None for version in versions)


async def test_bounded_history_retains_the_current_and_most_recent_generations(
    tmp_path: Path,
) -> None:
    policies = tmp_path / "policies"
    policies.mkdir()
    _write_policy(policies, rule_id="GEN-INIT", pattern="tool:init")
    engine = PolicyEngine(policy_dirs=[policies], max_retained_generations=2)

    versions = await _generations(engine, policies, 4)

    assert engine.resolve_bundle(versions[0]) is None
    assert engine.resolve_bundle(versions[1]) is None
    assert [engine.resolve_bundle(version) is not None for version in versions[2:]] == [
        True,
        True,
        True,
    ]
    assert engine.resolve_bundle(engine.bundle_version) is not None


async def test_a_dropped_generation_fails_attestation_instead_of_substituting(
    tmp_path: Path,
) -> None:
    policies = tmp_path / "policies"
    policies.mkdir()
    _write_policy(policies, rule_id="GEN-INIT", pattern="tool:init")
    engine = PolicyEngine(policy_dirs=[policies], max_retained_generations=1)
    dropped_version = engine.bundle_version
    await _generations(engine, policies, 3)
    assert engine.resolve_bundle(dropped_version) is None

    log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_path / "audit"))
    await log.write(_stamped_event(dropped_version, "GEN-INIT"))

    with pytest.raises(AuditAttestationError, match="policy_provenance_unresolved"):
        await ComplianceReporter(engine).generate_report(log)


async def test_a_restored_snapshot_survives_a_bounded_history(tmp_path: Path) -> None:
    policies = tmp_path / "policies"
    policies.mkdir()
    _write_policy(policies, rule_id="GEN-INIT", pattern="tool:init")
    engine = PolicyEngine(policy_dirs=[policies], max_retained_generations=1)
    snapshot = engine.export_bundle(engine.snapshot())
    _write_policy(policies, rule_id="GEN-NEXT", pattern="tool:next")
    await engine.reload()

    restored = engine.restore_bundle(snapshot)

    assert engine.resolve_bundle(snapshot.version) is restored


def test_a_non_positive_retention_bound_is_rejected(tmp_path: Path) -> None:
    policies = tmp_path / "policies"
    policies.mkdir()
    _write_policy(policies, rule_id="GEN-INIT", pattern="tool:init")

    with pytest.raises(ValueError, match="max_retained_generations"):
        PolicyEngine(policy_dirs=[policies], max_retained_generations=0)
