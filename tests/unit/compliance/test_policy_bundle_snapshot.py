"""Restart-safe policy bundle snapshot tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agentguard.compliance.engine import (
    PolicyBundleSnapshot,
    PolicyEngine,
    PolicyRule,
)
from agentguard.exceptions import PolicyLoadError
from agentguard.models import AuditEvent, PolicyResult


def _write_policy(directory: Path, *, check_type: str = "action_blocklist") -> None:
    (directory / "snapshot.yaml").write_text(
        f"""\
schema_version: 2
name: Snapshot policy
version: "1"
rules:
  - id: SNAPSHOT-01
    name: Snapshot rule
    severity: high
    description: Snapshot restore acceptance rule
    stage: pre_tool
    applies_to: all
    on_fail: deny
    check:
      type: {check_type}
      patterns: ["tool:blocked"]
    remediation: Use an approved action.
"""
    )


def _custom_handler(rule: PolicyRule, event: AuditEvent) -> PolicyResult:
    return PolicyResult(
        rule_id=rule.id,
        rule_name=rule.name,
        passed=True,
        severity=rule.severity,
        evidence={"action": event.action},
        remediation=rule.remediation,
    )


def test_export_and_restore_bundle_across_engine_restart(tmp_path: Path) -> None:
    original_dir = tmp_path / "original"
    replacement_dir = tmp_path / "replacement"
    original_dir.mkdir()
    replacement_dir.mkdir()
    _write_policy(original_dir, check_type="snapshot_custom")
    _write_policy(replacement_dir)
    original = PolicyEngine(
        policy_dirs=[original_dir],
        extra_check_handlers={"snapshot_custom": _custom_handler},
    )
    restarted = PolicyEngine(
        policy_dirs=[replacement_dir],
        extra_check_handlers={"snapshot_custom": _custom_handler},
    )

    snapshot = original.export_bundle(original.current_bundle)
    restored = restarted.restore_bundle(snapshot)

    assert restored.version == original.current_bundle.version
    assert restored.policy_sets == snapshot.policy_sets
    assert restarted.resolve_bundle(snapshot.version) == restored
    assert restarted.current_bundle.version != restored.version


def test_restore_same_version_returns_snapshot_bundle_without_replacing_active(
    tmp_path: Path,
) -> None:
    _write_policy(tmp_path)
    engine = PolicyEngine(policy_dirs=[tmp_path])
    active = engine.current_bundle
    snapshot = engine.export_bundle(active)

    restored = engine.restore_bundle(snapshot)

    assert restored.policy_sets == snapshot.policy_sets
    assert restored is not active
    assert engine.current_bundle is active
    assert engine.resolve_bundle(snapshot.version) is restored


def test_restore_rejects_tampered_snapshot_and_preserves_active_bundle(
    tmp_path: Path,
) -> None:
    _write_policy(tmp_path)
    engine = PolicyEngine(policy_dirs=[tmp_path])
    active = engine.current_bundle
    exported = engine.export_bundle(active)
    payload = exported.model_dump(mode="json")
    payload["policy_sets"][0]["rules"][0]["name"] = "Tampered"
    tampered = PolicyBundleSnapshot.model_validate(payload)

    with pytest.raises(PolicyLoadError, match="version does not match"):
        engine.restore_bundle(tampered)

    assert engine.current_bundle == active
    assert engine.resolve_bundle(tampered.version) == active


def test_restore_rejects_unknown_handler_without_retaining_bundle(tmp_path: Path) -> None:
    custom_dir = tmp_path / "custom"
    replacement_dir = tmp_path / "replacement"
    custom_dir.mkdir()
    replacement_dir.mkdir()
    _write_policy(custom_dir, check_type="snapshot_custom")
    _write_policy(replacement_dir)
    source = PolicyEngine(
        policy_dirs=[custom_dir],
        extra_check_handlers={"snapshot_custom": _custom_handler},
    )
    restarted = PolicyEngine(policy_dirs=[replacement_dir])
    snapshot = source.export_bundle(source.current_bundle)

    with pytest.raises(PolicyLoadError, match="unknown check type 'snapshot_custom'"):
        restarted.restore_bundle(snapshot)

    assert restarted.resolve_bundle(snapshot.version) is None


def test_restore_rejects_noncanonical_policy_set_order(tmp_path: Path) -> None:
    _write_policy(tmp_path)
    (tmp_path / "second.yaml").write_text(
        (tmp_path / "snapshot.yaml")
        .read_text()
        .replace("Snapshot policy", "Second policy")
        .replace("SNAPSHOT-01", "SNAPSHOT-02")
    )
    engine = PolicyEngine(policy_dirs=[tmp_path])
    snapshot = engine.export_bundle(engine.current_bundle)
    reversed_sets = tuple(reversed(snapshot.policy_sets))
    forged = PolicyBundleSnapshot(
        version=engine._bundle_digest(reversed_sets),
        policy_sets=reversed_sets,
    )

    with pytest.raises(PolicyLoadError, match="version does not match"):
        engine.restore_bundle(forged)


def test_snapshot_is_frozen_and_rejects_unknown_fields(tmp_path: Path) -> None:
    _write_policy(tmp_path)
    engine = PolicyEngine(policy_dirs=[tmp_path])
    snapshot = engine.export_bundle(engine.current_bundle)

    with pytest.raises(ValidationError, match="frozen"):
        snapshot.version = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="frozen"):
        snapshot.policy_sets[0].name = "Changed"
    with pytest.raises(ValidationError, match="extra"):
        PolicyBundleSnapshot.model_validate(
            {**snapshot.model_dump(mode="json"), "unexpected": True}
        )
    payload = snapshot.model_dump(mode="json")
    payload["policy_sets"][0]["unexpected"] = True
    with pytest.raises(ValidationError, match="extra"):
        PolicyBundleSnapshot.model_validate(payload)
