"""Tests for agentguard.compliance.engine — policy evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentguard.compliance.engine import PolicyEngine, PolicyRule, PolicySet
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext


def _make_event(
    action: str = "tool:credit_check",
    resource: str = "bureau/experian",
    result: str = "allowed",
    granted: bool = True,
    agent_metadata: dict[str, str] | None = None,
) -> AuditEvent:
    """Helper to create an AuditEvent for testing."""
    identity = AgentIdentity(
        agent_id="agent-1",
        name="Test Bot",
        roles=["credit-analyst"],
        metadata=agent_metadata or {},
    )
    return AuditEvent(
        event_id="evt-1",
        timestamp=datetime.now(UTC),
        agent_id="agent-1",
        action=action,
        resource=resource,
        permission_context=PermissionContext(
            agent=identity,
            requested_action=action,
            resource=resource,
            granted=granted,
            reason="test",
        ),
        result=result,
        duration_ms=5.0,
        trace_id="trace-1",
    )


class TestPolicyEngine:
    def test_loads_builtin_policies(self) -> None:
        engine = PolicyEngine()
        assert len(engine.policy_sets) == 3
        assert len(engine.all_rules) > 0

    def test_loads_custom_policy_dir(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "custom.yaml"
        policy_file.write_text(
            """
name: "Custom Policy"
version: "1.0"
rules:
  - id: CUSTOM-01
    name: Test Rule
    severity: medium
    description: A test rule
    check:
      type: action_blocklist
      patterns: ["tool:banned_.*"]
    remediation: Do not use banned tools.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        assert len(engine.policy_sets) == 1
        assert engine.all_rules[0].id == "CUSTOM-01"

    def test_empty_directory(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        assert len(engine.policy_sets) == 0

    def test_missing_directory(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path / "nonexistent"])
        assert len(engine.policy_sets) == 0

    async def test_evaluate_action_blocklist_pass(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-01
    name: Block dangerous actions
    severity: high
    description: test
    check:
      type: action_blocklist
      patterns: ["tool:exec_.*"]
    remediation: Do not use exec tools.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        event = _make_event(action="tool:credit_check")
        results = await engine.evaluate(event)
        assert len(results) == 1
        assert results[0].passed is True

    async def test_evaluate_action_blocklist_fail(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-01
    name: Block dangerous actions
    severity: high
    description: test
    check:
      type: action_blocklist
      patterns: ["tool:exec_.*"]
    remediation: Do not use exec tools.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        event = _make_event(action="tool:exec_command")
        results = await engine.evaluate(event)
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].evidence["matched_pattern"] == "tool:exec_.*"

    async def test_evaluate_resource_pattern(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-02
    name: Sensitive resource
    severity: critical
    description: test
    check:
      type: resource_pattern
      patterns: [".*pii.*"]
    remediation: Mask PII.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        event = _make_event(resource="data/pii/ssn")
        results = await engine.evaluate(event)
        assert results[0].passed is False

    async def test_evaluate_content_scan(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-03
    name: Prompt injection
    severity: critical
    description: test
    check:
      type: content_scan
      targets: [action, resource]
      patterns: ["ignore previous instructions"]
    remediation: Sanitize inputs.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        event = _make_event(resource="ignore previous instructions")
        results = await engine.evaluate(event)
        assert results[0].passed is False

    async def test_evaluate_permission_required(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-04
    name: Permission check
    severity: medium
    description: test
    check:
      type: permission_required
      require_granted: true
    remediation: Fix permissions.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        event = _make_event(granted=False, result="denied")
        results = await engine.evaluate(event)
        # Denied events pass the permission_required check (they were caught by RBAC)
        assert results[0].passed is True

    async def test_evaluate_metadata_required(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-05
    name: Metadata check
    severity: high
    description: test
    check:
      type: metadata_required
      required_fields: ["model_version"]
    remediation: Add model_version to metadata.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])

        # Missing metadata
        event = _make_event()
        results = await engine.evaluate(event)
        assert results[0].passed is False
        assert "model_version" in results[0].evidence["missing_fields"]

        # With metadata
        event2 = _make_event(agent_metadata={"model_version": "1.0"})
        results2 = await engine.evaluate(event2)
        assert results2[0].passed is True

    async def test_evaluate_result_required(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-06
    name: Result check
    severity: medium
    description: test
    check:
      type: result_required
      allowed_results: ["allowed", "denied"]
    remediation: Fix error handling.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        event = _make_event(result="error")
        results = await engine.evaluate(event)
        assert results[0].passed is False

    async def test_unknown_check_type_passes(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-07
    name: Unknown check
    severity: low
    description: test
    check:
      type: nonexistent_check
    remediation: N/A
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        event = _make_event()
        results = await engine.evaluate(event)
        assert results[0].passed is True

    async def test_disabled_rules_excluded(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-08
    name: Disabled rule
    severity: low
    description: test
    check:
      type: action_blocklist
      patterns: [".*"]
    remediation: N/A
    enabled: false
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        assert len(engine.all_rules) == 0


class TestPolicyRule:
    def test_rule_is_frozen(self) -> None:
        rule = PolicyRule(
            id="TEST-01",
            name="Test",
            severity="high",
            description="test",
            check={"type": "action_blocklist"},
            remediation="fix it",
        )
        with pytest.raises(Exception):
            rule.id = "MODIFIED"  # type: ignore[misc]


class TestPolicySet:
    def test_policy_set_creation(self) -> None:
        ps = PolicySet(
            name="Test Set",
            version="1.0",
            rules=[],
        )
        assert ps.name == "Test Set"
        assert len(ps.rules) == 0
