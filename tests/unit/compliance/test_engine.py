"""Tests for agentguard.compliance.engine — policy evaluation."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import pytest

from agentguard.compliance.engine import PolicyEngine, PolicyRule, PolicySet
from agentguard.exceptions import PolicyLoadError
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext, PolicyResult


def _make_event(
    action: str = "tool:credit_check",
    resource: str = "bureau/experian",
    result: Literal["allowed", "denied", "escalated", "rejected", "error"] = "allowed",
    granted: bool = True,
    agent_metadata: dict[str, str] | None = None,
    context: dict[str, Any] | None = None,
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
            context=context or {},
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

    def test_unknown_check_type_fails_to_load(self, tmp_path: Path) -> None:
        """Fail-safe: a typo'd check type must block at load, never silently pass."""
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
        with pytest.raises(PolicyLoadError) as exc_info:
            PolicyEngine(policy_dirs=[tmp_path])
        message = str(exc_info.value)
        assert "TEST-07" in message
        assert "nonexistent_check" in message
        assert "unknown check type" in message

    def test_missing_check_type_fails_to_load(self, tmp_path: Path) -> None:
        """A rule with no check.type at all is also a load-time failure."""
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-07B
    name: No check type
    severity: low
    description: test
    check: {}
    remediation: N/A
"""
        )
        with pytest.raises(PolicyLoadError):
            PolicyEngine(policy_dirs=[tmp_path])

    async def test_extra_check_handler_loads_and_evaluates(self, tmp_path: Path) -> None:
        """A custom check type registered via extra_check_handlers loads and runs."""
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test"
version: "1.0"
rules:
  - id: TEST-CUSTOM
    name: Custom check
    severity: critical
    description: test
    check:
      type: my_custom_check
    remediation: Implement the control.
"""
        )

        def _always_fails(rule: PolicyRule, event: AuditEvent) -> PolicyResult:
            return PolicyResult(
                rule_id=rule.id,
                rule_name=rule.name,
                passed=False,
                severity=rule.severity,
                evidence={"custom": event.action},
                remediation=rule.remediation,
            )

        engine = PolicyEngine(
            policy_dirs=[tmp_path],
            extra_check_handlers={"my_custom_check": _always_fails},
        )
        assert len(engine.all_rules) == 1

        results = await engine.evaluate(_make_event(action="tool:custom"))
        assert len(results) == 1
        assert results[0].rule_id == "TEST-CUSTOM"
        assert results[0].passed is False
        assert results[0].evidence == {"custom": "tool:custom"}

    async def test_legacy_evaluate_does_not_apply_runtime_effects(self, tmp_path: Path) -> None:
        """Legacy evaluation remains an all-rules attestation API."""
        (tmp_path / "legacy.yaml").write_text(
            """
name: Legacy
version: "1"
rules:
  - id: LEGACY-01
    name: Legacy failure
    severity: high
    description: test
    check:
      type: action_blocklist
      patterns: ["tool:blocked"]
    remediation: fix
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])

        results = await engine.evaluate(_make_event(action="tool:blocked"))

        assert results[0].passed is False
        assert results[0].effect is None

    async def test_evaluate_stage_filters_and_normalizes_effects(self, tmp_path: Path) -> None:
        calls: list[str] = []
        (tmp_path / "staged.yaml").write_text(
            """
name: Staged
version: "1"
rules:
  - id: STAGE-01
    name: Matching rule
    severity: high
    description: test
    stage: pre_tool
    applies_to:
      action: ["TOOL:CREDIT_*"]
      resource: ["BUREAU/*"]
    on_fail: deny
    check: {type: custom}
    remediation: fix
  - id: STAGE-02
    name: Other stage
    severity: low
    description: test
    stage: post_tool
    check: {type: custom}
    remediation: fix
  - id: STAGE-03
    name: Nonmatching action
    severity: low
    description: test
    stage: pre_tool
    applies_to: {action: ["tool:other"]}
    check: {type: custom}
    remediation: fix
"""
        )

        def _custom(rule: PolicyRule, event: AuditEvent) -> PolicyResult:
            calls.append(rule.id)
            return PolicyResult(
                rule_id=rule.id,
                rule_name=rule.name,
                passed=False,
                severity=rule.severity,
                evidence={"action": event.action},
                remediation=rule.remediation,
            )

        engine = PolicyEngine(policy_dirs=[tmp_path], extra_check_handlers={"custom": _custom})
        results = await engine.evaluate_stage(
            _make_event(action="tool:credit_check", resource="bureau/experian"),
            "pre_tool",
        )

        assert calls == ["STAGE-01"]
        assert [result.effect for result in results] == ["deny"]

    async def test_evaluate_stage_pass_effect_is_allow(self, tmp_path: Path) -> None:
        (tmp_path / "pass.yml").write_text(
            """
name: Staged
version: "1"
rules:
  - id: STAGE-PASS
    name: Passing rule
    severity: low
    description: test
    stage: pre_tool
    on_fail: escalate
    check: {type: action_blocklist, patterns: ["blocked"]}
    remediation: fix
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])

        results = await engine.evaluate_stage(_make_event(action="safe"), "pre_tool")

        assert results[0].passed is True
        assert results[0].effect == "allow"

    async def test_runtime_handler_exception_propagates(self, tmp_path: Path) -> None:
        (tmp_path / "raising.yaml").write_text(
            """
name: Raising
version: "1"
rules:
  - id: RAISE-01
    name: Raising rule
    severity: high
    description: test
    stage: pre_tool
    check: {type: raising}
    remediation: fix
"""
        )

        def _raise(rule: PolicyRule, event: AuditEvent) -> PolicyResult:
            raise RuntimeError(f"{rule.id}:{event.action}")

        engine = PolicyEngine(policy_dirs=[tmp_path], extra_check_handlers={"raising": _raise})
        with pytest.raises(RuntimeError, match="RAISE-01:tool:credit_check"):
            await engine.evaluate_stage(_make_event(), "pre_tool")

    async def test_runtime_handler_timeout_does_not_block_event_loop(self, tmp_path: Path) -> None:
        (tmp_path / "blocking.yaml").write_text(
            """
name: Blocking
version: "1"
rules:
  - id: BLOCK-01
    name: Blocking rule
    severity: high
    description: test
    stage: pre_tool
    check: {type: blocking}
    remediation: fix
"""
        )
        release = threading.Event()

        def _block(rule: PolicyRule, event: AuditEvent) -> PolicyResult:
            release.wait(timeout=1)
            return PolicyResult(
                rule_id=rule.id,
                rule_name=rule.name,
                passed=True,
                severity=rule.severity,
                evidence={"action": event.action},
                remediation=rule.remediation,
            )

        engine = PolicyEngine(
            policy_dirs=[tmp_path],
            extra_check_handlers={"blocking": _block},
            runtime_timeout_seconds=0.01,
        )
        heartbeat = asyncio.create_task(asyncio.sleep(0))
        try:
            with pytest.raises(TimeoutError):
                await engine.evaluate_stage(_make_event(), "pre_tool")
            assert heartbeat.done()
        finally:
            release.set()
            await heartbeat

    @pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
    def test_runtime_timeout_must_be_positive_and_finite(self, timeout: float) -> None:
        with pytest.raises(ValueError, match="runtime_timeout_seconds"):
            PolicyEngine(policy_dirs=[], runtime_timeout_seconds=timeout)

    async def test_content_scan_uses_actual_tool_args_and_result(self, tmp_path: Path) -> None:
        (tmp_path / "content.yaml").write_text(
            """
name: Content
version: "1"
rules:
  - id: ARGS-01
    name: Args scan
    severity: high
    description: test
    stage: pre_tool
    check:
      type: content_scan
      targets: [tool_args]
      patterns: ["ignore previous instructions"]
    remediation: fix
  - id: RESULT-01
    name: Result scan
    severity: high
    description: test
    stage: post_tool
    check:
      type: content_scan
      targets: [tool_result]
      patterns: ["<script"]
    remediation: fix
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])

        args_results = await engine.evaluate_stage(
            _make_event(context={"tool_args": {"prompt": "ignore previous instructions"}}),
            "pre_tool",
        )
        result_results = await engine.evaluate_stage(
            _make_event(context={"tool_result": {"body": "<script>alert(1)"}}),
            "post_tool",
        )

        assert args_results[0].passed is False
        assert result_results[0].passed is False

    def test_load_errors_include_file_and_rule_detail(self, tmp_path: Path) -> None:
        bad_syntax = tmp_path / "syntax.yaml"
        bad_syntax.write_text("rules: [")
        with pytest.raises(PolicyLoadError) as syntax_error:
            PolicyEngine(policy_dirs=[tmp_path])
        assert str(bad_syntax) in str(syntax_error.value)
        assert "YAML syntax error" in str(syntax_error.value)

        bad_syntax.unlink()
        invalid = tmp_path / "invalid.yaml"
        invalid.write_text(
            """
rules:
  - id: invalid/id
    name: Invalid
    severity: medium
    description: test
    check: {type: action_blocklist}
    remediation: fix
"""
        )
        with pytest.raises(PolicyLoadError) as validation_error:
            PolicyEngine(policy_dirs=[tmp_path])
        message = str(validation_error.value)
        assert str(invalid) in message
        assert "invalid/id" in message
        assert "validation error" in message

    @pytest.mark.parametrize(
        "rule_fields",
        [
            "stage: during_tool",
            "on_fail: allow",
            "applies_to: {action: []}",
            "applies_to: {unknown: ['*']}",
            "effect: deny\n    on_fail: warn",
        ],
    )
    def test_invalid_runtime_schema_rejected(self, tmp_path: Path, rule_fields: str) -> None:
        (tmp_path / "invalid.yaml").write_text(
            f"""
rules:
  - id: VALID-ID
    name: Invalid
    severity: medium
    description: test
    {rule_fields}
    check: {{type: action_blocklist}}
    remediation: fix
"""
        )
        with pytest.raises(PolicyLoadError, match="VALID-ID.*validation error"):
            PolicyEngine(policy_dirs=[tmp_path])

    def test_deprecated_effect_alias_is_accepted(self, tmp_path: Path) -> None:
        (tmp_path / "alias.yaml").write_text(
            """
rules:
  - id: ALIAS-01
    name: Alias
    severity: medium
    description: test
    effect: escalate
    check: {type: action_blocklist}
    remediation: fix
"""
        )
        rule = PolicyEngine(policy_dirs=[tmp_path]).all_rules[0]
        assert rule.on_fail == "escalate"

    @pytest.mark.parametrize("missing_field", ["stage", "applies_to", "on_fail"])
    def test_schema_v2_requires_explicit_runtime_fields(
        self, tmp_path: Path, missing_field: str
    ) -> None:
        fields = {
            "stage": "stage: pre_tool",
            "applies_to": "applies_to: all",
            "on_fail": "on_fail: warn",
        }
        fields.pop(missing_field)
        (tmp_path / "v2.yaml").write_text(
            "\n".join(
                [
                    "schema_version: 2",
                    "name: Strict",
                    'version: "1"',
                    "rules:",
                    "  - id: STRICT-01",
                    "    name: Strict rule",
                    "    severity: high",
                    "    description: test",
                    *(f"    {field}" for field in fields.values()),
                    "    check: {type: action_blocklist}",
                    "    remediation: fix",
                ]
            )
        )

        with pytest.raises(PolicyLoadError, match=f"STRICT-01.*{missing_field}"):
            PolicyEngine(policy_dirs=[tmp_path])

    def test_unknown_policy_schema_version_is_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "future.yaml").write_text("schema_version: 99\nrules: []\n")

        with pytest.raises(PolicyLoadError, match="unsupported policy schema_version 99"):
            PolicyEngine(policy_dirs=[tmp_path])

    def test_builtin_runtime_policy_table(self) -> None:
        engine = PolicyEngine()
        assert {policy_set.schema_version for policy_set in engine.policy_sets} == {2}
        by_id = {rule.id: (rule.stage, rule.on_fail) for rule in engine.all_rules}
        assert len(by_id) == 35

        pre_tool_ids = {
            "OWASP-AGENT-01",
            "OWASP-AGENT-02",
            "OWASP-AGENT-03",
            "OWASP-AGENT-04",
            "OWASP-AGENT-05",
            "OWASP-AGENT-06",
            "OWASP-AGENT-07",
            "OWASP-AGENT-08",
            "AG-FINOS-005",
            "AG-FINOS-012",
            "AG-FINOS-015",
            "AG-FINOS-025",
            "AG-FINOS-040",
            "EU-AI-ACT-ART14-01",
        }
        assert {
            rule_id for rule_id, (stage, _) in by_id.items() if stage == "pre_tool"
        } == pre_tool_ids
        assert {rule_id for rule_id, (stage, _) in by_id.items() if stage == "post_tool"} == {
            "OWASP-AGENT-09"
        }

        assert {rule_id for rule_id, (_, effect) in by_id.items() if effect == "deny"} == {
            "OWASP-AGENT-01",
            "OWASP-AGENT-06",
            "OWASP-AGENT-09",
        }
        assert {rule_id for rule_id, (_, effect) in by_id.items() if effect == "escalate"} == {
            "AG-FINOS-005",
            "AG-FINOS-025",
            "EU-AI-ACT-ART14-01",
        }
        assert sum(stage == "attestation" for stage, _ in by_id.values()) == 20
        assert sum(effect == "warn" for _, effect in by_id.values()) == 29
        assert by_id["OWASP-AGENT-09"] == ("post_tool", "deny")

    async def test_builtin_runtime_scans_transient_args_and_result(self) -> None:
        engine = PolicyEngine()

        pre_results = await engine.evaluate_stage(
            _make_event(
                action="tool:search",
                context={"tool_args": {"query": "ignore previous instructions"}},
            ),
            "pre_tool",
        )
        post_results = await engine.evaluate_stage(
            _make_event(
                action="tool:search",
                context={"tool_result": {"html": "<script>alert(1)</script>"}},
            ),
            "post_tool",
        )

        pre_by_id = {result.rule_id: result for result in pre_results}
        assert pre_by_id["OWASP-AGENT-01"].passed is False
        assert pre_by_id["OWASP-AGENT-01"].effect == "deny"
        assert post_results[0].rule_id == "OWASP-AGENT-09"
        assert post_results[0].passed is False
        assert post_results[0].effect == "deny"

    def test_builtin_policies_still_load(self) -> None:
        """The shipped policy set must remain loadable under the strict check."""
        engine = PolicyEngine()
        assert len(engine.all_rules) == 35

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
            rule.id = "MODIFIED"


class TestPolicySet:
    def test_policy_set_creation(self) -> None:
        ps = PolicySet(
            name="Test Set",
            version="1.0",
            rules=[],
        )
        assert ps.name == "Test Set"
        assert len(ps.rules) == 0
