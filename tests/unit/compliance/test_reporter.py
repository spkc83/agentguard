"""Tests for agentguard.compliance.reporter — compliance report generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.reporter import ComplianceReporter
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext


def _make_event(
    action: str = "tool:credit_check",
    resource: str = "bureau/experian",
    result: str = "allowed",
    granted: bool = True,
) -> AuditEvent:
    identity = AgentIdentity(
        agent_id="agent-1",
        name="Test Bot",
        roles=["credit-analyst"],
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


class TestComplianceReporter:
    async def test_generate_report(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test Policy"
version: "1.0"
rules:
  - id: TEST-01
    name: Block exec tools
    severity: high
    description: test
    check:
      type: action_blocklist
      patterns: ["tool:exec_.*"]
    remediation: Do not use exec tools.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)

        events = [_make_event(), _make_event(action="tool:exec_cmd")]
        report = await reporter.generate_report(events, report_id="TEST-001")

        assert report.report_id == "TEST-001"
        assert report.total_events == 2
        assert report.total_rules == 1
        assert len(report.rule_summaries) == 1
        assert report.rule_summaries[0].passed == 1
        assert report.rule_summaries[0].failed == 1

    async def test_empty_events(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        report = await reporter.generate_report([])
        assert report.total_events == 0
        assert report.overall_pass_rate == 100.0

    async def test_to_json(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        report = await reporter.generate_report([_make_event()])
        json_output = reporter.to_json(report)
        assert "TEST" not in json_output or "report_id" in json_output

    async def test_to_markdown(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test Policy"
version: "1.0"
rules:
  - id: TEST-01
    name: Simple check
    severity: medium
    description: test
    check:
      type: result_required
      allowed_results: ["allowed"]
    remediation: Fix it.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)

        events = [_make_event(), _make_event(result="error")]
        report = await reporter.generate_report(events)
        md = reporter.to_markdown(report)
        assert "# Compliance Report" in md
        assert "Rule Summary" in md

    async def test_report_with_failures(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            """
name: "Test Policy"
version: "1.0"
rules:
  - id: TEST-01
    name: Block admin access
    severity: critical
    description: test
    check:
      type: resource_pattern
      patterns: ["admin/.*"]
    remediation: No admin access.
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)

        events = [_make_event(resource="admin/users")]
        report = await reporter.generate_report(events)
        assert report.critical_failures == 1
        assert len(report.failed_events) == 1
