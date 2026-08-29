"""Tests for agentguard.compliance.reporter — compliance report generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.reporter import ComplianceReporter, RuleSummary
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.exceptions import AuditAttestationError, AuditTamperDetectedError
from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    GuardrailEvaluation,
    PermissionContext,
    PolicyResult,
)

pytestmark = pytest.mark.usefixtures("_set_audit_key")


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


async def _verified_log(tmp_path: Path, events: list[AuditEvent]) -> AppendOnlyAuditLog:
    backend = FileAuditBackend(directory=tmp_path / "audit")
    log = AppendOnlyAuditLog(backend=backend)
    for event in events:
        await log.write(event)
    return log


class TestComplianceReporter:
    def test_rule_summary_legacy_construction_remains_compatible(self) -> None:
        summary = RuleSummary(
            rule_id="LEGACY-01",
            rule_name="Legacy",
            severity="low",
            total_evaluations=1,
            passed=1,
            failed=0,
            pass_rate=100.0,
        )

        assert summary.policy_bundle_version == ""

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

        log = await _verified_log(
            tmp_path,
            [_make_event(), _make_event(action="tool:exec_cmd")],
        )
        report = await reporter.generate_report(log, report_id="TEST-001")

        assert report.report_id == "TEST-001"
        assert report.total_events == 2
        assert report.total_rules == 1
        assert len(report.rule_summaries) == 1
        assert report.rule_summaries[0].passed == 1
        assert report.rule_summaries[0].failed == 1
        assert report.attestable is True
        assert report.checkpoint_status == "verified"
        assert report.chain_id
        assert report.head_sequence == 2

    async def test_empty_events(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        log = await _verified_log(tmp_path, [])

        with pytest.raises(AuditAttestationError, match="empty"):
            await reporter.generate_report(log)

    async def test_to_json(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        log = await _verified_log(tmp_path, [_make_event()])
        report = await reporter.generate_report(log)
        json_output = reporter.to_json(report)
        assert '"attestable": true' in json_output
        assert '"checkpoint_status": "verified"' in json_output

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

        log = await _verified_log(
            tmp_path,
            [_make_event(), _make_event(result="error")],
        )
        report = await reporter.generate_report(log)
        md = reporter.to_markdown(report)
        assert "# Compliance Report" in md
        assert "Rule Summary" in md
        assert "Chain integrity: verified" in md

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

        log = await _verified_log(tmp_path, [_make_event(resource="admin/users")])
        report = await reporter.generate_report(log)
        assert report.critical_failures == 1
        assert len(report.failed_events) == 1

    async def test_broken_chain_cannot_produce_attestation(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        log = await _verified_log(tmp_path, [_make_event(), _make_event(action="tool:other")])
        log_file = next((tmp_path / "audit").glob("audit-*.jsonl"))
        lines = log_file.read_text().splitlines()
        log_file.write_text(lines[0] + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await reporter.generate_report(log)

    async def test_unknown_policy_bundle_cannot_produce_attestation(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        event = _make_event().model_copy(
            update={
                "policy_bundle_version": "banana",
                "policy_results": [
                    PolicyResult(
                        rule_id="UNKNOWN-01",
                        rule_name="Unknown",
                        passed=True,
                        severity="low",
                        evidence={},
                        remediation="none",
                        effect="allow",
                    )
                ],
            }
        )
        log = await _verified_log(tmp_path, [event])

        with pytest.raises(AuditAttestationError, match="policy_provenance_unresolved"):
            await reporter.generate_report(log)

    async def test_unknown_stamped_bundle_without_results_cannot_attest(
        self, tmp_path: Path
    ) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        event = _make_event().model_copy(update={"policy_bundle_version": "unknown"})

        with pytest.raises(AuditAttestationError, match="policy_provenance_unresolved"):
            await ComplianceReporter(engine).generate_report(await _verified_log(tmp_path, [event]))

    async def test_unknown_rule_in_current_bundle_cannot_produce_attestation(
        self, tmp_path: Path
    ) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        event = _make_event().model_copy(
            update={
                "policy_bundle_version": engine.bundle_version,
                "policy_results": [
                    PolicyResult(
                        rule_id="UNKNOWN-01",
                        rule_name="Unknown",
                        passed=True,
                        severity="low",
                        evidence={},
                        remediation="none",
                        effect="allow",
                    )
                ],
            }
        )
        log = await _verified_log(tmp_path, [event])

        with pytest.raises(AuditAttestationError, match="policy_provenance_unresolved"):
            await reporter.generate_report(log)

    async def test_historical_bundle_remains_attestable_after_reload(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "runtime.yaml"
        policy_file.write_text(
            """
name: Historical
version: "1"
rules:
  - id: OLD-01
    name: Historical rule
    severity: low
    description: test
    check: {type: result_required, allowed_results: [allowed]}
    remediation: fix
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        historical_version = engine.bundle_version
        historical_result = PolicyResult(
            rule_id="OLD-01",
            rule_name="Historical rule",
            passed=True,
            severity="low",
            evidence={},
            remediation="fix",
            effect="allow",
        )
        historical_event = _make_event().model_copy(
            update={
                "policy_bundle_version": historical_version,
                "policy_results": [historical_result],
            }
        )
        policy_file.write_text(
            """
name: Current
version: "2"
rules:
  - id: NEW-01
    name: Current rule
    severity: low
    description: test
    check: {type: result_required, allowed_results: [allowed]}
    remediation: fix
"""
        )
        await engine.reload()

        report = await ComplianceReporter(engine).generate_report(
            await _verified_log(tmp_path, [historical_event])
        )

        assert report.policy_provenance_resolved is True
        assert historical_version in report.policy_bundle_versions
        assert engine.bundle_version not in report.policy_bundle_versions
        assert {summary.rule_id for summary in report.rule_summaries} == {"OLD-01"}
        assert report.policy_sets_evaluated == ["Historical"]

    async def test_one_invocation_cannot_claim_multiple_bundle_versions(
        self, tmp_path: Path
    ) -> None:
        policy_file = tmp_path / "runtime.yaml"
        policy_file.write_text(
            """
name: Runtime
version: "1"
rules:
  - id: RUNTIME-01
    name: Runtime rule
    severity: low
    description: test
    check: {type: result_required, allowed_results: [allowed]}
    remediation: fix
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        old_version = engine.bundle_version
        policy_file.write_text(policy_file.read_text().replace('version: "1"', 'version: "2"'))
        await engine.reload()
        events = [
            _make_event().model_copy(
                update={
                    "event_id": f"evt-{index}",
                    "invocation_id": "mixed-invocation",
                    "policy_bundle_version": version,
                }
            )
            for index, version in enumerate((old_version, engine.bundle_version), start=1)
        ]

        with pytest.raises(AuditAttestationError, match="policy_provenance_unresolved"):
            await ComplianceReporter(engine).generate_report(await _verified_log(tmp_path, events))

    async def test_one_invocation_cannot_mix_stamped_and_unstamped_events(
        self, tmp_path: Path
    ) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        events = [
            _make_event().model_copy(
                update={
                    "event_id": f"evt-{index}",
                    "invocation_id": "partially-stamped",
                    "policy_bundle_version": version,
                }
            )
            for index, version in enumerate(("", engine.bundle_version), start=1)
        ]

        with pytest.raises(AuditAttestationError, match="policy_provenance_unresolved"):
            await ComplianceReporter(engine).generate_report(await _verified_log(tmp_path, events))

    async def test_repeated_lifecycle_policy_results_are_counted_once(self, tmp_path: Path) -> None:
        (tmp_path / "runtime.yaml").write_text(
            """
name: Runtime
version: "1"
rules:
  - id: RUNTIME-01
    name: Runtime rule
    severity: high
    description: test
    stage: pre_tool
    check: {type: action_blocklist, patterns: ["blocked"]}
    remediation: fix
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        result = PolicyResult(
            rule_id="RUNTIME-01",
            rule_name="Runtime rule",
            passed=False,
            severity="high",
            evidence={},
            remediation="fix",
            effect="deny",
        )
        events = [
            _make_event().model_copy(
                update={
                    "event_id": f"evt-{index}",
                    "invocation_id": "invocation-1",
                    "event_type": event_type,
                    "policy_results": [result],
                    "policy_bundle_version": engine.bundle_version,
                }
            )
            for index, event_type in enumerate(
                ("admission", "execution_completed", "delivery_denied"),
                start=1,
            )
        ]
        log = await _verified_log(tmp_path, events)

        report = await reporter.generate_report(log)

        assert len(report.rule_summaries) == 1
        assert report.rule_summaries[0].total_evaluations == 1
        assert report.rule_summaries[0].failed == 1

    async def test_conflicting_lifecycle_policy_results_refuse_attestation(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "runtime.yaml").write_text(
            """
name: Runtime
version: "1"
rules:
  - id: RUNTIME-01
    name: Runtime rule
    severity: high
    description: test
    stage: pre_tool
    check: {type: action_blocklist, patterns: [blocked]}
    remediation: fix
"""
        )
        engine = PolicyEngine(policy_dirs=[tmp_path])
        first = PolicyResult(
            rule_id="RUNTIME-01",
            rule_name="Runtime rule",
            passed=True,
            severity="high",
            evidence={},
            remediation="fix",
            effect="allow",
        )
        conflict = first.model_copy(update={"passed": False, "effect": "deny"})
        events = [
            _make_event().model_copy(
                update={
                    "event_id": f"evt-{index}",
                    "invocation_id": "invocation-conflict",
                    "policy_results": [result],
                    "policy_bundle_version": engine.bundle_version,
                }
            )
            for index, result in enumerate((first, conflict), start=1)
        ]

        with pytest.raises(AuditAttestationError, match="policy_result_conflict"):
            await ComplianceReporter(engine).generate_report(await _verified_log(tmp_path, events))

    async def test_same_rule_id_in_two_generations_has_separate_summaries(
        self, tmp_path: Path
    ) -> None:
        policy_file = tmp_path / "attestation.yaml"

        def policy_document(*, version: str, name: str, severity: str) -> str:
            return f"""
name: Runtime
version: "{version}"
rules:
  - id: SHARED-01
    name: {name}
    severity: {severity}
    description: test
    check: {{type: result_required, allowed_results: [allowed]}}
    remediation: fix
"""

        policy_file.write_text(policy_document(version="1", name="Old rule", severity="low"))
        engine = PolicyEngine(policy_dirs=[tmp_path])
        old_version = engine.bundle_version
        policy_file.write_text(policy_document(version="2", name="New rule", severity="critical"))
        await engine.reload()
        new_version = engine.bundle_version
        events = [
            _make_event().model_copy(
                update={
                    "event_id": f"evt-{index}",
                    "invocation_id": f"inv-{index}",
                    "policy_bundle_version": version,
                }
            )
            for index, version in enumerate((old_version, new_version), start=1)
        ]

        report = await ComplianceReporter(engine).generate_report(
            await _verified_log(tmp_path, events)
        )

        assert report.total_rules == 2
        assert {
            (summary.policy_bundle_version, summary.rule_name, summary.severity)
            for summary in report.rule_summaries
        } == {
            (old_version, "Old rule", "low"),
            (new_version, "New rule", "critical"),
        }

    async def test_shadow_findings_are_separate_from_policy_metrics(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        evaluation = GuardrailEvaluation(
            guardrail_id="content-safety",
            guardrail_version="4",
            stage="post_tool",
            effect="deny",
            reason_codes=("unsafe.output",),
            duration_ms=0.4,
            enforced=False,
        )
        events = [
            _make_event().model_copy(
                update={
                    "event_id": f"evt-{index}",
                    "invocation_id": "inv-shadow",
                    "event_type": event_type,
                    "guardrail_evaluations": (evaluation,),
                    "chain_mode": "shadow",
                }
            )
            for index, event_type in enumerate(
                ("execution_completed", "delivery_completed"), start=1
            )
        ]

        report = await reporter.generate_report(await _verified_log(tmp_path, events))

        assert report.overall_pass_rate == 100.0
        assert report.critical_failures == 0
        assert report.failed_events == []
        assert report.shadow_evaluation_count == 1
        assert report.shadow_affected_invocation_count == 1
        assert report.shadow_would_deny_invocation_count == 1
        assert report.shadow_would_escalate_invocation_count == 0
        assert report.shadow_would_transform_invocation_count == 0
        assert report.shadow_findings[0].guardrail_id == "content-safety"
        assert report.shadow_findings[0].guardrail_version == "4"
        assert report.shadow_findings[0].effects == ("deny",)
        assert report.shadow_findings[0].reason_codes == ("unsafe.output",)
        assert "Observed, Not Enforced" in reporter.to_markdown(report)
        assert '"shadow_evaluation_count": 1' in reporter.to_json(report)

    async def test_shadow_conflicts_are_surfaced_once(self, tmp_path: Path) -> None:
        engine = PolicyEngine(policy_dirs=[tmp_path])
        reporter = ComplianceReporter(engine)
        first = GuardrailEvaluation(
            guardrail_id="risk",
            guardrail_version="1",
            stage="pre_tool",
            effect="escalate",
            reason_codes=("review",),
            duration_ms=0.1,
            enforced=False,
        )
        conflict = first.model_copy(update={"effect": "deny", "reason_codes": ("deny",)})
        events = [
            _make_event().model_copy(
                update={
                    "event_id": f"evt-{index}",
                    "invocation_id": "inv-conflict",
                    "event_type": event_type,
                    "guardrail_evaluations": (evaluation,),
                    "chain_mode": "shadow",
                }
            )
            for index, (event_type, evaluation) in enumerate(
                (("admission", first), ("delivery_completed", conflict)), start=1
            )
        ]

        report = await reporter.generate_report(await _verified_log(tmp_path, events))

        assert report.shadow_evaluation_count == 1
        assert report.shadow_conflict_count == 1
        assert report.shadow_findings[0].conflicting_duplicate is True
        assert report.shadow_findings[0].effects == ("escalate", "deny")
        assert report.shadow_findings[0].reason_codes == ("deny", "review")
        assert report.shadow_would_deny_invocation_count == 1
        assert report.shadow_would_escalate_invocation_count == 1

        reversed_report = await reporter.generate_report(
            await _verified_log(tmp_path / "reversed", list(reversed(events)))
        )
        assert reversed_report.shadow_findings[0].effects == ("escalate", "deny")
        assert reversed_report.shadow_findings[0].reason_codes == ("deny", "review")

    async def test_allow_only_shadow_conflict_is_still_surfaced(self, tmp_path: Path) -> None:
        reporter = ComplianceReporter(PolicyEngine(policy_dirs=[tmp_path]))
        first = GuardrailEvaluation(
            guardrail_id="observer",
            guardrail_version="1",
            stage="pre_tool",
            effect="allow",
            reason_codes=(),
            duration_ms=0.1,
            enforced=False,
        )
        conflict = first.model_copy(update={"duration_ms": 0.2})
        events = [
            _make_event().model_copy(
                update={
                    "event_id": f"evt-{index}",
                    "invocation_id": "inv-allow-conflict",
                    "event_type": event_type,
                    "guardrail_evaluations": (evaluation,),
                    "chain_mode": "shadow",
                }
            )
            for index, (event_type, evaluation) in enumerate(
                (("admission", first), ("delivery_completed", conflict)), start=1
            )
        ]

        report = await reporter.generate_report(await _verified_log(tmp_path, events))

        assert report.shadow_evaluation_count == 1
        assert report.shadow_affected_invocation_count == 0
        assert report.shadow_conflict_count == 1
        assert report.shadow_findings[0].effects == ("allow",)
