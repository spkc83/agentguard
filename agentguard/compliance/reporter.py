"""Compliance attestation report generator.

Reads audit events, evaluates them against loaded policies, and
produces a structured compliance report in JSON or Markdown format.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

from agentguard.compliance.engine import PolicyEngine
from agentguard.models import AuditEvent, PolicyResult

logger = structlog.get_logger()


class RuleSummary(BaseModel):
    """Summary of a single rule's evaluation across all events.

    Args:
        rule_id: The policy rule ID.
        rule_name: Human-readable name.
        severity: Rule severity.
        total_evaluations: How many events were checked.
        passed: How many passed.
        failed: How many failed.
        pass_rate: Percentage of events that passed.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_name: str
    severity: str
    total_evaluations: int
    passed: int
    failed: int
    pass_rate: float


class ComplianceReport(BaseModel):
    """Full compliance attestation report.

    Args:
        report_id: Unique report identifier.
        generated_at: When the report was generated.
        time_range_start: Start of the audit period.
        time_range_end: End of the audit period.
        total_events: Number of audit events analyzed.
        total_rules: Number of policy rules evaluated.
        overall_pass_rate: Percentage of (event, rule) pairs that passed.
        critical_failures: Number of critical-severity failures.
        rule_summaries: Per-rule breakdown.
        policy_sets_evaluated: Names of policy sets included.
        failed_events: Events that had at least one failure.
    """

    model_config = ConfigDict(frozen=True)

    report_id: str
    generated_at: datetime
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    total_events: int
    total_rules: int
    overall_pass_rate: float
    critical_failures: int
    rule_summaries: list[RuleSummary]
    policy_sets_evaluated: list[str]
    failed_events: list[dict[str, Any]] = []


class ComplianceReporter:
    """Generates compliance reports from audit events and policy evaluations.

    Args:
        engine: The policy engine with loaded rules.
    """

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine

    async def generate_report(
        self,
        events: list[AuditEvent],
        report_id: str = "",
    ) -> ComplianceReport:
        """Generate a compliance report for a set of audit events.

        Args:
            events: Audit events to evaluate.
            report_id: Optional report identifier.

        Returns:
            A structured ComplianceReport.
        """
        if not report_id:
            report_id = f"CR-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

        # Track per-rule stats
        rule_stats: dict[str, dict[str, Any]] = {}
        failed_events: list[dict[str, Any]] = []
        all_results: list[PolicyResult] = []

        for event in events:
            results = await self._engine.evaluate(event)
            all_results.extend(results)
            event_failures = [r for r in results if not r.passed]

            if event_failures:
                failed_events.append(
                    {
                        "event_id": event.event_id,
                        "action": event.action,
                        "resource": event.resource,
                        "failures": [
                            {"rule_id": r.rule_id, "severity": r.severity} for r in event_failures
                        ],
                    }
                )

            for result in results:
                if result.rule_id not in rule_stats:
                    rule_stats[result.rule_id] = {
                        "rule_name": result.rule_name,
                        "severity": result.severity,
                        "total": 0,
                        "passed": 0,
                        "failed": 0,
                    }
                stats = rule_stats[result.rule_id]
                stats["total"] += 1
                if result.passed:
                    stats["passed"] += 1
                else:
                    stats["failed"] += 1

        # Build rule summaries
        rule_summaries = []
        for rule_id, stats in sorted(rule_stats.items()):
            total = stats["total"]
            passed = stats["passed"]
            rule_summaries.append(
                RuleSummary(
                    rule_id=rule_id,
                    rule_name=stats["rule_name"],
                    severity=stats["severity"],
                    total_evaluations=total,
                    passed=passed,
                    failed=stats["failed"],
                    pass_rate=round(passed / total * 100, 1) if total > 0 else 100.0,
                )
            )

        # Overall stats
        total_evaluations = len(all_results)
        total_passed = sum(1 for r in all_results if r.passed)
        critical_failures = sum(1 for r in all_results if not r.passed and r.severity == "critical")
        overall_pass_rate = (
            round(total_passed / total_evaluations * 100, 1) if total_evaluations > 0 else 100.0
        )

        # Time range
        timestamps = [e.timestamp for e in events]
        time_start = min(timestamps) if timestamps else None
        time_end = max(timestamps) if timestamps else None

        report = ComplianceReport(
            report_id=report_id,
            generated_at=datetime.now(UTC),
            time_range_start=time_start,
            time_range_end=time_end,
            total_events=len(events),
            total_rules=len(self._engine.all_rules),
            overall_pass_rate=overall_pass_rate,
            critical_failures=critical_failures,
            rule_summaries=rule_summaries,
            policy_sets_evaluated=[ps.name for ps in self._engine.policy_sets],
            failed_events=failed_events,
        )

        logger.info(
            "compliance_report_generated",
            report_id=report.report_id,
            total_events=report.total_events,
            overall_pass_rate=report.overall_pass_rate,
            critical_failures=report.critical_failures,
        )
        return report

    def to_json(self, report: ComplianceReport) -> str:
        """Serialize a compliance report to JSON."""
        return report.model_dump_json(indent=2)

    def to_markdown(self, report: ComplianceReport) -> str:
        """Render a compliance report as Markdown."""
        lines = [
            f"# Compliance Report: {report.report_id}",
            "",
            f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Events analyzed:** {report.total_events}",
            f"**Policy rules evaluated:** {report.total_rules}",
            f"**Overall pass rate:** {report.overall_pass_rate}%",
            f"**Critical failures:** {report.critical_failures}",
            "",
            "## Policy Sets",
            "",
        ]
        for ps_name in report.policy_sets_evaluated:
            lines.append(f"- {ps_name}")

        lines.extend(["", "## Rule Summary", ""])
        lines.append("| Rule ID | Name | Severity | Passed | Failed | Pass Rate |")
        lines.append("|---------|------|----------|--------|--------|-----------|")
        for rs in report.rule_summaries:
            lines.append(
                f"| {rs.rule_id} | {rs.rule_name} | {rs.severity} "
                f"| {rs.passed} | {rs.failed} | {rs.pass_rate}% |"
            )

        if report.failed_events:
            lines.extend(["", "## Failed Events", ""])
            for fe in report.failed_events:
                lines.append(f"- **{fe['event_id']}** ({fe['action']} → {fe['resource']})")
                for fail in fe["failures"]:
                    lines.append(f"  - {fail['rule_id']} [{fail['severity']}]")

        lines.append("")
        return "\n".join(lines)
