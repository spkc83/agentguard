"""Compliance attestation report generator.

Reads audit events, evaluates them against loaded policies, and
produces a structured compliance report in JSON or Markdown format.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog
from pydantic import BaseModel, ConfigDict, Field

from agentguard.compliance.engine import PolicyBundle, PolicyEngine
from agentguard.exceptions import AuditAttestationError
from agentguard.models import AuditEvent, GuardrailEvaluation, PolicyResult

if TYPE_CHECKING:
    from agentguard.core.audit import AuditLog

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

    policy_bundle_version: str = ""
    rule_id: str
    rule_name: str
    severity: str
    total_evaluations: int
    passed: int
    failed: int
    pass_rate: float


class ShadowFinding(BaseModel):
    """Signed observed-but-not-enforced guardrail finding."""

    model_config = ConfigDict(frozen=True)

    invocation_id: str
    event_id: str
    guardrail_id: str
    guardrail_version: str
    stage: str
    effects: tuple[str, ...]
    reason_codes: tuple[str, ...] = ()
    conflicting_duplicate: bool = False


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
    failed_events: list[dict[str, Any]] = Field(default_factory=list)
    attestable: bool = False
    checkpoint_status: str = "unverified"
    chain_id: str = ""
    head_sequence: int | None = None
    head_event_hash: str = ""
    chain_modes: tuple[str, ...] = ()
    policy_bundle_versions: tuple[str, ...] = ()
    policy_provenance_resolved: bool = False
    shadow_evaluation_count: int = 0
    shadow_affected_invocation_count: int = 0
    shadow_would_deny_invocation_count: int = 0
    shadow_would_escalate_invocation_count: int = 0
    shadow_would_transform_invocation_count: int = 0
    shadow_conflict_count: int = 0
    shadow_findings: list[ShadowFinding] = Field(default_factory=list)


class ComplianceReporter:
    """Generates compliance reports from audit events and policy evaluations.

    Args:
        engine: The policy engine with loaded rules.
    """

    def __init__(self, engine: PolicyEngine) -> None:
        self._engine = engine

    async def generate_report(
        self,
        audit_log: AuditLog,
        report_id: str = "",
    ) -> ComplianceReport:
        """Generate an attestation from one checkpoint-verified audit snapshot.

        Args:
            audit_log: Audit source that can return a lock-consistent verified snapshot.
            report_id: Optional report identifier.

        Returns:
            A structured ComplianceReport.
        """
        snapshot = await audit_log.read_verified()
        verification = snapshot.verification
        if not verification.attestable:
            raise AuditAttestationError(verification.checkpoint_status)
        events = list(snapshot.events)
        current_bundle = self._engine.snapshot()
        bundles_by_version: dict[str, PolicyBundle] = {}
        invocation_versions: dict[str, set[str]] = {}
        for event in events:
            version = event.policy_bundle_version
            scope = event.invocation_id or event.event_id
            invocation_versions.setdefault(scope, set()).add(version)
            if not version:
                if event.policy_results:
                    raise AuditAttestationError("policy_provenance_unresolved")
                bundles_by_version[current_bundle.version] = current_bundle
                continue
            bundle = self._engine.resolve_bundle(version)
            if bundle is None or any(
                result.rule_id not in bundle.rule_ids for result in event.policy_results
            ):
                raise AuditAttestationError("policy_provenance_unresolved")
            bundles_by_version[version] = bundle
        if any(len(versions) > 1 for versions in invocation_versions.values()):
            raise AuditAttestationError("policy_provenance_unresolved")
        policy_provenance_resolved = True

        if not report_id:
            report_id = f"CR-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

        # Track per-rule stats
        rule_stats: dict[tuple[str, str], dict[str, Any]] = {}
        failed_events: list[dict[str, Any]] = []
        all_results: list[PolicyResult] = []
        seen_runtime_results: dict[tuple[str, str, str], PolicyResult] = {}

        for event in events:
            event_bundle = bundles_by_version.get(
                event.policy_bundle_version,
                current_bundle,
            )
            bundle_version = event_bundle.version
            runtime_results = []
            result_scope = event.invocation_id or event.event_id
            for result in event.policy_results:
                result_key = (result_scope, bundle_version, result.rule_id)
                previous_result = seen_runtime_results.get(result_key)
                if previous_result is not None:
                    if previous_result != result:
                        raise AuditAttestationError("policy_result_conflict")
                    continue
                seen_runtime_results[result_key] = result
                runtime_results.append(result)
            results = [
                *runtime_results,
                *await self._engine.evaluate_stage(
                    event,
                    "attestation",
                    bundle=event_bundle,
                ),
            ]
            all_results.extend(results)
            event_failures = [r for r in results if not r.passed]

            if event_failures:
                failed_events.append(
                    {
                        "event_id": event.event_id,
                        "action": event.action,
                        "resource": event.resource,
                        "policy_bundle_version": bundle_version,
                        "failures": [
                            {"rule_id": r.rule_id, "severity": r.severity} for r in event_failures
                        ],
                    }
                )

            for result in results:
                stats_key = (bundle_version, result.rule_id)
                if stats_key not in rule_stats:
                    rule_stats[stats_key] = {
                        "rule_name": result.rule_name,
                        "severity": result.severity,
                        "total": 0,
                        "passed": 0,
                        "failed": 0,
                    }
                stats = rule_stats[stats_key]
                stats["total"] += 1
                if result.passed:
                    stats["passed"] += 1
                else:
                    stats["failed"] += 1

        # Build rule summaries
        rule_summaries = []
        for (bundle_version, rule_id), stats in sorted(rule_stats.items()):
            total = stats["total"]
            passed = stats["passed"]
            rule_summaries.append(
                RuleSummary(
                    policy_bundle_version=bundle_version,
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
        shadow_findings = self._shadow_findings(events)
        actionable_effects = {"deny", "escalate", "transform"}

        def scopes_for(effect: str) -> set[str]:
            return {
                finding.invocation_id or finding.event_id
                for finding in shadow_findings
                if effect in finding.effects
            }

        report = ComplianceReport(
            report_id=report_id,
            generated_at=datetime.now(UTC),
            time_range_start=time_start,
            time_range_end=time_end,
            total_events=len(events),
            total_rules=len(
                {
                    (bundle.version, rule.id)
                    for bundle in bundles_by_version.values()
                    for rule in bundle.all_rules
                }
            ),
            overall_pass_rate=overall_pass_rate,
            critical_failures=critical_failures,
            rule_summaries=rule_summaries,
            policy_sets_evaluated=sorted(
                {
                    policy_set.name
                    for bundle in bundles_by_version.values()
                    for policy_set in bundle.policy_sets
                }
            ),
            failed_events=failed_events,
            attestable=True,
            checkpoint_status=verification.checkpoint_status,
            chain_id=verification.chain_id,
            head_sequence=verification.head_sequence,
            head_event_hash=verification.head_event_hash,
            chain_modes=tuple(sorted({event.chain_mode for event in events})),
            policy_bundle_versions=tuple(sorted(bundles_by_version)),
            policy_provenance_resolved=policy_provenance_resolved,
            shadow_evaluation_count=len(shadow_findings),
            shadow_affected_invocation_count=len(
                {
                    finding.invocation_id or finding.event_id
                    for finding in shadow_findings
                    if actionable_effects.intersection(finding.effects)
                }
            ),
            shadow_would_deny_invocation_count=len(scopes_for("deny")),
            shadow_would_escalate_invocation_count=len(scopes_for("escalate")),
            shadow_would_transform_invocation_count=len(scopes_for("transform")),
            shadow_conflict_count=sum(finding.conflicting_duplicate for finding in shadow_findings),
            shadow_findings=shadow_findings,
        )

        logger.info(
            "compliance_report_generated",
            report_id=report.report_id,
            total_events=report.total_events,
            overall_pass_rate=report.overall_pass_rate,
            critical_failures=report.critical_failures,
        )
        return report

    @staticmethod
    def _shadow_findings(events: list[AuditEvent]) -> list[ShadowFinding]:
        """Return one observed finding per signed lifecycle identity."""
        variants: dict[
            tuple[str, str, str, str],
            list[tuple[AuditEvent, GuardrailEvaluation]],
        ] = {}
        for event in events:
            scope = event.invocation_id or event.event_id
            for evaluation in event.guardrail_evaluations:
                if evaluation.enforced:
                    continue
                key: tuple[str, str, str, str] = (
                    scope,
                    evaluation.stage,
                    evaluation.guardrail_id,
                    evaluation.guardrail_version,
                )
                records = variants.setdefault(key, [])
                if all(existing != evaluation for _, existing in records):
                    records.append((event, evaluation))
        findings: list[ShadowFinding] = []
        effect_order = {
            effect: index
            for index, effect in enumerate(("allow", "warn", "transform", "escalate", "deny"))
        }
        for records in variants.values():
            event, evaluation = records[0]
            effects = tuple(
                sorted(
                    {record.effect for _, record in records},
                    key=effect_order.__getitem__,
                )
            )
            if effects == ("allow",) and len(records) == 1:
                continue
            findings.append(
                ShadowFinding(
                    invocation_id=event.invocation_id,
                    event_id=event.event_id,
                    guardrail_id=evaluation.guardrail_id,
                    guardrail_version=evaluation.guardrail_version,
                    stage=evaluation.stage,
                    effects=effects,
                    reason_codes=tuple(
                        sorted({reason for _, record in records for reason in record.reason_codes})
                    ),
                    conflicting_duplicate=len(records) > 1,
                )
            )
        return findings

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
            f"**Chain integrity: {report.checkpoint_status}**",
            f"**Chain head:** {report.chain_id}@{report.head_sequence}",
            f"**Policy provenance resolved:** {report.policy_provenance_resolved}",
            "",
            "## Policy Sets",
            "",
        ]
        for ps_name in report.policy_sets_evaluated:
            lines.append(f"- {ps_name}")

        lines.extend(["", "## Rule Summary", ""])
        lines.append("| Bundle | Rule ID | Name | Severity | Passed | Failed | Pass Rate |")
        lines.append("|--------|---------|------|----------|--------|--------|-----------|")
        for rs in report.rule_summaries:
            lines.append(
                f"| {rs.policy_bundle_version} | {rs.rule_id} | {rs.rule_name} | {rs.severity} "
                f"| {rs.passed} | {rs.failed} | {rs.pass_rate}% |"
            )

        if report.failed_events:
            lines.extend(["", "## Failed Events", ""])
            for fe in report.failed_events:
                lines.append(f"- **{fe['event_id']}** ({fe['action']} → {fe['resource']})")
                for fail in fe["failures"]:
                    lines.append(f"  - {fail['rule_id']} [{fail['severity']}]")

        if report.shadow_findings:
            lines.extend(["", "## Shadow Findings (Observed, Not Enforced)", ""])
            lines.append(
                f"Evaluations: {report.shadow_evaluation_count}; "
                f"affected invocations: {report.shadow_affected_invocation_count}; "
                f"conflicting duplicates: {report.shadow_conflict_count}."
            )
            lines.append(
                "Would deny/escalate/transform invocations: "
                f"{report.shadow_would_deny_invocation_count}/"
                f"{report.shadow_would_escalate_invocation_count}/"
                f"{report.shadow_would_transform_invocation_count}."
            )
            for finding in report.shadow_findings:
                reasons = ", ".join(finding.reason_codes) or "none"
                conflict = " [conflicting duplicate]" if finding.conflicting_duplicate else ""
                lines.append(
                    f"- **{finding.guardrail_id}@{finding.guardrail_version}** "
                    f"would {'/'.join(finding.effects)} at {finding.stage} "
                    f"(reasons: {reasons}){conflict}"
                )

        lines.append("")
        return "\n".join(lines)
