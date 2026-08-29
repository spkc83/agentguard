"""Metrics dashboard — aggregate metrics from audit events.

Computes governance KPIs: action counts, denial rates, latency
percentiles, agent activity, and policy violation trends.

Usage:
    from agentguard.observability.dashboard import MetricsDashboard

    dashboard = MetricsDashboard()
    metrics = dashboard.compute(events)
    print(metrics.denial_rate)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field

from agentguard.models import AuditEvent, GuardrailEvaluation

logger = structlog.get_logger()


class AgentMetrics(BaseModel):
    """Per-agent activity metrics.

    Args:
        agent_id: Agent identifier.
        total_actions: Total number of actions.
        allowed: Number of allowed actions.
        denied: Number of denied actions.
        errors: Number of error results.
        escalated: Number of escalated (HITL) actions.
        denial_rate: Fraction of actions denied (0.0-1.0).
    """

    model_config = ConfigDict(frozen=True)

    agent_id: str
    total_actions: int
    allowed: int
    denied: int
    errors: int
    escalated: int = 0
    rejected: int = 0
    denial_rate: float


class PolicyViolationTrend(BaseModel):
    """Policy violation tracking.

    Args:
        rule_id: The policy rule that was violated.
        violation_count: Number of violations.
        last_violation: Timestamp of most recent violation.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str
    violation_count: int
    last_violation: datetime | None = None


class ShadowGuardrailSummary(BaseModel):
    """Deduplicated observed effects for one guardrail version and stage."""

    model_config = ConfigDict(frozen=True)

    guardrail_id: str
    guardrail_version: str
    stage: str
    evaluation_count: int
    affected_invocation_count: int
    allow_count: int = 0
    warn_count: int = 0
    would_deny_count: int = 0
    would_escalate_count: int = 0
    would_transform_count: int = 0
    conflict_count: int = 0
    reason_code_counts: dict[str, int] = Field(default_factory=dict)


class DashboardMetrics(BaseModel):
    """Aggregate governance metrics.

    Args:
        total_events: Total audit events.
        allowed_count: Number of allowed events.
        denied_count: Number of denied events.
        error_count: Number of error events.
        escalated_count: Number of escalated events.
        denial_rate: Overall denial rate (0.0-1.0).
        latency_p50_ms: 50th percentile latency.
        latency_p95_ms: 95th percentile latency.
        latency_p99_ms: 99th percentile latency.
        agent_metrics: Per-agent metrics.
        top_actions: Most frequent actions and their counts.
        policy_violations: Policy violation trends.
        time_range_start: Earliest event timestamp.
        time_range_end: Latest event timestamp.
    """

    model_config = ConfigDict(frozen=True)

    total_events: int
    allowed_count: int
    denied_count: int
    error_count: int
    escalated_count: int
    rejected_count: int = 0
    raw_event_count: int = 0
    incomplete_count: int = 0
    in_doubt_count: int = 0
    execution_success_count: int = 0
    delivery_denied_count: int = 0
    denial_rate: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    agent_metrics: list[AgentMetrics]
    top_actions: list[tuple[str, int]]
    policy_violations: list[PolicyViolationTrend]
    shadow_evaluation_count: int = 0
    shadow_affected_invocation_count: int = 0
    shadow_would_deny_count: int = 0
    shadow_would_escalate_count: int = 0
    shadow_would_transform_count: int = 0
    shadow_conflict_count: int = 0
    shadow_guardrails: list[ShadowGuardrailSummary] = Field(default_factory=list)
    escalation_requested_count: int = 0
    approval_granted_count: int = 0
    approval_denied_count: int = 0
    approval_expired_count: int = 0
    escalation_resumed_count: int = 0
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None


class MetricsDashboard:
    """Computes aggregate governance metrics from audit events."""

    def compute(self, events: list[AuditEvent]) -> DashboardMetrics:
        """Compute dashboard metrics from audit events.

        Args:
            events: List of audit events to analyze.

        Returns:
            DashboardMetrics with all computed KPIs.
        """
        if not events:
            return DashboardMetrics(
                total_events=0,
                allowed_count=0,
                denied_count=0,
                error_count=0,
                escalated_count=0,
                rejected_count=0,
                raw_event_count=0,
                incomplete_count=0,
                in_doubt_count=0,
                execution_success_count=0,
                delivery_denied_count=0,
                denial_rate=0.0,
                latency_p50_ms=0.0,
                latency_p95_ms=0.0,
                latency_p99_ms=0.0,
                agent_metrics=[],
                top_actions=[],
                policy_violations=[],
            )

        terminal_events, groups, incomplete, in_doubt = self._select_terminal_events(events)

        # Result counts are invocation counts, not raw lifecycle-event counts.
        allowed = sum(1 for e in terminal_events if e.result == "allowed")
        denied = sum(1 for e in terminal_events if e.result == "denied")
        errors = sum(1 for e in terminal_events if e.result == "error")
        escalated = sum(1 for e in terminal_events if e.result == "escalated")
        rejected = sum(1 for e in terminal_events if e.result == "rejected")
        total = len(terminal_events)
        execution_success = sum(
            1
            for group in groups.values()
            if any(
                event.event_type == "execution_completed" and event.result == "allowed"
                for event in group
            )
        )
        delivery_denied = sum(1 for e in terminal_events if e.event_type == "delivery_denied")

        # Latency percentiles
        durations = [e.duration_ms for e in terminal_events if e.duration_ms > 0]
        if durations:
            durations_sorted = sorted(durations)
            p50 = self._percentile(durations_sorted, 50)
            p95 = self._percentile(durations_sorted, 95)
            p99 = self._percentile(durations_sorted, 99)
        else:
            p50 = p95 = p99 = 0.0

        # Per-agent metrics
        agent_data: dict[str, dict[str, int]] = {}
        for e in terminal_events:
            if e.agent_id not in agent_data:
                agent_data[e.agent_id] = {
                    "total": 0,
                    "allowed": 0,
                    "denied": 0,
                    "errors": 0,
                    "escalated": 0,
                    "rejected": 0,
                }
            agent_data[e.agent_id]["total"] += 1
            if e.result == "allowed":
                agent_data[e.agent_id]["allowed"] += 1
            elif e.result == "denied":
                agent_data[e.agent_id]["denied"] += 1
            elif e.result == "error":
                agent_data[e.agent_id]["errors"] += 1
            elif e.result == "escalated":
                agent_data[e.agent_id]["escalated"] += 1
            elif e.result == "rejected":
                agent_data[e.agent_id]["rejected"] += 1

        agent_metrics = [
            AgentMetrics(
                agent_id=aid,
                total_actions=d["total"],
                allowed=d["allowed"],
                denied=d["denied"],
                errors=d["errors"],
                escalated=d["escalated"],
                rejected=d["rejected"],
                denial_rate=d["denied"] / d["total"] if d["total"] > 0 else 0.0,
            )
            for aid, d in sorted(agent_data.items())
        ]

        # Top actions
        action_counts: dict[str, int] = {}
        for e in terminal_events:
            action_counts[e.action] = action_counts.get(e.action, 0) + 1
        top_actions = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Policy violations
        violation_data: dict[str, dict[str, Any]] = {}
        for group in groups.values():
            seen_rules: set[str] = set()
            for e in group:
                for pr in e.policy_results:
                    if pr.passed or pr.rule_id in seen_rules:
                        continue
                    seen_rules.add(pr.rule_id)
                    if not pr.passed:
                        if pr.rule_id not in violation_data:
                            violation_data[pr.rule_id] = {"count": 0, "last": None}
                        violation_data[pr.rule_id]["count"] += 1
                        violation_data[pr.rule_id]["last"] = e.timestamp

        policy_violations = [
            PolicyViolationTrend(
                rule_id=rid,
                violation_count=d["count"],
                last_violation=d["last"],
            )
            for rid, d in sorted(violation_data.items(), key=lambda x: x[1]["count"], reverse=True)
        ]

        shadow = self._shadow_metrics(events)
        hitl = self._hitl_metrics(events)

        # Time range
        timestamps = [e.timestamp for e in terminal_events]

        return DashboardMetrics(
            total_events=total,
            allowed_count=allowed,
            denied_count=denied,
            error_count=errors,
            escalated_count=escalated,
            rejected_count=rejected,
            raw_event_count=len(events),
            incomplete_count=incomplete,
            in_doubt_count=in_doubt,
            execution_success_count=execution_success,
            delivery_denied_count=delivery_denied,
            denial_rate=denied / total if total > 0 else 0.0,
            latency_p50_ms=p50,
            latency_p95_ms=p95,
            latency_p99_ms=p99,
            agent_metrics=agent_metrics,
            top_actions=top_actions,
            policy_violations=policy_violations,
            shadow_evaluation_count=shadow["evaluation_count"],
            shadow_affected_invocation_count=shadow["affected_invocation_count"],
            shadow_would_deny_count=shadow["would_deny_count"],
            shadow_would_escalate_count=shadow["would_escalate_count"],
            shadow_would_transform_count=shadow["would_transform_count"],
            shadow_conflict_count=shadow["conflict_count"],
            shadow_guardrails=shadow["guardrails"],
            escalation_requested_count=hitl["escalation_requested"],
            approval_granted_count=hitl["approval_granted"],
            approval_denied_count=hitl["approval_denied"],
            approval_expired_count=hitl["approval_expired"],
            escalation_resumed_count=hitl["escalation_resumed"],
            time_range_start=min(timestamps) if timestamps else None,
            time_range_end=max(timestamps) if timestamps else None,
        )

    @staticmethod
    def _hitl_metrics(events: list[AuditEvent]) -> dict[str, int]:
        """Count each signed HITL lifecycle transition once per escalation."""
        event_types = (
            "escalation_requested",
            "approval_granted",
            "approval_denied",
            "approval_expired",
            "escalation_resumed",
        )
        observed: set[tuple[str, str]] = set()
        for event in events:
            evidence = event.hitl_evidence
            if evidence is None or event.event_type not in event_types:
                continue
            observed.add((evidence.escalation_id, event.event_type))
        return {
            event_type: sum(1 for key in observed if key[1] == event_type)
            for event_type in event_types
        }

    @staticmethod
    def _shadow_metrics(events: list[AuditEvent]) -> dict[str, Any]:
        """Aggregate signed shadow evidence without lifecycle double counting."""
        variants: dict[tuple[str, str, str, str], list[GuardrailEvaluation]] = {}
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
                if evaluation not in records:
                    records.append(evaluation)

        summaries: dict[tuple[str, str, str], dict[str, Any]] = {}
        affected: set[str] = set()
        effect_scopes: dict[str, set[str]] = {
            "deny": set(),
            "escalate": set(),
            "transform": set(),
        }
        conflicts = {key for key, records in variants.items() if len(records) > 1}
        for key, records in variants.items():
            scope = key[0]
            evaluation = records[0]
            summary_key = (
                evaluation.guardrail_id,
                evaluation.guardrail_version,
                evaluation.stage,
            )
            summary = summaries.setdefault(
                summary_key,
                {
                    "evaluations": 0,
                    "affected": set(),
                    "effect_scopes": {
                        "allow": set(),
                        "warn": set(),
                        "deny": set(),
                        "escalate": set(),
                        "transform": set(),
                    },
                    "conflicts": 0,
                    "reasons": {},
                },
            )
            summary["evaluations"] += 1
            observed_effects = {record.effect for record in records}
            observed_reasons = {reason for record in records for reason in record.reason_codes}
            for effect in observed_effects:
                summary["effect_scopes"][effect].add(scope)
            for reason in observed_reasons:
                summary["reasons"][reason] = summary["reasons"].get(reason, 0) + 1
            actionable = observed_effects.intersection(effect_scopes)
            if actionable:
                affected.add(scope)
                summary["affected"].add(scope)
            for effect in actionable:
                effect_scopes[effect].add(scope)
            if key in conflicts:
                summary["conflicts"] += 1

        guardrails = [
            ShadowGuardrailSummary(
                guardrail_id=guardrail_id,
                guardrail_version=version,
                stage=stage,
                evaluation_count=data["evaluations"],
                affected_invocation_count=len(data["affected"]),
                allow_count=len(data["effect_scopes"]["allow"]),
                warn_count=len(data["effect_scopes"]["warn"]),
                would_deny_count=len(data["effect_scopes"]["deny"]),
                would_escalate_count=len(data["effect_scopes"]["escalate"]),
                would_transform_count=len(data["effect_scopes"]["transform"]),
                conflict_count=data["conflicts"],
                reason_code_counts=dict(sorted(data["reasons"].items())),
            )
            for (guardrail_id, version, stage), data in sorted(summaries.items())
        ]
        return {
            "evaluation_count": len(variants),
            "affected_invocation_count": len(affected),
            "would_deny_count": len(effect_scopes["deny"]),
            "would_escalate_count": len(effect_scopes["escalate"]),
            "would_transform_count": len(effect_scopes["transform"]),
            "conflict_count": len(conflicts),
            "guardrails": guardrails,
        }

    @staticmethod
    def _select_terminal_events(
        events: list[AuditEvent],
    ) -> tuple[list[AuditEvent], dict[str, list[AuditEvent]], int, int]:
        """Collapse lifecycle records to one truthful terminal per invocation."""
        groups: dict[str, list[AuditEvent]] = {}
        indexed: dict[str, list[tuple[int, AuditEvent]]] = {}
        for index, event in enumerate(events):
            if event.event_type == "legacy":
                key = f"legacy:{index}:{event.event_id}"
            elif event.invocation_id:
                key = f"v2:{event.invocation_id}"
            else:
                key = f"v2-missing:{index}:{event.event_id}"
            groups.setdefault(key, []).append(event)
            indexed.setdefault(key, []).append((index, event))

        def priority(event: AuditEvent) -> int:
            if event.event_type == "delivery_denied":
                return 8
            if event.event_type == "delivery_escalated":
                return 7
            if event.event_type == "delivery_completed":
                return 6
            if event.event_type == "execution_reconciled":
                return 5
            if event.event_type == "execution_completed" and event.result == "error":
                return 4
            if event.event_type in {"denial", "rejection", "escalation"}:
                return 3
            if event.event_type == "legacy":
                return 2
            return 0

        terminals: list[tuple[int, AuditEvent]] = []
        incomplete = 0
        in_doubt = 0
        for records in indexed.values():
            candidates = [(priority(event), index, event) for index, event in records]
            selected = max(candidates, key=lambda item: (item[0], item[1]))
            if selected[0] == 0:
                reconciliation = [
                    (index, event)
                    for index, event in records
                    if event.event_type
                    in {"execution_in_doubt", "execution_reconciliation_resumed"}
                ]
                if reconciliation and max(reconciliation)[1].event_type == "execution_in_doubt":
                    in_doubt += 1
                else:
                    incomplete += 1
            else:
                terminals.append((selected[1], selected[2]))

        terminals.sort(key=lambda item: item[0])
        return [event for _, event in terminals], groups, incomplete, in_doubt

    def to_json(self, metrics: DashboardMetrics) -> str:
        """Serialize dashboard metrics to JSON.

        Args:
            metrics: The metrics to serialize.

        Returns:
            Indented JSON string.
        """
        return metrics.model_dump_json(indent=2)

    def to_markdown(self, metrics: DashboardMetrics) -> str:
        """Render dashboard metrics as Markdown.

        Args:
            metrics: The metrics to render.

        Returns:
            Markdown-formatted report.
        """
        lines = [
            "# AgentGuard Dashboard",
            "",
            f"**Events analyzed:** {metrics.total_events}",
            f"**Allowed:** {metrics.allowed_count}",
            f"**Denied:** {metrics.denied_count}",
            f"**Errors:** {metrics.error_count}",
            f"**Escalated:** {metrics.escalated_count}",
            f"**Rejected:** {metrics.rejected_count}",
            f"**Executions in doubt:** {metrics.in_doubt_count}",
            f"**Incomplete traces:** {metrics.incomplete_count}",
            f"**Denial rate:** {metrics.denial_rate * 100:.2f}%",
            "",
            "## Latency (ms)",
            "",
            f"- p50: {metrics.latency_p50_ms:.2f}",
            f"- p95: {metrics.latency_p95_ms:.2f}",
            f"- p99: {metrics.latency_p99_ms:.2f}",
        ]
        if metrics.shadow_evaluation_count:
            lines.extend(
                [
                    "",
                    "## Shadow guardrail observations (not enforced)",
                    "",
                    f"- Evaluations: {metrics.shadow_evaluation_count}",
                    f"- Affected invocations: {metrics.shadow_affected_invocation_count}",
                    f"- Would deny: {metrics.shadow_would_deny_count}",
                    f"- Would escalate: {metrics.shadow_would_escalate_count}",
                    f"- Would transform: {metrics.shadow_would_transform_count}",
                    f"- Conflicting duplicates: {metrics.shadow_conflict_count}",
                    "",
                    "| Guardrail | Stage | Evaluations | Affected | Allow | Warn "
                    "| Deny | Escalate | Transform | Conflicts |",
                    "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
                ]
            )
            for guardrail in metrics.shadow_guardrails:
                lines.append(
                    f"| {guardrail.guardrail_id}@{guardrail.guardrail_version} "
                    f"| {guardrail.stage} "
                    f"| {guardrail.evaluation_count} "
                    f"| {guardrail.affected_invocation_count} "
                    f"| {guardrail.allow_count} "
                    f"| {guardrail.warn_count} "
                    f"| {guardrail.would_deny_count} "
                    f"| {guardrail.would_escalate_count} "
                    f"| {guardrail.would_transform_count} "
                    f"| {guardrail.conflict_count} |"
                )
        hitl_total = (
            metrics.escalation_requested_count
            + metrics.approval_granted_count
            + metrics.approval_denied_count
            + metrics.approval_expired_count
            + metrics.escalation_resumed_count
        )
        if hitl_total:
            lines.extend(
                [
                    "",
                    "## HITL lifecycle",
                    "",
                    f"- Escalations requested: {metrics.escalation_requested_count}",
                    f"- Approvals granted: {metrics.approval_granted_count}",
                    f"- Approvals denied: {metrics.approval_denied_count}",
                    f"- Approvals expired: {metrics.approval_expired_count}",
                    f"- Escalations resumed: {metrics.escalation_resumed_count}",
                ]
            )
        if metrics.time_range_start and metrics.time_range_end:
            lines.extend(
                [
                    "",
                    "## Time range",
                    "",
                    f"- Start: {metrics.time_range_start.isoformat()}",
                    f"- End:   {metrics.time_range_end.isoformat()}",
                ]
            )
        if metrics.top_actions:
            lines.extend(["", "## Top actions", "", "| Action | Count |", "|---|---|"])
            for action, count in metrics.top_actions:
                lines.append(f"| {action} | {count} |")
        if metrics.agent_metrics:
            lines.extend(
                [
                    "",
                    "## Per-agent activity",
                    "",
                    "| Agent | Total | Allowed | Denied | Errors | Escalated | Denial Rate |",
                    "|---|---|---|---|---|---|---|",
                ]
            )
            for am in metrics.agent_metrics:
                lines.append(
                    f"| {am.agent_id} | {am.total_actions} | {am.allowed} "
                    f"| {am.denied} | {am.errors} | {am.escalated} "
                    f"| {am.denial_rate * 100:.1f}% |"
                )
        if metrics.policy_violations:
            lines.extend(
                [
                    "",
                    "## Policy violations",
                    "",
                    "| Rule | Count | Last violation |",
                    "|---|---|---|",
                ]
            )
            for pv in metrics.policy_violations:
                last = pv.last_violation.isoformat() if pv.last_violation else "—"
                lines.append(f"| {pv.rule_id} | {pv.violation_count} | {last} |")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _percentile(sorted_data: list[float], percentile: int) -> float:
        """Compute percentile from pre-sorted data.

        Args:
            sorted_data: Sorted list of values.
            percentile: Percentile to compute (0-100).

        Returns:
            The percentile value.
        """
        if not sorted_data:
            return 0.0
        k = (len(sorted_data) - 1) * percentile / 100
        f = int(k)
        c = f + 1
        if c >= len(sorted_data):
            return sorted_data[f]
        return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])
