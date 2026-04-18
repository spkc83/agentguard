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
from pydantic import BaseModel, ConfigDict

from agentguard.models import AuditEvent

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
    denial_rate: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    agent_metrics: list[AgentMetrics]
    top_actions: list[tuple[str, int]]
    policy_violations: list[PolicyViolationTrend]
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
                denial_rate=0.0,
                latency_p50_ms=0.0,
                latency_p95_ms=0.0,
                latency_p99_ms=0.0,
                agent_metrics=[],
                top_actions=[],
                policy_violations=[],
            )

        # Result counts
        allowed = sum(1 for e in events if e.result == "allowed")
        denied = sum(1 for e in events if e.result == "denied")
        errors = sum(1 for e in events if e.result == "error")
        escalated = sum(1 for e in events if e.result == "escalated")
        total = len(events)

        # Latency percentiles
        durations = [e.duration_ms for e in events if e.duration_ms > 0]
        if durations:
            durations_sorted = sorted(durations)
            p50 = self._percentile(durations_sorted, 50)
            p95 = self._percentile(durations_sorted, 95)
            p99 = self._percentile(durations_sorted, 99)
        else:
            p50 = p95 = p99 = 0.0

        # Per-agent metrics
        agent_data: dict[str, dict[str, int]] = {}
        for e in events:
            if e.agent_id not in agent_data:
                agent_data[e.agent_id] = {
                    "total": 0,
                    "allowed": 0,
                    "denied": 0,
                    "errors": 0,
                    "escalated": 0,
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

        agent_metrics = [
            AgentMetrics(
                agent_id=aid,
                total_actions=d["total"],
                allowed=d["allowed"],
                denied=d["denied"],
                errors=d["errors"],
                escalated=d["escalated"],
                denial_rate=d["denied"] / d["total"] if d["total"] > 0 else 0.0,
            )
            for aid, d in sorted(agent_data.items())
        ]

        # Top actions
        action_counts: dict[str, int] = {}
        for e in events:
            action_counts[e.action] = action_counts.get(e.action, 0) + 1
        top_actions = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Policy violations
        violation_data: dict[str, dict[str, Any]] = {}
        for e in events:
            for pr in e.policy_results:
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

        # Time range
        timestamps = [e.timestamp for e in events]

        return DashboardMetrics(
            total_events=total,
            allowed_count=allowed,
            denied_count=denied,
            error_count=errors,
            escalated_count=escalated,
            denial_rate=denied / total if total > 0 else 0.0,
            latency_p50_ms=p50,
            latency_p95_ms=p95,
            latency_p99_ms=p99,
            agent_metrics=agent_metrics,
            top_actions=top_actions,
            policy_violations=policy_violations,
            time_range_start=min(timestamps),
            time_range_end=max(timestamps),
        )

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
            f"**Denial rate:** {metrics.denial_rate * 100:.2f}%",
            "",
            "## Latency (ms)",
            "",
            f"- p50: {metrics.latency_p50_ms:.2f}",
            f"- p95: {metrics.latency_p95_ms:.2f}",
            f"- p99: {metrics.latency_p99_ms:.2f}",
        ]
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
