"""Audit log replay debugger.

Reads audit events and replays them with structured output for debugging
governance decisions. Supports filtering by agent, action, time range,
and result type.

Usage:
    from agentguard.observability.replay import ReplayDebugger

    debugger = ReplayDebugger()
    events = await debugger.load(audit_dir=Path("./audit-logs"))
    filtered = debugger.filter(agent_id="agent-001", result="denied")
    timeline = debugger.timeline(filtered)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path  # noqa: TC003 — used at runtime in load()
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

from agentguard.core.audit import FileAuditBackend
from agentguard.models import AuditEvent

logger = structlog.get_logger()


class ReplayEntry(BaseModel):
    """A single entry in the replay timeline.

    Args:
        index: Position in the replay sequence.
        event: The original audit event.
        decision_summary: Human-readable summary of the governance decision.
        flags: Warning flags (e.g. "chain_break", "denied", "policy_violation").
    """

    model_config = ConfigDict(frozen=True)

    index: int
    event: AuditEvent
    decision_summary: str
    flags: list[str] = []


class ReplayDebugger:
    """Audit log replay and debugging tool.

    Loads audit events and provides filtering, timeline generation,
    and decision analysis for debugging governance issues.
    """

    async def load(self, audit_dir: Path) -> list[AuditEvent]:
        """Load all audit events from a directory, sorted by timestamp.

        Args:
            audit_dir: Path to the audit log directory.

        Returns:
            List of audit events sorted by timestamp (ascending).
        """
        backend = FileAuditBackend(directory=audit_dir)
        events = await backend.read_all()
        events.sort(key=lambda e: e.timestamp)
        logger.info("replay_events_loaded", count=len(events), dir=str(audit_dir))
        return events

    def filter(
        self,
        events: list[AuditEvent],
        agent_id: str | None = None,
        action: str | None = None,
        result: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[AuditEvent]:
        """Filter audit events by criteria.

        Args:
            events: Events to filter.
            agent_id: Filter by agent ID.
            action: Filter by action (substring match).
            result: Filter by result (allowed, denied, escalated, error).
            start_time: Include events at or after this time.
            end_time: Include events at or before this time.

        Returns:
            Filtered list of events.
        """
        filtered = events

        if agent_id:
            filtered = [e for e in filtered if e.agent_id == agent_id]

        if action:
            filtered = [e for e in filtered if action in e.action]

        if result:
            filtered = [e for e in filtered if e.result == result]

        if start_time:
            filtered = [e for e in filtered if e.timestamp >= start_time]

        if end_time:
            filtered = [e for e in filtered if e.timestamp <= end_time]

        return filtered

    def timeline(self, events: list[AuditEvent]) -> list[ReplayEntry]:
        """Generate a replay timeline from audit events.

        Produces a chronological sequence of ReplayEntry objects with
        human-readable summaries and warning flags.

        Args:
            events: Audit events to replay.

        Returns:
            Ordered list of ReplayEntry objects.
        """
        entries: list[ReplayEntry] = []

        for i, event in enumerate(events):
            flags: list[str] = []
            summary_parts: list[str] = []

            # Build decision summary
            summary_parts.append(
                f"Agent {event.agent_id[:12]} -> {event.action} on {event.resource}"
            )

            if event.result == "denied":
                flags.append("denied")
                summary_parts.append(f"DENIED: {event.permission_context.reason}")
            elif event.result == "error":
                flags.append("error")
                summary_parts.append("ERROR during execution")
            elif event.result == "escalated":
                flags.append("escalated")
                summary_parts.append("Escalated to human review")
            else:
                summary_parts.append("Allowed")

            # Check for policy violations
            failed_policies = [p for p in event.policy_results if not p.passed]
            if failed_policies:
                flags.append("policy_violation")
                for p in failed_policies:
                    summary_parts.append(f"Policy {p.rule_id} failed ({p.severity})")

            entries.append(
                ReplayEntry(
                    index=i,
                    event=event,
                    decision_summary=" | ".join(summary_parts),
                    flags=flags,
                )
            )

        return entries

    def summarize(self, events: list[AuditEvent]) -> dict[str, Any]:
        """Produce a summary of replay events.

        Args:
            events: Audit events to summarize.

        Returns:
            Dict with counts by result, agent, action, and flagged events.
        """
        result_counts: dict[str, int] = {}
        agent_counts: dict[str, int] = {}
        action_counts: dict[str, int] = {}

        for event in events:
            result_counts[event.result] = result_counts.get(event.result, 0) + 1
            agent_counts[event.agent_id] = agent_counts.get(event.agent_id, 0) + 1
            action_counts[event.action] = action_counts.get(event.action, 0) + 1

        return {
            "total_events": len(events),
            "by_result": result_counts,
            "by_agent": agent_counts,
            "by_action": action_counts,
        }
