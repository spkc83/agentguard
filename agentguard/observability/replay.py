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
from pydantic import BaseModel, ConfigDict, Field

from agentguard.core.audit import FileAuditBackend
from agentguard.models import AuditEvent, EvidenceRef, GuardrailEvaluation

logger = structlog.get_logger()


class ShadowEvaluationView(BaseModel):
    """Observed guardrail effect that shadow mode did not enforce."""

    model_config = ConfigDict(frozen=True)

    guardrail_id: str
    guardrail_version: str
    stage: str
    effect: str
    reason_codes: tuple[str, ...] = ()


class ReconciliationView(BaseModel):
    """Typed, redacted view of authenticated reconciliation evidence."""

    model_config = ConfigDict(frozen=True)

    classification: str
    state: str
    reconciler_id: str


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
    flags: list[str] = Field(default_factory=list)
    shadow_evaluations: tuple[ShadowEvaluationView, ...] = ()
    reconciliation: ReconciliationView | None = None


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
        if events and all(event.sequence is not None for event in events):
            events.sort(key=lambda event: event.sequence or 0)
        else:
            events.sort(key=lambda event: event.timestamp)
        logger.info("replay_events_loaded", count=len(events), dir=str(audit_dir))
        return events

    def filter(
        self,
        events: list[AuditEvent],
        agent_id: str | None = None,
        action: str | None = None,
        result: str | None = None,
        subject_ref: EvidenceRef | None = None,
        linked_ref: EvidenceRef | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[AuditEvent]:
        """Filter audit events by criteria.

        Args:
            events: Events to filter.
            agent_id: Filter by agent ID.
            action: Filter by action (substring match).
            result: Filter by result (allowed, denied, escalated, error).
            subject_ref: Filter by an exact opaque evidence subject reference.
            linked_ref: Filter events carrying a link to this exact reference.
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

        if subject_ref is not None:
            filtered = [e for e in filtered if e.subject_ref == subject_ref]

        if linked_ref is not None:
            filtered = [
                event
                for event in filtered
                if any(link.target == linked_ref for link in event.links)
            ]

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
            shadow_evaluations = tuple(
                self._shadow_view(evaluation)
                for evaluation in event.guardrail_evaluations
                if not evaluation.enforced and evaluation.effect != "allow"
            )
            reconciliation = (
                ReconciliationView(
                    classification=event.reconciliation_evidence.classification,
                    state=event.reconciliation_evidence.state,
                    reconciler_id=event.reconciliation_evidence.reconciler_id,
                )
                if event.reconciliation_evidence is not None
                else None
            )

            # Build decision summary
            summary_parts.append(
                f"Agent {event.agent_id[:12]} -> {event.action} on {event.resource}"
            )

            if event.event_type == "execution_in_doubt":
                flags.append("in_doubt")
                summary_parts.append("Execution outcome is IN DOUBT")
            elif event.event_type == "execution_reconciliation_resumed":
                flags.append("reconciliation_resumed")
                summary_parts.append("Reconciliation resumed from protected outcome")
            elif event.event_type == "execution_reconciled":
                flags.extend(("reconciled", "denied"))
                summary_parts.append("Reconciliation closed with delivery denied")
            elif event.result == "denied":
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

            if reconciliation is not None:
                summary_parts.append(
                    "Reconciliation "
                    f"{reconciliation.classification}/{reconciliation.state} "
                    f"by {reconciliation.reconciler_id}"
                )

            # Check for policy violations
            failed_policies = [p for p in event.policy_results if not p.passed]
            if failed_policies:
                flags.append("policy_violation")
                for p in failed_policies:
                    summary_parts.append(f"Policy {p.rule_id} failed ({p.severity})")

            for evaluation in shadow_evaluations:
                flag = f"shadow_would_{evaluation.effect}"
                if flag not in flags:
                    flags.append(flag)
                reasons = ",".join(evaluation.reason_codes) or "none"
                summary_parts.append(
                    "Shadow "
                    f"{evaluation.guardrail_id}@{evaluation.guardrail_version} "
                    f"would {evaluation.effect} at {evaluation.stage} "
                    f"(reasons: {reasons})"
                )

            entries.append(
                ReplayEntry(
                    index=i,
                    event=event,
                    decision_summary=" | ".join(summary_parts),
                    flags=flags,
                    shadow_evaluations=shadow_evaluations,
                    reconciliation=reconciliation,
                )
            )

        return entries

    @staticmethod
    def _shadow_view(evaluation: GuardrailEvaluation) -> ShadowEvaluationView:
        return ShadowEvaluationView(
            guardrail_id=evaluation.guardrail_id,
            guardrail_version=evaluation.guardrail_version,
            stage=evaluation.stage,
            effect=evaluation.effect,
            reason_codes=evaluation.reason_codes,
        )

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
        subject_counts: dict[str, int] = {}

        for event in events:
            result_counts[event.result] = result_counts.get(event.result, 0) + 1
            agent_counts[event.agent_id] = agent_counts.get(event.agent_id, 0) + 1
            action_counts[event.action] = action_counts.get(event.action, 0) + 1
            if event.subject_ref is not None:
                subject = f"{event.subject_ref.namespace}:{event.subject_ref.value}"
                subject_counts[subject] = subject_counts.get(subject, 0) + 1

        return {
            "total_events": len(events),
            "by_result": result_counts,
            "by_agent": agent_counts,
            "by_action": action_counts,
            "by_subject": subject_counts,
        }
