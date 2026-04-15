"""Human-in-the-loop escalation patterns.

HITL is triggered when a policy rule or RBAC configuration requires
human approval before an agent action can proceed. The escalation is
callback-based: AgentGuard produces the escalation event, the calling
application provides the approval handler.

Built-in handlers:
- LogAndApproveHandler: Auto-approve with logging (dev/testing only).
- CallbackHandler: Delegate to an async callback function.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from pydantic import BaseModel, ConfigDict

logger = structlog.get_logger()


class HitlEscalation(BaseModel):
    """An escalation request requiring human decision.

    Args:
        escalation_id: Unique ID for this escalation.
        agent_id: The agent requesting the action.
        action: The action being escalated.
        resource: The target resource.
        reason: Why escalation was triggered.
        policy_rule_id: The policy rule that triggered escalation (if any).
        context: Additional context for the approver.
        timestamp: When the escalation was created.
    """

    model_config = ConfigDict(frozen=True)

    escalation_id: str
    agent_id: str
    action: str
    resource: str
    reason: str
    policy_rule_id: str = ""
    context: dict[str, Any] = {}
    timestamp: datetime = datetime.now(UTC)


class ApprovalDecision(BaseModel):
    """A human's decision on an escalation request.

    Args:
        approved: Whether the action was approved.
        approver_id: Who made the decision.
        reason: Why the decision was made.
        timestamp: When the decision was made.
    """

    model_config = ConfigDict(frozen=True)

    approved: bool
    approver_id: str
    reason: str = ""
    timestamp: datetime = datetime.now(UTC)


# Type alias for HITL handler functions
HitlHandler = Callable[[HitlEscalation], Awaitable[ApprovalDecision]]


class HitlManager:
    """Manages HITL escalations and routes them to the configured handler.

    Args:
        handler: Async function that processes escalation requests.
        escalation_mode: How to handle escalations.
            - "block": Block until human responds (default).
            - "auto_approve": Auto-approve and log (dev only).
            - "auto_deny": Auto-deny all escalations.
    """

    def __init__(
        self,
        handler: HitlHandler | None = None,
        escalation_mode: Literal["block", "auto_approve", "auto_deny"] = "block",
    ) -> None:
        self._handler = handler
        self._mode = escalation_mode
        self._history: list[tuple[HitlEscalation, ApprovalDecision]] = []

    async def escalate(self, escalation: HitlEscalation) -> ApprovalDecision:
        """Process an escalation through the configured handler.

        Args:
            escalation: The escalation request.

        Returns:
            The approval decision.
        """
        logger.info(
            "hitl_escalation_created",
            escalation_id=escalation.escalation_id,
            agent_id=escalation.agent_id,
            action=escalation.action,
            reason=escalation.reason,
        )

        if self._mode == "auto_approve":
            decision = ApprovalDecision(
                approved=True,
                approver_id="system:auto_approve",
                reason="Auto-approved (development mode)",
            )
        elif self._mode == "auto_deny":
            decision = ApprovalDecision(
                approved=False,
                approver_id="system:auto_deny",
                reason="Auto-denied (escalation mode: auto_deny)",
            )
        elif self._handler is not None:
            decision = await self._handler(escalation)
        else:
            decision = ApprovalDecision(
                approved=False,
                approver_id="system:no_handler",
                reason="No HITL handler configured; denied by default",
            )

        self._history.append((escalation, decision))

        logger.info(
            "hitl_decision_made",
            escalation_id=escalation.escalation_id,
            approved=decision.approved,
            approver_id=decision.approver_id,
        )
        return decision

    @property
    def history(self) -> list[tuple[HitlEscalation, ApprovalDecision]]:
        """Return the escalation history."""
        return list(self._history)
