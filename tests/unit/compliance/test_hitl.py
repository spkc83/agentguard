"""Tests for agentguard.compliance.hitl — HITL escalation."""

from __future__ import annotations

import pytest

from agentguard.compliance.hitl import (
    ApprovalDecision,
    HitlEscalation,
    HitlManager,
)


def _make_escalation(
    action: str = "tool:credit_decision",
) -> HitlEscalation:
    return HitlEscalation(
        escalation_id="esc-1",
        agent_id="agent-1",
        action=action,
        resource="loan/application-123",
        reason="Credit decision requires human review",
    )


class TestHitlManager:
    async def test_auto_approve_mode(self) -> None:
        manager = HitlManager(escalation_mode="auto_approve")
        decision = await manager.escalate(_make_escalation())
        assert decision.approved is True
        assert decision.approver_id == "system:auto_approve"

    async def test_auto_deny_mode(self) -> None:
        manager = HitlManager(escalation_mode="auto_deny")
        decision = await manager.escalate(_make_escalation())
        assert decision.approved is False
        assert decision.approver_id == "system:auto_deny"

    async def test_no_handler_denies(self) -> None:
        manager = HitlManager(escalation_mode="block")
        decision = await manager.escalate(_make_escalation())
        assert decision.approved is False
        assert "no_handler" in decision.approver_id

    async def test_custom_handler(self) -> None:
        async def approve_handler(esc: HitlEscalation) -> ApprovalDecision:
            return ApprovalDecision(
                approved=True,
                approver_id="human-1",
                reason="Approved by reviewer",
            )

        manager = HitlManager(handler=approve_handler, escalation_mode="block")
        decision = await manager.escalate(_make_escalation())
        assert decision.approved is True
        assert decision.approver_id == "human-1"

    async def test_history_tracked(self) -> None:
        manager = HitlManager(escalation_mode="auto_approve")
        await manager.escalate(_make_escalation())
        await manager.escalate(_make_escalation())
        assert len(manager.history) == 2

    async def test_custom_deny_handler(self) -> None:
        async def deny_handler(esc: HitlEscalation) -> ApprovalDecision:
            return ApprovalDecision(
                approved=False,
                approver_id="human-2",
                reason="Too risky",
            )

        manager = HitlManager(handler=deny_handler, escalation_mode="block")
        decision = await manager.escalate(_make_escalation())
        assert decision.approved is False


class TestHitlEscalation:
    def test_escalation_is_frozen(self) -> None:
        esc = _make_escalation()
        with pytest.raises(Exception):
            esc.agent_id = "modified"  # type: ignore[misc]


class TestApprovalDecision:
    def test_decision_is_frozen(self) -> None:
        decision = ApprovalDecision(approved=True, approver_id="test")
        with pytest.raises(Exception):
            decision.approved = False  # type: ignore[misc]
