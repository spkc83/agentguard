"""Tests for agentguard.compliance.formal_verifier — Z3 verification."""

from __future__ import annotations

import pytest

from agentguard.compliance.formal_verifier import FormalVerifier, VerificationResult
from agentguard.core.rbac import Permission, Role


class TestFormalVerifier:
    def test_rbac_escalation_safe(self) -> None:
        """Verify that analyst role cannot reach admin permission.

        Sorted perm_list: [('tool:admin','admin/*'), ('tool:read','data/*')]
        Index 0 = tool:admin (admin only), Index 1 = tool:read (both).
        Without admin role, index 0 should be unreachable.
        """
        roles = [
            Role(
                name="analyst",
                permissions=[
                    Permission(action="tool:read", resource="data/*", effect="allow"),
                ],
            ),
            Role(
                name="admin",
                permissions=[
                    Permission(action="tool:read", resource="data/*", effect="allow"),
                    Permission(action="tool:admin", resource="admin/*", effect="allow"),
                ],
            ),
        ]
        verifier = FormalVerifier()
        # Index 0 = (tool:admin, admin/*) — should not be reachable without admin role
        result = verifier.verify_rbac_escalation(
            roles=roles,
            target_permission_index=0,
            forbidden_roles=["admin"],
        )
        assert result.status == "unsat"

    def test_rbac_escalation_detected(self) -> None:
        """Verify that analyst role can reach its own permission (index 0)."""
        roles = [
            Role(
                name="analyst",
                permissions=[
                    Permission(action="tool:read", resource="data/*", effect="allow"),
                ],
            ),
        ]
        verifier = FormalVerifier()
        # Only one permission: (tool:read, data/*) at index 0 — reachable via analyst
        result = verifier.verify_rbac_escalation(
            roles=roles,
            target_permission_index=0,
        )
        assert result.status == "sat"
        assert "analyst" in result.counterexample

    def test_policy_consistency_no_contradictions(self) -> None:
        rules = [
            {"id": "R1", "action_keyword": "read", "resource_keyword": "data", "effect": "allow"},
            {"id": "R2", "action_keyword": "write", "resource_keyword": "data", "effect": "allow"},
        ]
        verifier = FormalVerifier()
        result = verifier.verify_policy_consistency(rules)
        assert result.status == "unsat"

    def test_policy_consistency_contradiction_found(self) -> None:
        rules = [
            {"id": "R1", "action_keyword": "read", "resource_keyword": "data", "effect": "allow"},
            {"id": "R2", "action_keyword": "read", "resource_keyword": "data", "effect": "deny"},
        ]
        verifier = FormalVerifier()
        result = verifier.verify_policy_consistency(rules)
        assert result.status == "sat"
        assert len(result.details["contradictions"]) == 1

    def test_workflow_safety_with_hitl(self) -> None:
        """Target is not reachable without HITL — safe."""
        nodes = ["start", "hitl_review", "execute"]
        edges = [("start", "hitl_review"), ("hitl_review", "execute")]
        hitl_nodes = {"hitl_review"}

        verifier = FormalVerifier()
        result = verifier.verify_workflow_safety(
            nodes=nodes,
            edges=edges,
            hitl_nodes=hitl_nodes,
            source="start",
            target="execute",
        )
        assert result.status == "unsat"

    def test_workflow_safety_without_hitl(self) -> None:
        """Target is reachable without HITL — unsafe."""
        nodes = ["start", "process", "execute"]
        edges = [("start", "process"), ("process", "execute")]
        hitl_nodes: set[str] = set()

        verifier = FormalVerifier()
        result = verifier.verify_workflow_safety(
            nodes=nodes,
            edges=edges,
            hitl_nodes=hitl_nodes,
            source="start",
            target="execute",
        )
        assert result.status == "sat"

    def test_workflow_single_node(self) -> None:
        """A single node with no edges — target equals source but no path exists."""
        verifier = FormalVerifier()
        result = verifier.verify_workflow_safety(
            nodes=["start", "end"],
            edges=[],
            hitl_nodes=set(),
            source="start",
            target="end",
        )
        # No edges means target is unreachable — safe
        assert result.status == "unsat"

    def test_empty_policy_rules(self) -> None:
        verifier = FormalVerifier()
        result = verifier.verify_policy_consistency([])
        assert result.status == "unsat"


class TestVerificationResult:
    def test_result_is_frozen(self) -> None:
        result = VerificationResult(
            property_name="test",
            status="unsat",
        )
        with pytest.raises(Exception):
            result.status = "sat"  # type: ignore[misc]
