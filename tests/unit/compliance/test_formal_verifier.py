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
        pytest.importorskip("z3")
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
        pytest.importorskip("z3")
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
        pytest.importorskip("z3")
        rules = [
            {"id": "R1", "action_keyword": "read", "resource_keyword": "data", "effect": "allow"},
            {"id": "R2", "action_keyword": "write", "resource_keyword": "data", "effect": "allow"},
        ]
        verifier = FormalVerifier()
        result = verifier.verify_policy_consistency(rules)
        assert result.status == "unsat"

    def test_policy_consistency_contradiction_found(self) -> None:
        pytest.importorskip("z3")
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
        pytest.importorskip("z3")
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
        pytest.importorskip("z3")
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
        pytest.importorskip("z3")
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
        pytest.importorskip("z3")
        verifier = FormalVerifier()
        result = verifier.verify_policy_consistency([])
        assert result.status == "unsat"

    def test_workflow_unknown_when_source_or_target_missing(self) -> None:
        """Source or target absent from node list -> unknown, not raise."""
        pytest.importorskip("z3")
        verifier = FormalVerifier()
        r1 = verifier.verify_workflow_safety(
            nodes=["a", "b"],
            edges=[("a", "b")],
            hitl_nodes=set(),
            source="ghost",
            target="b",
        )
        assert r1.status == "unknown"

        r2 = verifier.verify_workflow_safety(
            nodes=["a", "b"],
            edges=[("a", "b")],
            hitl_nodes=set(),
            source="a",
            target="ghost",
        )
        assert r2.status == "unknown"

    def test_compliance_engine_imports_without_z3(self) -> None:
        """R6 C3: the rest of the compliance layer must be usable without z3 loaded.

        Verified structurally: agentguard.compliance.engine and agentguard.compliance.hitl
        do not import from z3 or z3_models at module level. A full 'z3 missing' smoke
        test would require a subprocess/fresh interpreter; the structural check
        documents the lazy-import contract established by ADR-013.
        """
        import ast
        from pathlib import Path

        from agentguard.compliance import engine as engine_mod
        from agentguard.compliance import hitl as hitl_mod

        for mod in (engine_mod, hitl_mod):
            src = Path(mod.__file__).read_text()
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    assert not any(n.name.startswith("z3") for n in node.names), (
                        f"{mod.__name__} imports z3 at module top level"
                    )
                if isinstance(node, ast.ImportFrom):
                    assert node.module is None or not node.module.startswith("z3"), (
                        f"{mod.__name__} imports from z3 at module top level"
                    )
                    assert node.module != "agentguard.compliance.z3_models", (
                        f"{mod.__name__} imports z3_models at module top level "
                        "(must be deferred to keep z3 optional)"
                    )


class TestVerificationResult:
    def test_result_is_frozen(self) -> None:
        result = VerificationResult(
            property_name="test",
            status="unsat",
        )
        with pytest.raises(Exception):
            result.status = "sat"  # type: ignore[misc]
