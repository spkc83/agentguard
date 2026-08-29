"""Tests for agentguard.compliance.formal_verifier — Z3 verification."""

from __future__ import annotations

import pytest

from agentguard.compliance.formal_verifier import FormalVerifier, VerificationResult
from agentguard.core.rbac import Permission, Role


def _permission_index(roles: list[Role], action: str, resource: str) -> int:
    permissions = sorted(
        {
            (permission.action, permission.resource)
            for role in roles
            for permission in role.permissions
        }
    )
    return permissions.index((action, resource))


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
            {
                "id": "R1",
                "kind": "authorization",
                "action_patterns": ["data:read"],
                "resource_patterns": ["data/*"],
                "effect": "allow",
            },
            {
                "id": "R2",
                "kind": "authorization",
                "action_patterns": ["data:write"],
                "resource_patterns": ["data/*"],
                "effect": "deny",
            },
        ]
        verifier = FormalVerifier()
        result = verifier.verify_policy_consistency(rules)
        assert result.status == "unsat"

    def test_policy_consistency_contradiction_found(self) -> None:
        pytest.importorskip("z3")
        rules = [
            {
                "id": "R1",
                "kind": "authorization",
                "action_patterns": ["data:*"],
                "resource_patterns": ["data/*"],
                "effect": "allow",
            },
            {
                "id": "R2",
                "kind": "authorization",
                "action_patterns": ["data:read"],
                "resource_patterns": ["data/private/*"],
                "effect": "deny",
            },
        ]
        verifier = FormalVerifier()
        result = verifier.verify_policy_consistency(rules)
        assert result.status == "sat"
        assert len(result.details["contradictions"]) == 1

    def test_policy_consistency_rejects_severity_derived_effects(self) -> None:
        """Compliance severity is not an authorization effect."""
        pytest.importorskip("z3")
        result = FormalVerifier().verify_policy_consistency(
            [
                {
                    "id": "R1",
                    "action_keyword": "read",
                    "resource_keyword": "",
                    "effect": "deny",
                }
            ]
        )

        assert result.status == "unknown"
        assert result.details["reason"] == "unsupported_policy_rule_schema"

    def test_policy_consistency_rejects_unsupported_fnmatch_syntax(self) -> None:
        pytest.importorskip("z3")
        result = FormalVerifier().verify_policy_consistency(
            [
                {
                    "id": "R1",
                    "kind": "authorization",
                    "action_patterns": ["data:[rw]ead"],
                    "resource_patterns": ["data/*"],
                    "effect": "allow",
                }
            ]
        )

        assert result.status == "unknown"
        assert "unsupported fnmatch" in result.details["reason"]

    def test_rbac_wildcard_permission_reaches_literal_target(self) -> None:
        pytest.importorskip("z3")
        roles = [
            Role(
                name="target-catalog",
                permissions=[
                    Permission(
                        action="tool:credit_check",
                        resource="bureau/experian",
                        effect="deny",
                    )
                ],
            ),
            Role(
                name="analyst",
                permissions=[Permission(action="tool:*", resource="bureau/*", effect="allow")],
            ),
        ]

        result = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=_permission_index(
                roles, "tool:credit_check", "bureau/experian"
            ),
            forbidden_roles=["target-catalog"],
        )

        assert result.status == "sat"
        assert result.details["action"] == "tool:credit_check"
        assert result.details["resource"] == "bureau/experian"

    def test_rbac_inherited_permission_reaches_target(self) -> None:
        pytest.importorskip("z3")
        roles = [
            Role(
                name="base",
                permissions=[Permission(action="tool:*", resource="bureau/*", effect="allow")],
            ),
            Role(name="analyst", inherited_roles=["base"]),
            Role(
                name="target-catalog",
                permissions=[
                    Permission(
                        action="tool:credit_check",
                        resource="bureau/experian",
                        effect="deny",
                    )
                ],
            ),
        ]

        result = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=_permission_index(
                roles, "tool:credit_check", "bureau/experian"
            ),
            forbidden_roles=["base", "target-catalog"],
        )

        assert result.status == "sat"
        assert result.details["assigned_roles"] == ["analyst"]

    def test_rbac_inherited_deny_overrides_wildcard_allow(self) -> None:
        pytest.importorskip("z3")
        roles = [
            Role(
                name="base",
                permissions=[
                    Permission(
                        action="tool:credit_check",
                        resource="bureau/*",
                        effect="deny",
                    )
                ],
            ),
            Role(
                name="analyst",
                permissions=[Permission(action="tool:*", resource="bureau/*", effect="allow")],
                inherited_roles=["base"],
            ),
            Role(
                name="target-catalog",
                permissions=[
                    Permission(
                        action="tool:credit_check",
                        resource="bureau/experian",
                        effect="deny",
                    )
                ],
            ),
        ]

        result = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=_permission_index(
                roles, "tool:credit_check", "bureau/experian"
            ),
            forbidden_roles=["base", "target-catalog"],
        )

        assert result.status == "unsat"

    def test_rbac_unsupported_fnmatch_is_unknown(self) -> None:
        pytest.importorskip("z3")
        roles = [
            Role(
                name="analyst",
                permissions=[Permission(action="tool:[rc]ead", resource="data/*", effect="allow")],
            )
        ]

        result = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=0,
        )

        assert result.status == "unknown"
        assert "unsupported fnmatch" in result.details["reason"]

    def test_rbac_codepoint_above_z3_regex_maximum_is_unknown(self) -> None:
        pytest.importorskip("z3")
        unsupported = chr(0x30000)
        roles = [
            Role(
                name="target-catalog",
                permissions=[Permission(action=unsupported, resource="x", effect="deny")],
            ),
            Role(
                name="candidate",
                permissions=[Permission(action="*", resource="x", effect="allow")],
            ),
        ]

        result = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=_permission_index(roles, unsupported, "x"),
            forbidden_roles=["target-catalog"],
        )

        assert Permission(action="*", resource="x", effect="allow").matches(unsupported, "x")
        assert result.status == "unknown"
        assert "U+2FFFF" in result.details["reason"]

    def test_rbac_action_case_sensitive_resource_case_insensitive(self) -> None:
        pytest.importorskip("z3")
        roles = [
            Role(
                name="target-catalog",
                permissions=[
                    Permission(
                        action="tool:read",
                        resource="admin/key",
                        effect="deny",
                    )
                ],
            ),
            Role(
                name="wrong-action-case",
                permissions=[Permission(action="TOOL:*", resource="ADMIN/*", effect="allow")],
            ),
            Role(
                name="right-action-case",
                permissions=[Permission(action="tool:*", resource="ADMIN/*", effect="allow")],
            ),
        ]
        target_index = _permission_index(roles, "tool:read", "admin/key")

        wrong_case = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=target_index,
            forbidden_roles=["target-catalog", "right-action-case"],
        )
        resource_casefolded = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=target_index,
            forbidden_roles=["target-catalog", "wrong-action-case"],
        )

        assert wrong_case.status == "unsat"
        assert resource_casefolded.status == "sat"

    def test_rbac_sat_counterexample_replays_nonprintable_witness(self) -> None:
        pytest.importorskip("z3")
        roles = [
            Role(
                name="target-catalog",
                permissions=[Permission(action="?", resource=":", effect="deny")],
            ),
            Role(
                name="candidate",
                permissions=[Permission(action="*", resource=":", effect="allow")],
            ),
        ]

        result = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=_permission_index(roles, "?", ":"),
            forbidden_roles=["target-catalog"],
        )

        assert result.status == "sat"
        assert len(result.details["action"]) == 1
        assert roles[0].permissions[0].matches(result.details["action"], result.details["resource"])

    def test_shipped_policy_projection_is_not_certified(self) -> None:
        """The CLI's legacy projection cannot manufacture policy effects."""
        pytest.importorskip("z3")
        from agentguard.compliance.engine import PolicyEngine

        projected = []
        for rule in PolicyEngine().all_rules:
            check = rule.check
            patterns = check.get("patterns", [""])
            projected.append(
                {
                    "id": rule.id,
                    "action_keyword": patterns[0] if patterns else "",
                    "resource_keyword": "",
                    "effect": "deny" if rule.severity == "critical" else "allow",
                }
            )

        result = FormalVerifier().verify_policy_consistency(projected)

        assert result.status == "unknown"
        assert "contradictions" not in result.details

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

    def test_formal_verification_imports_z3_lazily(self) -> None:
        """Formal-verification modules must not import z3 at module level.

        Nested imports are allowed because they preserve the optional dependency
        contract established by ADR-013.
        """
        import ast
        from pathlib import Path

        from agentguard.compliance import formal_verifier as formal_verifier_mod
        from agentguard.compliance import z3_models as z3_models_mod

        for mod in (formal_verifier_mod, z3_models_mod):
            src = Path(mod.__file__).read_text(encoding="utf-8")
            tree = ast.parse(src)
            for node in tree.body:
                if isinstance(node, ast.Import):
                    assert not any(n.name.startswith("z3") for n in node.names), (
                        f"{mod.__name__} imports z3 at module top level"
                    )
                if isinstance(node, ast.ImportFrom):
                    assert node.module is None or not node.module.startswith("z3"), (
                        f"{mod.__name__} imports from z3 at module top level"
                    )


class TestVerificationResult:
    def test_result_is_frozen(self) -> None:
        result = VerificationResult(
            property_name="test",
            status="unsat",
        )
        with pytest.raises(Exception):
            result.status = "sat"  # type: ignore[misc]
