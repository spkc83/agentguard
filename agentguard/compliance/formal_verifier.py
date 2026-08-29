"""Z3-based formal verification for RBAC and policy properties.

Runs as a static analysis tool — does NOT sit in the runtime hot path.
Answers questions that runtime checks cannot: not "was this action allowed?"
but "is it possible for any agent to reach this forbidden state?"

Properties that can be verified:
1. RBAC privilege escalation absence (bitvector encoding)
2. Policy set consistency (contradiction and dead-rule detection)
3. Workflow safety — no path to resource X without HITL (reachability)

Z3 is imported lazily so formal verification is an optional feature.
"""

from __future__ import annotations

from typing import Any, Literal

import structlog
from pydantic import BaseModel, ConfigDict

from agentguard.compliance.z3_models import (
    UnsupportedEncodingError,
    encode_policy_consistency,
    encode_rbac_reachability,
)
from agentguard.core.rbac import Permission, Role

logger = structlog.get_logger()


class VerificationResult(BaseModel):
    """Result of a formal verification check.

    Args:
        property_name: What was being verified.
        status: Z3 result — sat (property violated), unsat (property holds),
            timeout, or unknown.
        counterexample: If sat, a human-readable description of the violation.
        details: Additional verification details.
    """

    model_config = ConfigDict(frozen=True)

    property_name: str
    status: Literal["sat", "unsat", "timeout", "unknown"]
    counterexample: str = ""
    details: dict[str, Any] = {}


class FormalVerifier:
    """Z3-based formal verifier for AgentGuard properties.

    All verification runs are time-bounded (default 10 seconds).
    Results include human-readable counterexamples when violations
    are found.
    """

    def __init__(self, timeout_ms: int = 10000) -> None:
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        self._timeout_ms = timeout_ms

    @staticmethod
    def _permissions_by_assignable_role(roles: list[Role]) -> list[dict[str, Any]]:
        """Flatten role inheritance exactly as ``RBACEngine`` does at runtime."""
        role_map = {role.name: role for role in roles}

        def collect(role_name: str, visited: set[str] | None = None) -> list[Permission]:
            if visited is None:
                visited = set()
            if role_name in visited:
                return []
            visited.add(role_name)
            role = role_map.get(role_name)
            if role is None:
                return []
            permissions = list(role.permissions)
            for parent_name in role.inherited_roles:
                permissions.extend(collect(parent_name, visited))
            return permissions

        return [
            {
                "name": role_name,
                "permissions": [permission.model_dump() for permission in collect(role_name)],
            }
            for role_name in role_map
        ]

    @staticmethod
    def _model_string(model: Any, expression: Any, z3: Any) -> str:
        """Extract a concrete Z3 string without display-escape ambiguity."""
        value = model.evaluate(expression, model_completion=True)
        length = model.evaluate(z3.Length(value), model_completion=True).as_long()
        characters: list[str] = []
        for index in range(length):
            codepoint = model.evaluate(
                z3.StrToCode(z3.SubString(value, index, 1)),
                model_completion=True,
            ).as_long()
            characters.append(chr(codepoint))
        return "".join(characters)

    def verify_rbac_escalation(
        self,
        roles: list[Role],
        target_permission_index: int,
        forbidden_roles: list[str] | None = None,
    ) -> VerificationResult:
        """Verify that no combination of roles can reach a forbidden permission.

        Proves: for all agents, if they are not assigned any forbidden role,
        they cannot reach the target permission.

        Args:
            roles: The RBAC role definitions.
            target_permission_index: Index of the permission to check.
            forbidden_roles: Roles that should NOT grant the target permission.
                If None, checks that NO role combination grants it.

        Returns:
            VerificationResult with status 'unsat' if safe.
        """
        perm_set: set[tuple[str, str]] = set()
        for role in roles:
            for p in role.permissions:
                perm_set.add((p.action, p.resource))
        perm_list = sorted(perm_set)
        if target_permission_index < 0 or target_permission_index >= len(perm_list):
            return VerificationResult(
                property_name="RBAC Privilege Escalation Absence",
                status="unknown",
                details={
                    "reason": "target_permission_index_out_of_range",
                    "target_index": target_permission_index,
                },
            )

        target_action, target_resource = perm_list[target_permission_index]
        try:
            solver, ctx = encode_rbac_reachability(
                self._permissions_by_assignable_role(roles),
                target_action,
                target_resource,
                timeout_ms=self._timeout_ms,
            )
        except UnsupportedEncodingError as error:
            return VerificationResult(
                property_name="RBAC Privilege Escalation Absence",
                status="unknown",
                details={
                    "reason": str(error),
                    "target_index": target_permission_index,
                },
            )

        z3 = ctx["z3"]
        role_assigned = ctx["role_assigned"]

        # Constraint: forbidden roles are not assigned
        if forbidden_roles:
            for rname in forbidden_roles:
                if rname in role_assigned:
                    solver.add(z3.Not(role_assigned[rname]))

        result = solver.check()

        if result == z3.sat:
            model = solver.model()
            assigned = [
                name
                for name, var in role_assigned.items()
                if z3.is_true(model.evaluate(var, model_completion=True))
            ]
            action = self._model_string(model, ctx["action"], z3)
            resource = self._model_string(model, ctx["resource"], z3)
            return VerificationResult(
                property_name="RBAC Privilege Escalation Absence",
                status="sat",
                counterexample=(
                    f"Roles {assigned} can authorize action={action!r}, resource={resource!r} "
                    f"within permission index {target_permission_index}"
                ),
                details={
                    "assigned_roles": assigned,
                    "target_index": target_permission_index,
                    "target_action_pattern": target_action,
                    "target_resource_pattern": target_resource,
                    "action": action,
                    "resource": resource,
                },
            )
        if result == z3.unsat:
            return VerificationResult(
                property_name="RBAC Privilege Escalation Absence",
                status="unsat",
                details={
                    "target_index": target_permission_index,
                    "target_action_pattern": target_action,
                    "target_resource_pattern": target_resource,
                },
            )
        reason = solver.reason_unknown()
        return VerificationResult(
            property_name="RBAC Privilege Escalation Absence",
            status="timeout" if reason == "timeout" else "unknown",
            details={"reason": reason},
        )

    def verify_policy_consistency(
        self,
        rules: list[dict[str, Any]],
    ) -> VerificationResult:
        """Verify that a policy set has no contradictory rules.

        Two rules contradict if they can match the same (action, resource)
        but have opposite effects (allow vs deny).

        Args:
            rules: List of rule dicts with 'id', 'action_keyword',
                'resource_keyword', 'effect'.

        Returns:
            VerificationResult with contradictions found (if any).
        """
        try:
            solver, contradictions, z3 = encode_policy_consistency(
                rules, timeout_ms=self._timeout_ms
            )
        except UnsupportedEncodingError as error:
            return VerificationResult(
                property_name="Policy Set Consistency",
                status="unknown",
                details={"reason": str(error), "rules_checked": len(rules)},
            )

        found_contradictions = []
        unknown_reason = ""
        for c in contradictions:
            solver.push()
            solver.add(c["formula"])
            result = solver.check()
            if result == z3.sat:
                found_contradictions.append(
                    {
                        "rule1": c["rule1"],
                        "rule2": c["rule2"],
                    }
                )
            elif result == z3.unknown:
                unknown_reason = solver.reason_unknown()
            solver.pop()

        if found_contradictions:
            return VerificationResult(
                property_name="Policy Set Consistency",
                status="sat",
                counterexample=f"Found {len(found_contradictions)} contradicting rule pair(s)",
                details={"contradictions": found_contradictions},
            )

        if unknown_reason:
            return VerificationResult(
                property_name="Policy Set Consistency",
                status="timeout" if unknown_reason == "timeout" else "unknown",
                details={"reason": unknown_reason, "rules_checked": len(rules)},
            )

        return VerificationResult(
            property_name="Policy Set Consistency",
            status="unsat",
            details={"rules_checked": len(rules)},
        )

    def verify_workflow_safety(
        self,
        nodes: list[str],
        edges: list[tuple[str, str]],
        hitl_nodes: set[str],
        source: str,
        target: str,
    ) -> VerificationResult:
        """Verify that a target node is not reachable without passing through HITL.

        Removes HITL nodes from the graph and checks if target is still
        reachable from source via BFS on the remaining edges. If reachable,
        the safety property is violated (sat). If not reachable, the
        property holds (unsat).

        This property is deliberately checked with a bounded Python BFS;
        workflow safety is graph reachability, not an SMT encoding.

        Args:
            nodes: All nodes in the workflow graph.
            edges: Directed edges (source, target).
            hitl_nodes: Nodes that are HITL checkpoints.
            source: Start node.
            target: Node that should only be reachable via HITL.

        Returns:
            VerificationResult with status 'unsat' if safe.
        """
        non_hitl_edges = tuple(
            (src, dst) for src, dst in edges if src not in hitl_nodes and dst not in hitl_nodes
        )
        node_ids = set(nodes)
        if source not in node_ids or target not in node_ids:
            return VerificationResult(
                property_name="Workflow Safety",
                status="unknown",
                details={"note": "Source or target not in node list"},
            )

        # Simple graph reachability via BFS on non-HITL edges
        adjacency: dict[str, list[str]] = {n: [] for n in nodes if n not in hitl_nodes}
        for src, tgt in non_hitl_edges:
            if src in adjacency:
                adjacency[src].append(tgt)

        # BFS from source
        visited: set[str] = set()
        queue = [source] if source not in hitl_nodes else []
        while queue:
            current = queue.pop(0)
            if current == target:
                # Target reachable without HITL — property violated
                return VerificationResult(
                    property_name="Workflow Safety",
                    status="sat",
                    counterexample=(
                        f"Node '{target}' is reachable from '{source}' "
                        f"without passing through HITL nodes {hitl_nodes}"
                    ),
                    details={
                        "source": source,
                        "target": target,
                        "hitl_nodes": list(hitl_nodes),
                    },
                )
            if current in visited:
                continue
            visited.add(current)
            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append(neighbor)

        # Target not reachable without HITL — property holds
        return VerificationResult(
            property_name="Workflow Safety",
            status="unsat",
            details={
                "source": source,
                "target": target,
                "hitl_nodes": list(hitl_nodes),
            },
        )
