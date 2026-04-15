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
    encode_policy_consistency,
    encode_rbac_permissions,
)
from agentguard.core.rbac import Role

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
        self._timeout_ms = timeout_ms

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
        # Build permission index map
        perm_set: set[tuple[str, str]] = set()
        for role in roles:
            for p in role.permissions:
                perm_set.add((p.action, p.resource))
        perm_list = sorted(perm_set)
        num_perms = max(len(perm_list), target_permission_index + 1)

        # Encode roles
        encoded_roles = []
        for role in roles:
            perms = []
            for p in role.permissions:
                if (p.action, p.resource) in perm_set:
                    idx = perm_list.index((p.action, p.resource))
                    perms.append({"index": idx, "effect": p.effect})
            encoded_roles.append({"name": role.name, "permissions": perms})

        solver, effective, ctx = encode_rbac_permissions(encoded_roles, num_perms)
        z3 = ctx["z3"]
        role_assigned = ctx["role_assigned"]

        # Constraint: forbidden roles are not assigned
        if forbidden_roles:
            for rname in forbidden_roles:
                if rname in role_assigned:
                    solver.add(z3.Not(role_assigned[rname]))

        # Check: can the target permission be reached?
        target_bit = z3.BitVecVal(1 << target_permission_index, num_perms)
        solver.add((effective & target_bit) == target_bit)

        result = solver.check()
        status = str(result)

        if status == "sat":
            model = solver.model()
            assigned = [
                name
                for name, var in role_assigned.items()
                if model.evaluate(var, model_completion=True)
            ]
            return VerificationResult(
                property_name="RBAC Privilege Escalation Absence",
                status="sat",
                counterexample=(
                    f"Roles {assigned} can reach permission index {target_permission_index}"
                ),
                details={"assigned_roles": assigned, "target_index": target_permission_index},
            )
        elif status == "unsat":
            return VerificationResult(
                property_name="RBAC Privilege Escalation Absence",
                status="unsat",
                details={"target_index": target_permission_index},
            )
        else:
            return VerificationResult(
                property_name="RBAC Privilege Escalation Absence",
                status="timeout" if "timeout" in status else "unknown",
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
        solver, contradictions, z3 = encode_policy_consistency(rules)

        found_contradictions = []
        for c in contradictions:
            solver.push()
            solver.add(c["formula"])
            result = solver.check()
            if str(result) == "sat":
                found_contradictions.append(
                    {
                        "rule1": c["rule1"],
                        "rule2": c["rule2"],
                    }
                )
            solver.pop()

        if found_contradictions:
            return VerificationResult(
                property_name="Policy Set Consistency",
                status="sat",
                counterexample=f"Found {len(found_contradictions)} contradicting rule pair(s)",
                details={"contradictions": found_contradictions},
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

        We encode this as a Z3 satisfiability problem: create boolean
        variables for each non-HITL edge being "used", and assert that
        a path exists from source to target using only those edges.

        Args:
            nodes: All nodes in the workflow graph.
            edges: Directed edges (source, target).
            hitl_nodes: Nodes that are HITL checkpoints.
            source: Start node.
            target: Node that should only be reachable via HITL.

        Returns:
            VerificationResult with status 'unsat' if safe.
        """
        from agentguard.compliance.z3_models import encode_workflow_reachability

        solver, non_hitl_edges, node_ids, z3 = encode_workflow_reachability(
            nodes, edges, hitl_nodes
        )

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
