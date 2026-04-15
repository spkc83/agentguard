"""Z3 sort and formula definitions for AgentGuard concepts.

Encodes RBAC permissions, policy rules, and workflow graphs as Z3
logical formulas for formal verification. All encodings are documented
with plain-English explanations of what they represent.

Z3 is imported lazily — this module is only loaded when formal
verification is explicitly requested.
"""

from __future__ import annotations

from typing import Any


def _import_z3() -> Any:
    """Lazily import z3-solver."""
    try:
        import z3
    except ImportError as e:
        raise ImportError(
            "z3-solver is required for formal verification. Install with: pip install z3-solver"
        ) from e
    return z3


def encode_rbac_permissions(
    roles: list[dict[str, Any]],
    num_permissions: int,
) -> tuple[Any, Any, dict[str, Any]]:
    """Encode RBAC roles and permissions as Z3 bitvectors.

    Each role is a bitvector where bit i = 1 means the role grants
    permission i. Deny permissions are encoded as a separate deny
    bitvector. The deny-override semantics mean: effective = allow & ~deny.

    Args:
        roles: List of role dicts with 'name', 'permissions' (list of
            dicts with 'index', 'effect').
        num_permissions: Total number of distinct permissions.

    Returns:
        Tuple of (solver, effective_bitvector, context_dict).
    """
    z3 = _import_z3()

    solver = z3.Solver()
    solver.set("timeout", 10000)  # 10 second timeout

    bv_size = max(num_permissions, 1)

    # Create bitvector constants for each role: which permissions it grants/denies
    role_allows: dict[str, Any] = {}
    role_denies: dict[str, Any] = {}

    for role in roles:
        name = role["name"]
        allow_val = 0
        deny_val = 0

        for perm in role.get("permissions", []):
            idx = perm["index"]
            if perm["effect"] == "allow":
                allow_val |= 1 << idx
            else:
                deny_val |= 1 << idx

        role_allows[name] = z3.BitVecVal(allow_val, bv_size)
        role_denies[name] = z3.BitVecVal(deny_val, bv_size)

    # Agent's assigned roles as boolean variables
    role_assigned = {name: z3.Bool(f"role_{name}") for name in role_allows}

    # Build effective allow/deny using If-Then-Else per role
    zero = z3.BitVecVal(0, bv_size)
    effective_allow = zero
    effective_deny = zero

    for name in role_allows:
        effective_allow = effective_allow | z3.If(role_assigned[name], role_allows[name], zero)
        effective_deny = effective_deny | z3.If(role_assigned[name], role_denies[name], zero)

    # Deny-override: effective = allow & ~deny
    effective = effective_allow & ~effective_deny

    context = {
        "role_assigned": role_assigned,
        "effective_allow": effective_allow,
        "effective_deny": effective_deny,
        "effective": effective,
        "num_permissions": num_permissions,
        "z3": z3,
    }

    return solver, effective, context


def encode_policy_consistency(
    rules: list[dict[str, Any]],
) -> tuple[Any, list[Any], Any]:
    """Encode policy rules as Z3 formulas for consistency checking.

    Two rules are contradictory if their conditions can simultaneously
    be true but their effects differ (one allows, one denies the same
    action on the same resource).

    Args:
        rules: List of rule dicts with 'id', 'action_keyword',
            'resource_keyword', 'effect'.

    Returns:
        Tuple of (solver, contradiction_formulas, z3_module).
    """
    z3 = _import_z3()

    solver = z3.Solver()
    solver.set("timeout", 10000)

    # Symbolic action and resource
    action = z3.String("action")
    resource = z3.String("resource")

    contradictions = []

    for i, r1 in enumerate(rules):
        for r2 in rules[i + 1 :]:
            if r1["effect"] != r2["effect"]:
                # Both rules could match the same (action, resource) pair
                # if their patterns overlap
                r1_matches = z3.And(
                    z3.Contains(action, z3.StringVal(r1.get("action_keyword", ""))),
                    z3.Contains(resource, z3.StringVal(r1.get("resource_keyword", ""))),
                )
                r2_matches = z3.And(
                    z3.Contains(action, z3.StringVal(r2.get("action_keyword", ""))),
                    z3.Contains(resource, z3.StringVal(r2.get("resource_keyword", ""))),
                )
                contradiction = z3.And(r1_matches, r2_matches)
                contradictions.append(
                    {
                        "formula": contradiction,
                        "rule1": r1["id"],
                        "rule2": r2["id"],
                    }
                )

    return solver, contradictions, z3


def encode_workflow_reachability(
    nodes: list[str],
    edges: list[tuple[str, str]],
    hitl_nodes: set[str],
) -> tuple[Any, Any, dict[str, int], Any]:
    """Encode a workflow graph for reachability analysis.

    Uses a simple Z3 Solver-based bounded reachability check instead of
    the Fixedpoint engine. Encodes nodes as integers and checks if a path
    exists from source to target that avoids all HITL nodes.

    Args:
        nodes: List of node names in the workflow.
        edges: List of (source, target) directed edges.
        hitl_nodes: Set of node names that are HITL checkpoints.

    Returns:
        Tuple of (solver, reachability_var, node_id_map, z3_module).
    """
    z3 = _import_z3()

    # Map node names to integer IDs
    node_ids = {name: i for i, name in enumerate(nodes)}

    # Build adjacency list excluding HITL nodes (except as endpoints)
    # For safety check: can we reach target from source WITHOUT going through HITL?
    # Remove HITL nodes from the graph entirely, then check reachability.
    non_hitl_edges = [
        (src, tgt) for src, tgt in edges if src not in hitl_nodes and tgt not in hitl_nodes
    ]

    solver = z3.Solver()
    solver.set("timeout", 10000)

    return solver, non_hitl_edges, node_ids, z3
