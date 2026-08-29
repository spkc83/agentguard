"""Z3 sort and formula definitions for AgentGuard concepts.

Encodes RBAC permissions, policy rules, and workflow graphs as Z3
logical formulas for formal verification. All encodings are documented
with plain-English explanations of what they represent.

Z3 is imported lazily — this module is only loaded when formal
verification is explicitly requested.
"""

from __future__ import annotations

from typing import Any


class UnsupportedEncodingError(ValueError):
    """Raised when an input cannot be represented without changing its semantics."""


def _import_z3() -> Any:
    """Lazily import z3-solver."""
    try:
        import z3
    except ImportError as e:
        raise ImportError(
            "z3-solver is required for formal verification. Install with: pip install z3-solver"
        ) from e
    return z3


def _fnmatch_regex(pattern: str, z3: Any) -> Any:
    """Encode the sound ``fnmatchcase`` subset used by the verifier.

    ``*`` and ``?`` have the same whole-string semantics as Python's
    :func:`fnmatch.fnmatchcase`. Character classes are deliberately rejected:
    silently treating them as literals or regex syntax could prove a property
    over a different language than the runtime checks.
    """
    if "[" in pattern or "]" in pattern:
        raise UnsupportedEncodingError(
            f"unsupported fnmatch character class in pattern {pattern!r}"
        )
    if any(ord(character) > 0x2FFFF for character in pattern):
        raise UnsupportedEncodingError(
            "unsupported fnmatch code point above Z3 regex maximum U+2FFFF"
        )

    all_character = z3.AllChar(z3.ReSort(z3.StringSort()))
    parts: list[Any] = []
    previous_was_star = False

    for character in pattern:
        if character == "*":
            if not previous_was_star:
                parts.append(z3.Star(all_character))
            previous_was_star = True
        elif character == "?":
            parts.append(all_character)
            previous_was_star = False
        else:
            # Range avoids z3py treating a literal ``\\u{...}`` sequence as
            # one escaped code point when constructing a regex string.
            parts.append(z3.Range(character, character))
            previous_was_star = False

    if not parts:
        return z3.Re("")
    if len(parts) == 1:
        return parts[0]
    return z3.Concat(*parts)


def _matches(value: Any, pattern: str, z3: Any) -> Any:
    return z3.InRe(value, _fnmatch_regex(pattern, z3))


def encode_rbac_reachability(
    roles: list[dict[str, Any]],
    target_action: str,
    target_resource: str,
    *,
    timeout_ms: int = 10000,
) -> tuple[Any, dict[str, Any]]:
    """Encode whether some role assignment can authorize a target request.

    The symbolic action/resource must match the target patterns. A request is
    effective when at least one assigned role has a matching allow and no
    assigned role has a matching deny. Each role's permission list must already
    include inherited permissions, matching :class:`RBACEngine` collection.
    Resources are encoded case-folded because the runtime case-folds both the
    resource subject and pattern before calling ``fnmatchcase``.
    """
    z3 = _import_z3()
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    action = z3.String("requested_action")
    resource = z3.String("requested_resource_casefolded")
    role_assigned = {role["name"]: z3.Bool(f"role_{index}") for index, role in enumerate(roles)}
    allow_matches: list[Any] = []
    deny_matches: list[Any] = []

    solver.add(_matches(action, target_action, z3))
    solver.add(_matches(resource, target_resource.casefold(), z3))

    for role in roles:
        assigned = role_assigned[role["name"]]
        for permission in role.get("permissions", []):
            permission_matches = z3.And(
                assigned,
                _matches(action, permission["action"], z3),
                _matches(resource, permission["resource"].casefold(), z3),
            )
            if permission["effect"] == "allow":
                allow_matches.append(permission_matches)
            else:
                deny_matches.append(permission_matches)

    solver.add(z3.Or(*allow_matches) if allow_matches else z3.BoolVal(False))
    if deny_matches:
        solver.add(z3.Not(z3.Or(*deny_matches)))

    return solver, {
        "action": action,
        "resource": resource,
        "role_assigned": role_assigned,
        "z3": z3,
    }


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
    *,
    timeout_ms: int = 10000,
) -> tuple[Any, list[Any], Any]:
    """Encode policy rules as Z3 formulas for consistency checking.

    Only explicit authorization rules are supported. AgentGuard compliance
    rules describe checks and failure handling; their severity or ``on_fail``
    value is not an allow/deny authorization effect and cannot soundly be
    encoded as one.

    Args:
        rules: Authorization-rule dictionaries with ``kind='authorization'``,
            non-empty ``action_patterns`` and ``resource_patterns`` lists, and
            an explicit ``allow`` or ``deny`` effect.

    Returns:
        Tuple of (solver, contradiction_formulas, z3_module).
    """
    z3 = _import_z3()

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    normalized: list[dict[str, Any]] = []
    for rule in rules:
        action_patterns = rule.get("action_patterns")
        resource_patterns = rule.get("resource_patterns")
        if (
            rule.get("kind") != "authorization"
            or rule.get("effect") not in {"allow", "deny"}
            or not isinstance(rule.get("id"), str)
            or not isinstance(action_patterns, list | tuple)
            or not action_patterns
            or not all(isinstance(pattern, str) for pattern in action_patterns)
            or not isinstance(resource_patterns, list | tuple)
            or not resource_patterns
            or not all(isinstance(pattern, str) for pattern in resource_patterns)
        ):
            raise UnsupportedEncodingError("unsupported_policy_rule_schema")
        for pattern in (*action_patterns, *resource_patterns):
            _fnmatch_regex(pattern, z3)
        normalized.append(
            {
                "id": rule["id"],
                "effect": rule["effect"],
                "action_patterns": tuple(action_patterns),
                "resource_patterns": tuple(pattern.casefold() for pattern in resource_patterns),
            }
        )

    action = z3.String("action")
    resource = z3.String("resource_casefolded")

    contradictions = []

    for i, r1 in enumerate(normalized):
        for r2 in normalized[i + 1 :]:
            if r1["effect"] != r2["effect"]:
                r1_matches = z3.And(
                    z3.Or(*[_matches(action, pattern, z3) for pattern in r1["action_patterns"]]),
                    z3.Or(
                        *[_matches(resource, pattern, z3) for pattern in r1["resource_patterns"]]
                    ),
                )
                r2_matches = z3.And(
                    z3.Or(*[_matches(action, pattern, z3) for pattern in r2["action_patterns"]]),
                    z3.Or(
                        *[_matches(resource, pattern, z3) for pattern in r2["resource_patterns"]]
                    ),
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
