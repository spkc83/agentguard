"""Differential checks between the formal RBAC model and the runtime engine."""

from __future__ import annotations

import asyncio
import itertools
import random

import pytest

from agentguard.compliance.formal_verifier import FormalVerifier
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.models import AgentIdentity

pytest.importorskip("z3")

_ACTIONS = ("tool:read", "tool:write", "tool:credit_check")
_RESOURCES = ("data/public", "data/private", "bureau/experian")
_ACTION_PATTERNS = ("tool:*", "tool:r?ad", "tool:write", "tool:credit_*")
_RESOURCE_PATTERNS = ("*", "data/*", "data/p?ivate", "bureau/*")


def _target_index(roles: list[Role], action: str, resource: str) -> int:
    permissions = sorted(
        {
            (permission.action, permission.resource)
            for role in roles
            for permission in role.permissions
        }
    )
    return permissions.index((action, resource))


async def _runtime_can_reach(
    roles: list[Role],
    candidate_roles: list[str],
    action: str,
    resource: str,
) -> bool:
    engine = RBACEngine(roles)
    for size in range(len(candidate_roles) + 1):
        for assigned in itertools.combinations(candidate_roles, size):
            result = await engine.check_permission(
                AgentIdentity(agent_id="differential", name="Differential", roles=list(assigned)),
                action,
                resource,
            )
            if result.granted:
                return True
    return False


def test_randomized_rbac_model_matches_runtime_engine() -> None:
    """The SMT model and runtime agree over wildcard, deny, and inheritance cases."""
    rng = random.Random(0xA6E17)  # noqa: S311 - deterministic test generation

    for case in range(80):
        target_action = rng.choice(_ACTIONS)
        target_resource = rng.choice(_RESOURCES)
        roles = [
            Role(
                name="target-catalog",
                permissions=[
                    Permission(
                        action=target_action,
                        resource=target_resource,
                        effect="deny",
                    )
                ],
            )
        ]
        candidate_names: list[str] = []
        for index in range(4):
            name = f"role-{index}"
            candidate_names.append(name)
            inherited = [f"role-{index - 1}"] if index and rng.random() < 0.45 else []
            permissions = [
                Permission(
                    action=rng.choice(_ACTION_PATTERNS),
                    resource=rng.choice(_RESOURCE_PATTERNS),
                    effect=rng.choice(("allow", "deny")),
                )
                for _ in range(rng.randint(0, 3))
            ]
            roles.append(Role(name=name, permissions=permissions, inherited_roles=inherited))

        expected = asyncio.run(
            _runtime_can_reach(
                roles,
                candidate_names,
                target_action,
                target_resource,
            )
        )
        result = FormalVerifier().verify_rbac_escalation(
            roles=roles,
            target_permission_index=_target_index(roles, target_action, target_resource),
            forbidden_roles=["target-catalog"],
        )

        assert result.status == ("sat" if expected else "unsat"), (
            f"case={case} action={target_action!r} resource={target_resource!r} "
            f"roles={roles!r} result={result.model_dump()!r}"
        )
        if result.status == "sat":
            assert Permission(
                action=target_action,
                resource=target_resource,
                effect="allow",
            ).matches(result.details["action"], result.details["resource"])
            replay = asyncio.run(
                RBACEngine(roles).check_permission(
                    AgentIdentity(
                        agent_id="replay",
                        name="Replay",
                        roles=result.details["assigned_roles"],
                    ),
                    result.details["action"],
                    result.details["resource"],
                )
            )
            assert replay.granted is True
