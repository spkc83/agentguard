"""Role-based access control with deny-override semantics.

Resolution order:
1. Collect all permissions from all of the agent's roles (including inherited).
2. Find permissions whose action and resource patterns match the request.
3. If ANY matching permission has effect="deny" → DENIED.
4. If at least one matching permission has effect="allow" → ALLOWED.
5. If no matching permissions at all → DENIED (deny by default).
"""

from __future__ import annotations

import fnmatch
from typing import Literal

import structlog
from pydantic import BaseModel, ConfigDict

from agentguard.models import AgentIdentity, PermissionContext

logger = structlog.get_logger()


class Permission(BaseModel):
    """A single permission rule.

    Args:
        action: Action pattern — supports fnmatch wildcards (e.g. "tool:*").
        resource: Resource pattern — supports fnmatch wildcards (e.g. "bureau/*").
        effect: "allow" or "deny".
    """

    model_config = ConfigDict(frozen=True)

    action: str
    resource: str
    effect: Literal["allow", "deny"]

    def matches(self, action: str, resource: str) -> bool:
        """Check if this permission matches the given action and resource."""
        return fnmatch.fnmatch(action, self.action) and fnmatch.fnmatch(resource, self.resource)


class Role(BaseModel):
    """A named role with permissions and optional inheritance.

    Args:
        name: Unique role name (e.g. "credit-analyst").
        permissions: Permission rules attached to this role.
        inherited_roles: Names of roles whose permissions this role inherits.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    permissions: list[Permission] = []
    inherited_roles: list[str] = []


class RBACEngine:
    """Deny-override RBAC permission checker.

    Args:
        roles: List of Role definitions.
    """

    def __init__(self, roles: list[Role]) -> None:
        self._roles: dict[str, Role] = {r.name: r for r in roles}

    def _collect_permissions(
        self, role_name: str, visited: set[str] | None = None
    ) -> list[Permission]:
        """Recursively collect permissions from a role and its ancestors."""
        if visited is None:
            visited = set()
        if role_name in visited:
            return []
        visited.add(role_name)

        role = self._roles.get(role_name)
        if role is None:
            return []

        perms = list(role.permissions)
        for parent_name in role.inherited_roles:
            perms.extend(self._collect_permissions(parent_name, visited))
        return perms

    async def check_permission(
        self,
        identity: AgentIdentity,
        action: str,
        resource: str,
    ) -> PermissionContext:
        """Check whether an agent has permission for the given action.

        Uses deny-override: any deny wins over all allows.
        """
        all_permissions: list[Permission] = []
        for role_name in identity.roles:
            all_permissions.extend(self._collect_permissions(role_name))

        matching = [p for p in all_permissions if p.matches(action, resource)]

        denies = [p for p in matching if p.effect == "deny"]
        if denies:
            reason = (
                f"Explicit deny from permission: "
                f"action={denies[0].action} resource={denies[0].resource}"
            )
            logger.info(
                "permission_denied",
                agent_id=identity.agent_id,
                action=action,
                resource=resource,
                reason=reason,
            )
            return PermissionContext(
                agent=identity,
                requested_action=action,
                resource=resource,
                granted=False,
                reason=reason,
            )

        allows = [p for p in matching if p.effect == "allow"]
        if allows:
            reason = (
                f"Allowed by permission: action={allows[0].action} resource={allows[0].resource}"
            )
            logger.info(
                "permission_granted",
                agent_id=identity.agent_id,
                action=action,
                resource=resource,
            )
            return PermissionContext(
                agent=identity,
                requested_action=action,
                resource=resource,
                granted=True,
                reason=reason,
            )

        reason = "No matching permissions found (deny by default)"
        logger.info(
            "permission_denied",
            agent_id=identity.agent_id,
            action=action,
            resource=resource,
            reason=reason,
        )
        return PermissionContext(
            agent=identity,
            requested_action=action,
            resource=resource,
            granted=False,
            reason=reason,
        )
