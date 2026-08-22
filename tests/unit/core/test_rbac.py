"""Tests for agentguard.core.rbac — deny-override RBAC engine."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.models import AgentIdentity

if TYPE_CHECKING:
    import pytest


def _identity(roles: list[str]) -> AgentIdentity:
    return AgentIdentity(agent_id="test", name="Test", roles=roles)


class TestPermission:
    def test_exact_match(self) -> None:
        perm = Permission(action="tool:credit_check", resource="bureau/experian", effect="allow")
        assert perm.matches("tool:credit_check", "bureau/experian") is True

    def test_no_match_action(self) -> None:
        perm = Permission(action="tool:credit_check", resource="*", effect="allow")
        assert perm.matches("tool:web_search", "anything") is False

    def test_wildcard_action(self) -> None:
        perm = Permission(action="tool:*", resource="*", effect="allow")
        assert perm.matches("tool:credit_check", "bureau/experian") is True
        assert perm.matches("tool:web_search", "google.com") is True

    def test_wildcard_resource(self) -> None:
        perm = Permission(action="tool:credit_check", resource="*", effect="allow")
        assert perm.matches("tool:credit_check", "bureau/experian") is True
        assert perm.matches("tool:credit_check", "bureau/equifax") is True

    def test_prefix_wildcard(self) -> None:
        perm = Permission(action="tool:credit_*", resource="bureau/*", effect="allow")
        assert perm.matches("tool:credit_check", "bureau/experian") is True
        assert perm.matches("tool:credit_score", "bureau/equifax") is True
        assert perm.matches("tool:web_search", "bureau/experian") is False

    def test_data_action(self) -> None:
        perm = Permission(action="data:read:pii", resource="*", effect="deny")
        assert perm.matches("data:read:pii", "customer_records") is True


class TestRole:
    def test_role_with_permissions(self) -> None:
        role = Role(
            name="credit-analyst",
            permissions=[
                Permission(action="tool:credit_check", resource="*", effect="allow"),
                Permission(action="data:read:pii", resource="*", effect="deny"),
            ],
        )
        assert role.name == "credit-analyst"
        assert len(role.permissions) == 2

    def test_role_with_inheritance(self) -> None:
        Role(
            name="readonly",
            permissions=[Permission(action="data:read:*", resource="*", effect="allow")],
        )
        analyst = Role(
            name="credit-analyst",
            permissions=[Permission(action="tool:credit_check", resource="*", effect="allow")],
            inherited_roles=["readonly"],
        )
        assert analyst.inherited_roles == ["readonly"]


class TestRBACEngine:
    def _build_engine(self) -> RBACEngine:
        readonly = Role(
            name="readonly",
            permissions=[
                Permission(action="data:read:*", resource="*", effect="allow"),
            ],
        )
        analyst = Role(
            name="credit-analyst",
            permissions=[
                Permission(action="tool:credit_check", resource="bureau/*", effect="allow"),
                Permission(action="tool:income_verify", resource="*", effect="allow"),
                Permission(action="data:read:pii", resource="*", effect="deny"),
            ],
            inherited_roles=["readonly"],
        )
        reviewer = Role(
            name="credit-reviewer",
            permissions=[
                Permission(action="tool:*", resource="*", effect="allow"),
                Permission(action="data:write:*", resource="*", effect="allow"),
            ],
            inherited_roles=["credit-analyst"],
        )
        system = Role(
            name="system-agent",
            permissions=[
                Permission(action="*", resource="*", effect="allow"),
            ],
        )
        return RBACEngine(roles=[readonly, analyst, reviewer, system])

    async def test_allow_simple(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.granted is True

    async def test_deny_no_matching_role(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["readonly"]),
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.granted is False

    async def test_deny_override(self) -> None:
        """Explicit deny beats allow — credit-analyst cannot read PII."""
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="data:read:pii",
            resource="customer_records",
        )
        assert ctx.granted is False
        assert "deny" in ctx.reason.lower()

    async def test_deny_override_even_with_inherited_allow(self) -> None:
        engine = self._build_engine()
        ctx_reports = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="data:read:reports",
            resource="monthly",
        )
        assert ctx_reports.granted is True

        ctx_pii = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="data:read:pii",
            resource="customer_records",
        )
        assert ctx_pii.granted is False

    async def test_role_inheritance(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="data:read:reports",
            resource="monthly",
        )
        assert ctx.granted is True

    async def test_multi_level_inheritance(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["credit-reviewer"]),
            action="data:read:reports",
            resource="monthly",
        )
        assert ctx.granted is True

    async def test_system_agent_wildcard(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["system-agent"]),
            action="anything:at_all",
            resource="any/resource",
        )
        assert ctx.granted is True

    async def test_no_roles_denies(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity([]),
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.granted is False

    async def test_unknown_role_ignored(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["nonexistent-role"]),
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.granted is False

    async def test_permission_context_fields(self) -> None:
        engine = self._build_engine()
        identity = _identity(["credit-analyst"])
        ctx = await engine.check_permission(
            identity,
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.agent == identity
        assert ctx.requested_action == "tool:credit_check"
        assert ctx.resource == "bureau/experian"

    def test_circular_inheritance_warns(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Circular role inheritance should log a warning, not crash."""
        structlog.configure(
            processors=[
                structlog.processors.add_log_level,
                structlog.dev.ConsoleRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(0),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=False,
        )
        role_a = Role(
            name="role-a",
            permissions=[Permission(action="tool:a", resource="*", effect="allow")],
            inherited_roles=["role-b"],
        )
        role_b = Role(
            name="role-b",
            permissions=[Permission(action="tool:b", resource="*", effect="allow")],
            inherited_roles=["role-a"],
        )
        RBACEngine(roles=[role_a, role_b])
        captured = capsys.readouterr()
        assert "circular_role_inheritance" in captured.out

    async def test_check_permission_terminates_with_cycle(self) -> None:
        """check_permission on a cyclic role graph must terminate with a deterministic result."""
        role_a = Role(
            name="role-a",
            permissions=[Permission(action="tool:a", resource="*", effect="allow")],
            inherited_roles=["role-b"],
        )
        role_b = Role(
            name="role-b",
            permissions=[Permission(action="tool:b", resource="*", effect="allow")],
            inherited_roles=["role-a"],
        )
        engine = RBACEngine(roles=[role_a, role_b])
        ctx_a = await engine.check_permission(_identity(["role-a"]), "tool:a", "anywhere")
        ctx_b = await engine.check_permission(_identity(["role-a"]), "tool:b", "anywhere")
        assert ctx_a.granted is True
        assert ctx_b.granted is True


class TestPermissionMatchingCaseSemantics:
    """Resource matching is case-insensitive; action matching is exact-case.

    A resource reaching RBAC is derived from tool arguments, so an attacker who
    controls the casing must not be able to slip past a deny rule. Actions are
    chosen by the integrator, so they stay exact to avoid silently widening a
    policy.
    """

    def test_resource_case_variant_still_matches_deny_pattern(self) -> None:
        perm = Permission(action="tool:*", resource="admin/*", effect="deny")
        assert perm.matches("tool:delete", "Admin/keys") is True
        assert perm.matches("tool:delete", "ADMIN/KEYS") is True

    def test_uppercase_pattern_matches_lowercase_resource(self) -> None:
        """A policy author writing ``Admin/*`` still governs ``admin/keys``."""
        perm = Permission(action="tool:*", resource="Admin/*", effect="deny")
        assert perm.matches("tool:delete", "admin/keys") is True

    def test_action_matching_is_case_sensitive(self) -> None:
        perm = Permission(action="tool:admin_delete", resource="*", effect="allow")
        assert perm.matches("tool:admin_delete", "x") is True
        assert perm.matches("tool:Admin_Delete", "x") is False
        assert perm.matches("TOOL:ADMIN_DELETE", "x") is False

    async def test_engine_denies_case_variant_resource(self) -> None:
        engine = RBACEngine(
            roles=[
                Role(
                    name="analyst",
                    permissions=[
                        Permission(action="tool:*", resource="*", effect="allow"),
                        Permission(action="tool:*", resource="admin/*", effect="deny"),
                    ],
                )
            ]
        )
        ctx = await engine.check_permission(_identity(["analyst"]), "tool:delete", "Admin/keys")
        assert ctx.granted is False
        assert "Explicit deny" in ctx.reason

    async def test_engine_action_case_variant_does_not_match(self) -> None:
        engine = RBACEngine(
            roles=[
                Role(
                    name="analyst",
                    permissions=[
                        Permission(action="tool:admin_delete", resource="*", effect="allow"),
                    ],
                )
            ]
        )
        ctx = await engine.check_permission(_identity(["analyst"]), "tool:Admin_Delete", "anything")
        assert ctx.granted is False
