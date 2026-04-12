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
