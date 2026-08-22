"""Tests for agentguard.integrations._pipeline — shared governance pipeline.

Covers the error-event logging contract that applies to all adapters.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations._pipeline import (
    UNRESOLVED_RESOURCE,
    canonicalize_resource,
    resolve_resource,
    run_governed,
)

if TYPE_CHECKING:
    from pathlib import Path


def _build_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="user",
                permissions=[
                    Permission(action="tool:*", resource="allowed/*", effect="allow"),
                    Permission(action="tool:*", resource="blocked/*", effect="deny"),
                ],
            ),
        ]
    )


@pytest.fixture
def _pipeline_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AgentRegistry, RBACEngine, AppendOnlyAuditLog, Path]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "test-key-pipeline")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    engine = _build_engine()
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    return registry, engine, audit, audit_dir


class TestPipeline:
    async def test_success_path_writes_one_allowed_event(self, _pipeline_setup: Any) -> None:
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        result = await run_governed(
            agent_id=agent.agent_id,
            action="tool:test",
            resource="allowed/x",
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            executor=executor,
        )
        assert result == "ok"
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "allowed"

    async def test_deny_path_writes_denied_event_and_raises(self, _pipeline_setup: Any) -> None:
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        with pytest.raises(PermissionDeniedError):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="blocked/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )
        executor.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"

    async def test_executor_exception_writes_error_event(self, _pipeline_setup: Any) -> None:
        """Per ADR-004: if execution fails, a follow-up error event must be written."""
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(side_effect=RuntimeError("downstream failure"))

        with pytest.raises(RuntimeError, match="downstream failure"):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="allowed/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 2
        assert events[0].result == "allowed"
        assert events[1].result == "error"
        # Error event should have non-zero duration (measured)
        assert events[1].duration_ms >= 0.0
        # Pre-event and error-event must share the same trace_id
        assert events[0].trace_id == events[1].trace_id

    async def test_tracer_invoked_when_provided(self, _pipeline_setup: Any) -> None:
        registry, engine, audit, _ = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        # Fake tracer that records span invocations
        span_calls: list[tuple[str, dict[str, Any] | None]] = []

        class _FakeTracer:
            def span(self, name: str, attributes: dict[str, Any] | None = None) -> Any:
                span_calls.append((name, attributes))
                from contextlib import nullcontext

                return nullcontext()

        await run_governed(
            agent_id=agent.agent_id,
            action="tool:test",
            resource="allowed/x",
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            executor=executor,
            tracer=_FakeTracer(),
        )
        assert len(span_calls) == 1
        assert span_calls[0][0] == "agentguard.tool_call"
        attrs = span_calls[0][1]
        assert attrs is not None
        assert attrs["action"] == "tool:test"
        assert attrs["resource"] == "allowed/x"

    async def test_audit_events_chain_on_error(self, _pipeline_setup: Any) -> None:
        """Error event must link into the HMAC chain with the preceding pre-event."""
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(side_effect=ValueError("boom"))

        with pytest.raises(ValueError, match="boom"):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="allowed/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )

        # Verify chain integrity after error event
        verification = await audit.verify_chain()
        assert verification.valid
        assert verification.event_count == 2

    async def test_error_event_write_failure_does_not_mask_original(
        self, _pipeline_setup: Any
    ) -> None:
        """If the error-event write itself fails, the original exception still propagates."""
        registry, engine, audit, _ = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])

        # Patch the audit log so the SECOND write (the error event) fails.
        # The first write (pre-event, allowed) must still succeed.
        original_write = audit.write
        call_count = {"n": 0}

        async def flaky_write(event: Any) -> Any:
            call_count["n"] += 1
            if call_count["n"] == 2:  # the error-event write
                raise RuntimeError("disk full")
            return await original_write(event)

        audit.write = flaky_write  # type: ignore[assignment]
        executor = AsyncMock(side_effect=ValueError("original"))

        # The original ValueError must surface — not the disk-full RuntimeError.
        with pytest.raises(ValueError, match="original"):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="allowed/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )
        assert call_count["n"] == 2


class TestCanonicalizeResource:
    """Table-driven tests for :func:`canonicalize_resource`.

    The resource reaching RBAC is derived from LLM/attacker-controlled tool
    arguments, so canonicalisation is a security boundary: anything that could
    make ``fnmatch`` disagree with a policy author's intent must be rejected.
    """

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            # --- accepted, normalised ---
            ("bureau/experian", "bureau/experian"),
            ("  bureau/experian  ", "bureau/experian"),
            ("Admin/Users", "admin/users"),
            ("ADMIN/KEYS", "admin/keys"),
            ("bureau//experian", "bureau/experian"),
            ("bureau/./experian", "bureau/experian"),
            ("bureau/experian/", "bureau/experian"),
            ("a/b/c", "a/b/c"),
            ("model/pd_v1", "model/pd_v1"),
            ("customers/A-001", "customers/a-001"),
            # --- rejected: empty / whitespace ---
            ("", None),
            ("   ", None),
            ("\t\n", None),
            # --- rejected: fnmatch metacharacters (self-granting wildcards) ---
            ("*", None),
            ("admin/*", None),
            ("?", None),
            ("bureau/experia?", None),
            ("[abc]", None),
            ("bureau/[a-z]", None),
            ("a]b", None),
            # --- rejected: absolute paths ---
            ("/admin/x", None),
            ("//admin/x", None),
            ("/", None),
            # --- rejected: traversal ---
            ("../admin/x", None),
            ("bureau/../../admin", None),
            ("..", None),
            ("a/..", None),
            (".", None),
            ("./", None),
            # --- rejected: reserved sentinel characters ---
            ("<unresolved>", None),
            ("a<b", None),
            ("a>b", None),
            # --- rejected: control characters ---
            ("bureau/exp\nerian", None),
            ("bureau/exp\x00erian", None),
        ],
    )
    def test_canonicalize_table(self, raw: str, expected: str | None) -> None:
        assert canonicalize_resource(raw) == expected

    def test_interior_traversal_collapses_to_its_true_target(self) -> None:
        """``bureau/../admin/x`` is not rejected — it *is* ``admin/x``.

        Resolving it to its true target is stricter than rejecting it: the
        resource is then judged on its merits (and audited by its real name)
        rather than recorded as an opaque ``<unresolved>``. Escaping upward out
        of the string entirely is still rejected.
        """
        assert canonicalize_resource("bureau/../admin/x") == "admin/x"
        assert canonicalize_resource("bureau/../../admin") is None

    def test_canonicalized_output_is_idempotent(self) -> None:
        once = canonicalize_resource("  Bureau/./Experian/  ")
        assert once == "bureau/experian"
        assert canonicalize_resource(once) == once

    def test_canonical_output_never_contains_wildcards(self) -> None:
        """A canonical resource can never widen a policy pattern."""
        for raw in ("bureau/experian", "Admin/Users", "a/b/c"):
            out = canonicalize_resource(raw)
            assert out is not None
            assert not any(ch in out for ch in "*?[]")


class TestResolveResource:
    async def test_none_resolver_returns_none(self) -> None:
        assert await resolve_resource(None, {"x": 1}) is None

    async def test_static_string_resolver(self) -> None:
        assert await resolve_resource("Bureau/Experian", {}) == "bureau/experian"

    async def test_static_string_resolver_is_canonicalized(self) -> None:
        assert await resolve_resource("admin/*", {}) is None

    async def test_sync_callable_resolver(self) -> None:
        assert await resolve_resource(lambda a: f"customers/{a['id']}", {"id": "A-001"}) == (
            "customers/a-001"
        )

    async def test_async_callable_resolver(self) -> None:
        async def _resolver(call_input: Any) -> str:
            return f"bureau/{call_input['bureau']}"

        assert await resolve_resource(_resolver, {"bureau": "Experian"}) == "bureau/experian"

    async def test_raising_resolver_returns_none(self) -> None:
        def _boom(_: Any) -> str:
            raise RuntimeError("resolver exploded")

        assert await resolve_resource(_boom, {}) is None

    async def test_raising_async_resolver_returns_none(self) -> None:
        async def _boom(_: Any) -> str:
            raise RuntimeError("async resolver exploded")

        assert await resolve_resource(_boom, {}) is None

    async def test_key_error_resolver_returns_none(self) -> None:
        """A resolver reading a missing argument must deny, not crash the pipeline."""
        assert await resolve_resource(lambda a: f"customers/{a['id']}", {}) is None

    @pytest.mark.parametrize("bad_result", [42, None, ["a"], {"resource": "x"}, b"bytes"])
    async def test_non_str_resolver_result_returns_none(self, bad_result: Any) -> None:
        resolver: Any = lambda _: bad_result  # noqa: E731
        assert await resolve_resource(resolver, {}) is None

    async def test_resolver_returning_wildcard_returns_none(self) -> None:
        assert await resolve_resource(lambda _: "*", {}) is None


class TestRunGovernedResourceDerivation:
    async def test_unresolved_resource_denies_and_audits(self, _pipeline_setup: Any) -> None:
        """resource=None must fail closed with an audited ``<unresolved>`` denial."""
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        with pytest.raises(PermissionDeniedError) as excinfo:
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource=None,
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )
        assert excinfo.value.resource == UNRESOLVED_RESOURCE
        assert "resource_unresolvable" in excinfo.value.reason
        executor.assert_not_called()

        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].result == "denied"
        assert events[0].resource == UNRESOLVED_RESOURCE
        assert events[0].permission_context.granted is False
        assert "resource_unresolvable" in events[0].permission_context.reason

    async def test_uncanonicalizable_resource_is_treated_as_unresolved(
        self, _pipeline_setup: Any
    ) -> None:
        """A wildcard resource string must not reach RBAC as a self-granted wildcard."""
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        with pytest.raises(PermissionDeniedError) as excinfo:
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="allowed/*",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )
        assert excinfo.value.resource == UNRESOLVED_RESOURCE
        executor.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].resource == UNRESOLVED_RESOURCE

    async def test_traversal_resource_is_treated_as_unresolved(self, _pipeline_setup: Any) -> None:
        registry, engine, audit, _ = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        with pytest.raises(PermissionDeniedError):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="allowed/../blocked/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )
        executor.assert_not_called()

    async def test_resource_is_canonicalized_in_audit_event(self, _pipeline_setup: Any) -> None:
        """``Allowed/X`` must be recorded (and matched) as ``allowed/x``."""
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        result = await run_governed(
            agent_id=agent.agent_id,
            action="tool:test",
            resource="Allowed/X",
            registry=registry,
            rbac_engine=engine,
            audit_log=audit,
            executor=executor,
        )
        assert result == "ok"
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert len(events) == 1
        assert events[0].resource == "allowed/x"
        assert events[0].permission_context.resource == "allowed/x"

    async def test_case_variant_cannot_evade_deny_rule(self, _pipeline_setup: Any) -> None:
        """``Blocked/X`` must still hit ``deny tool:* on blocked/*``."""
        registry, engine, audit, audit_dir = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")

        with pytest.raises(PermissionDeniedError):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource="BLOCKED/x",
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
            )
        executor.assert_not_called()
        events = await FileAuditBackend(directory=audit_dir).read_all()
        assert events[0].result == "denied"
        assert events[0].resource == "blocked/x"

    async def test_tracer_span_records_unresolved_sentinel(self, _pipeline_setup: Any) -> None:
        registry, engine, audit, _ = _pipeline_setup
        agent = await registry.register(name="Bot", roles=["user"])
        executor = AsyncMock(return_value="ok")
        span_calls: list[tuple[str, dict[str, Any] | None]] = []

        class _FakeTracer:
            def span(self, name: str, attributes: dict[str, Any] | None = None) -> Any:
                span_calls.append((name, attributes))
                from contextlib import nullcontext

                return nullcontext()

        with pytest.raises(PermissionDeniedError):
            await run_governed(
                agent_id=agent.agent_id,
                action="tool:test",
                resource=None,
                registry=registry,
                rbac_engine=engine,
                audit_log=audit,
                executor=executor,
                tracer=_FakeTracer(),
            )
        attrs = span_calls[0][1]
        assert attrs is not None
        assert attrs["resource"] == UNRESOLVED_RESOURCE
