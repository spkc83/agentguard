"""Tests for the authenticated registry control plane."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from structlog.testing import capture_logs

from agentguard.core import (
    AgentRegistryControlPlane,
    AgentRegistryRecord,
    AppendOnlyAuditLog,
    ControlPlanePrincipal,
    FileAuditBackend,
    InMemoryAuthoritativeAgentRegistry,
    RegisterAgentCommand,
    RegistryError,
    RegistryFailure,
    RegistryOperationState,
    ReplaceAgentRolesCommand,
    RevokeAgentCommand,
    RoleGrantPolicy,
    RotateAgentCredentialsCommand,
)
from agentguard.core.registry_state import _bind_registry_control_plane
from agentguard.exceptions import AuthenticationError, AuthenticationFailure

if TYPE_CHECKING:
    from agentguard.models import AuditEvent

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
pytestmark = pytest.mark.usefixtures("_set_audit_key")


class Authenticator:
    def __init__(self, principal: ControlPlanePrincipal, *, fail: bool = False) -> None:
        self.principal = principal
        self.fail = fail
        self.credentials: list[object] = []

    async def authenticate(self, credential: object) -> ControlPlanePrincipal:
        self.credentials.append(credential)
        if self.fail:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        return self.principal


def _principal(*capabilities: str, principal_id: str = "admin") -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        principal_id=principal_id,
        capabilities=capabilities,
        method="test",
        authority="tests",
        credential_digest="a" * 64,
        issued_at=NOW - timedelta(minutes=1),
        not_before=NOW - timedelta(minutes=1),
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def _policy() -> RoleGrantPolicy:
    return RoleGrantPolicy(
        known_roles=frozenset({"viewer", "operator"}),
        grant_capabilities={
            "viewer": "registry:role:viewer:grant",
            "operator": "registry:role:operator:grant",
        },
        revoke_capabilities={
            "viewer": "registry:role:viewer:revoke",
            "operator": "registry:role:operator:revoke",
        },
    )


def test_role_policy_requires_distinct_per_role_capabilities() -> None:
    with pytest.raises(ValueError, match="distinct capability"):
        RoleGrantPolicy(
            known_roles=frozenset({"viewer", "operator"}),
            grant_capabilities={
                "viewer": "registry:role:grant",
                "operator": "registry:role:grant",
            },
        )
    with pytest.raises(ValueError, match="action capabilities"):
        RoleGrantPolicy(
            known_roles=frozenset({"viewer"}),
            grant_capabilities={"viewer": "registry:agent:register"},
        )


def _log(tmp_path: Path) -> AppendOnlyAuditLog:
    return AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))


def _control_plane(
    tmp_path: Path,
    principal: ControlPlanePrincipal,
    *,
    registry: InMemoryAuthoritativeAgentRegistry | None = None,
    authenticator: Authenticator | None = None,
    audit_log: object | None = None,
) -> tuple[AgentRegistryControlPlane, InMemoryAuthoritativeAgentRegistry, Authenticator]:
    log = audit_log or _log(tmp_path)
    state = registry or InMemoryAuthoritativeAgentRegistry(
        "registry-1",
        audit_log=log,  # type: ignore[arg-type]
    )
    auth = authenticator or Authenticator(principal)
    plane = AgentRegistryControlPlane(
        state,
        auth,
        log,  # type: ignore[arg-type]
        _policy(),
        clock=lambda: NOW,
    )
    return plane, state, auth


async def test_register_replace_rotate_revoke_advance_revisions_and_epochs(
    tmp_path: Path,
) -> None:
    principal = _principal(
        "registry:agent:register",
        "registry:agent:roles:replace",
        "registry:credential:rotate",
        "registry:agent:revoke",
        "registry:role:viewer:grant",
        "registry:role:viewer:revoke",
        "registry:role:operator:grant",
    )
    plane, registry, _ = _control_plane(tmp_path, principal)
    registered = await plane.register(
        RegisterAgentCommand(
            operation_id="register",
            target_agent_id="agent-1",
            name="One",
            roles=("viewer",),
            expected_registry_revision=0,
        ),
        object(),
    )
    replaced = await plane.replace_roles(
        ReplaceAgentRolesCommand(
            operation_id="roles",
            target_agent_id="agent-1",
            roles=("operator",),
            expected_registry_revision=1,
        ),
        object(),
    )
    rotated = await plane.rotate_credentials(
        RotateAgentCredentialsCommand(
            operation_id="rotate",
            target_agent_id="agent-1",
            expected_registry_revision=2,
        ),
        object(),
    )
    revoked = await plane.revoke(
        RevokeAgentCommand(
            operation_id="revoke",
            target_agent_id="agent-1",
            expected_registry_revision=3,
        ),
        object(),
    )

    assert registered.record_revision == registered.credential_epoch == 1
    assert replaced.roles == ("operator",)
    assert replaced.record_revision == 2
    assert replaced.credential_epoch == 1
    assert rotated.record_revision == 3
    assert rotated.credential_epoch == 2
    assert revoked.record_revision == 4
    assert revoked.credential_epoch == 3
    assert (await registry.snapshot()).registry_revision == 4
    with pytest.raises(RegistryError) as inactive:
        await registry.resolve("agent-1")
    assert inactive.value.failure is RegistryFailure.IDENTITY_INACTIVE


async def test_roles_are_registry_owned_and_capabilities_are_exact(tmp_path: Path) -> None:
    wildcard = _principal("registry:agent:*", "registry:role:viewer:grant")
    plane, registry, _ = _control_plane(tmp_path, wildcard)
    command = RegisterAgentCommand(
        operation_id="register", target_agent_id="agent-1", name="One", roles=("viewer",)
    )
    with pytest.raises(RegistryError) as denied:
        await plane.register(command, "secret")
    assert denied.value.failure is RegistryFailure.CAPABILITY_DENIED
    assert (await registry.snapshot()).records == ()

    unknown = command.model_copy(update={"operation_id": "unknown", "roles": ("root",)})
    exact_plane, _, _ = _control_plane(
        tmp_path / "other",
        _principal("registry:agent:register", "registry:role:viewer:grant"),
    )
    with pytest.raises(RegistryError) as role_error:
        await exact_plane.register(unknown, "secret")
    assert role_error.value.failure is RegistryFailure.UNKNOWN_ROLE


async def test_role_delta_is_authorized_atomically_inside_prepare(tmp_path: Path) -> None:
    class NoSplitReadRegistry(InMemoryAuthoritativeAgentRegistry):
        async def get_record(self, agent_id: str) -> AgentRegistryRecord:
            raise AssertionError(f"split authorization read for {agent_id}")

    registry = NoSplitReadRegistry("registry-1", audit_log=_log(tmp_path))
    principal = _principal(
        "registry:agent:register",
        "registry:agent:roles:replace",
        "registry:role:viewer:grant",
        "registry:role:viewer:revoke",
        "registry:role:operator:grant",
    )
    plane, _, _ = _control_plane(tmp_path, principal, registry=registry)
    await plane.register(
        RegisterAgentCommand(
            operation_id="register",
            target_agent_id="agent-1",
            name="One",
            roles=("viewer",),
        ),
        "credential",
    )

    replaced = await plane.replace_roles(
        ReplaceAgentRolesCommand(
            operation_id="replace",
            target_agent_id="agent-1",
            roles=("operator",),
            expected_registry_revision=1,
        ),
        "credential",
    )

    assert replaced.roles == ("operator",)


async def test_empty_roles_are_valid_and_revision_denial_records_only_observed_facts(
    tmp_path: Path,
) -> None:
    log = _log(tmp_path)
    plane, registry, _ = _control_plane(
        tmp_path,
        _principal("registry:agent:register"),
        audit_log=log,
    )
    command = RegisterAgentCommand(
        operation_id="stale",
        target_agent_id="agent-1",
        name="One",
        roles=(),
        expected_registry_revision=7,
    )
    with pytest.raises(RegistryError) as conflict:
        await plane.register(command, {"secret": "never-audited"})
    assert conflict.value.failure is RegistryFailure.REVISION_CONFLICT
    assert (await registry.snapshot()).records == ()

    snapshot = await log.read_verified()
    event = snapshot.events[0]
    evidence = event.registry_mutation_evidence
    assert evidence is not None
    assert evidence.state == "rejected"
    assert evidence.requested_registry_revision == 7
    assert evidence.observed_registry_revision == 0
    assert evidence.failure_reason is RegistryFailure.REVISION_CONFLICT
    assert "never-audited" not in event.model_dump_json()


async def test_authentication_happens_before_observation_and_no_credential_is_audited(
    tmp_path: Path,
) -> None:
    auth = Authenticator(_principal(), fail=True)
    plane, registry, _ = _control_plane(tmp_path, auth.principal, authenticator=auth)
    credential = {"raw": "super-secret"}
    with pytest.raises(AuthenticationError):
        await plane.revoke(
            RevokeAgentCommand(operation_id="revoke", target_agent_id="missing"), credential
        )
    assert auth.credentials == [credential]
    assert (await registry.snapshot()).records == ()
    assert list((tmp_path / "audit").glob("*.jsonl")) == []


async def test_audit_failure_leaves_prepared_without_visible_mutation(tmp_path: Path) -> None:
    class FailingAudit:
        async def write_once(self, event: AuditEvent) -> AuditEvent:
            raise OSError("unavailable")

    plane, registry, _ = _control_plane(
        tmp_path,
        _principal("registry:agent:register"),
        audit_log=FailingAudit(),
    )
    command = RegisterAgentCommand(operation_id="register", target_agent_id="agent-1", name="One")
    with pytest.raises(OSError):
        await plane.register(command, "secret")
    assert (await registry.snapshot()).records == ()
    operation = await _bind_registry_control_plane(registry).get_operation("register")
    assert operation is not None
    assert operation.state is RegistryOperationState.PREPARED


async def test_tampered_signed_audit_result_cannot_commit(tmp_path: Path) -> None:
    class TamperingAudit:
        signed: AuditEvent | None = None

        async def write_once(self, event: AuditEvent) -> AuditEvent:
            self.signed = event.model_copy(
                update={
                    "trace_id": "forged",
                    "event_hash": "b" * 64,
                    "chain_id": "chain",
                    "sequence": 1,
                    "key_id": "key",
                }
            )
            return self.signed

        async def read_verified(self, *, require_checkpoint: bool = False) -> object:
            assert self.signed is not None
            return SimpleNamespace(
                events=(self.signed,),
                verification=SimpleNamespace(valid=True),
            )

    plane, registry, _ = _control_plane(
        tmp_path,
        _principal("registry:agent:register"),
        audit_log=TamperingAudit(),
    )
    command = RegisterAgentCommand(operation_id="register", target_agent_id="agent-1", name="One")
    with pytest.raises(RegistryError) as tampered:
        await plane.register(command, "secret")
    assert tampered.value.failure is RegistryFailure.TAMPER_DETECTED
    assert (await registry.snapshot()).records == ()


async def test_in_memory_registry_rechecks_its_own_audit_before_commit(
    tmp_path: Path,
) -> None:
    authoritative = _log(tmp_path / "authoritative")
    mismatched = _log(tmp_path / "mismatched")
    registry = InMemoryAuthoritativeAgentRegistry("registry-1", audit_log=authoritative)
    plane = AgentRegistryControlPlane(
        registry,
        Authenticator(_principal("registry:agent:register")),
        mismatched,
        _policy(),
        clock=lambda: NOW,
    )

    with pytest.raises(RegistryError) as rejected:
        await plane.register(
            RegisterAgentCommand(
                operation_id="register",
                target_agent_id="agent-1",
                name="One",
            ),
            "secret",
        )

    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED
    assert (await registry.snapshot()).registry_revision == 0
    assert (await authoritative.read_verified()).events == ()
    operation = await _bind_registry_control_plane(registry).get_operation("register")
    assert operation is not None
    assert operation.state is RegistryOperationState.PREPARED


async def test_control_plane_rechecks_expiry_before_registry_observation(tmp_path: Path) -> None:
    expired = ControlPlanePrincipal(
        principal_id="admin",
        capabilities=("registry:agent:revoke",),
        method="test",
        authority="tests",
        credential_digest="a" * 64,
        issued_at=NOW - timedelta(minutes=10),
        not_before=NOW - timedelta(minutes=10),
        authenticated_at=NOW - timedelta(minutes=2),
        expires_at=NOW - timedelta(minutes=1),
    )
    plane, registry, _ = _control_plane(tmp_path, expired)
    with pytest.raises(AuthenticationError) as error:
        await plane.revoke(
            RevokeAgentCommand(operation_id="revoke", target_agent_id="missing"), "secret"
        )
    assert error.value.failure is AuthenticationFailure.CREDENTIAL_EXPIRED
    assert (await registry.snapshot()).records == ()


async def test_control_plane_rechecks_principal_before_authorization_audit(
    tmp_path: Path,
) -> None:
    principal = _principal("registry:agent:register")
    times = iter((NOW, principal.expires_at))
    log = _log(tmp_path)
    registry = InMemoryAuthoritativeAgentRegistry("registry-1", audit_log=log)
    plane = AgentRegistryControlPlane(
        registry,
        Authenticator(principal),
        log,
        _policy(),
        clock=lambda: next(times),
    )

    with pytest.raises(AuthenticationError) as error:
        await plane.register(
            RegisterAgentCommand(
                operation_id="register",
                target_agent_id="agent-1",
                name="One",
            ),
            "secret",
        )

    assert error.value.failure is AuthenticationFailure.CREDENTIAL_EXPIRED
    assert (await registry.snapshot()).records == ()
    operation = await _bind_registry_control_plane(registry).get_operation("register")
    assert operation is not None
    assert operation.state is RegistryOperationState.PREPARED
    assert (await log.read_verified()).events == ()


async def test_missing_target_is_audited_with_stable_registry_failure(tmp_path: Path) -> None:
    log = _log(tmp_path)
    plane, registry, _ = _control_plane(
        tmp_path,
        _principal("registry:credential:rotate"),
        audit_log=log,
    )

    with pytest.raises(RegistryError) as error:
        await plane.rotate_credentials(
            RotateAgentCredentialsCommand(
                operation_id="rotate",
                target_agent_id="missing",
            ),
            "secret",
        )

    assert error.value.failure is RegistryFailure.IDENTITY_NOT_FOUND
    assert (await registry.snapshot()).records == ()
    events = (await log.read_verified()).events
    assert len(events) == 1
    assert events[0].reason_codes == (RegistryFailure.IDENTITY_NOT_FOUND.value,)


async def test_revoke_does_not_depend_on_role_policy_remaining_configured(
    tmp_path: Path,
) -> None:
    log = _log(tmp_path)
    registry = InMemoryAuthoritativeAgentRegistry("registry-1", audit_log=log)
    first = AgentRegistryControlPlane(
        registry,
        Authenticator(
            _principal(
                "registry:agent:register",
                "registry:role:viewer:grant",
            )
        ),
        log,
        _policy(),
        clock=lambda: NOW,
    )
    await first.register(
        RegisterAgentCommand(
            operation_id="register",
            target_agent_id="agent-1",
            name="One",
            roles=("viewer",),
        ),
        "secret",
    )
    narrowed = AgentRegistryControlPlane(
        registry,
        Authenticator(_principal("registry:agent:revoke")),
        _log(tmp_path),
        RoleGrantPolicy(),
        clock=lambda: NOW,
    )

    revoked = await narrowed.revoke(
        RevokeAgentCommand(
            operation_id="revoke",
            target_agent_id="agent-1",
            expected_registry_revision=1,
        ),
        "secret",
    )

    assert revoked.status.value == "revoked"


async def test_idempotent_retry_returns_one_commit_and_changed_actor_conflicts(
    tmp_path: Path,
) -> None:
    principal = _principal("registry:agent:register")
    plane, registry, _ = _control_plane(tmp_path, principal)
    command = RegisterAgentCommand(operation_id="register", target_agent_id="agent-1", name="One")
    first = await plane.register(command, "secret")
    second = await plane.register(command, "secret")
    assert second == first
    assert (await registry.snapshot()).registry_revision == 1

    other, _, _ = _control_plane(
        tmp_path,
        _principal("registry:agent:register", principal_id="other"),
        registry=registry,
        audit_log=_log(tmp_path),
    )
    with pytest.raises(RegistryError) as conflict:
        await other.register(command, "other-secret")
    assert conflict.value.failure is RegistryFailure.OPERATION_CONFLICT


async def test_prepared_retry_accepts_fresh_authentication_timestamps(tmp_path: Path) -> None:
    underlying = _log(tmp_path)

    class FailOnceAudit:
        failed = False

        async def write(self, event: AuditEvent) -> AuditEvent:
            return await underlying.write(event)

        async def write_once(self, event: AuditEvent) -> AuditEvent:
            if not self.failed:
                self.failed = True
                raise OSError("temporary outage")
            return await underlying.write_once(event)

        async def read_verified(self, *, require_checkpoint: bool = False) -> object:
            return await underlying.read_verified(require_checkpoint=require_checkpoint)

    first_principal = _principal("registry:agent:register").model_copy(
        update={"authenticated_at": NOW - timedelta(seconds=1)}
    )
    second_principal = _principal("registry:agent:register")
    audit = FailOnceAudit()
    registry = InMemoryAuthoritativeAgentRegistry("registry-1", audit_log=underlying)
    command = RegisterAgentCommand(
        operation_id="register",
        target_agent_id="agent-1",
        name="One",
    )
    first, _, _ = _control_plane(
        tmp_path,
        first_principal,
        registry=registry,
        audit_log=audit,
    )
    with pytest.raises(OSError):
        await first.register(command, "same-credential")

    retry, _, _ = _control_plane(
        tmp_path,
        second_principal,
        registry=registry,
        audit_log=audit,
    )
    committed = await retry.register(command, "same-credential")

    assert committed.agent_id == "agent-1"
    assert len((await underlying.read_verified()).events) == 1


async def test_repeated_rejection_is_recorded_as_distinct_attempts(tmp_path: Path) -> None:
    times = iter((NOW, NOW + timedelta(seconds=1)))
    log = _log(tmp_path)
    registry = InMemoryAuthoritativeAgentRegistry("registry-1", audit_log=log)
    plane = AgentRegistryControlPlane(
        registry,
        Authenticator(_principal()),
        log,
        _policy(),
        clock=lambda: next(times),
    )
    command = RegisterAgentCommand(
        operation_id="denied",
        target_agent_id="agent-1",
        name="One",
    )

    for _ in range(2):
        with pytest.raises(RegistryError) as denied:
            await plane.register(command, "credential")
        assert denied.value.failure is RegistryFailure.CAPABILITY_DENIED

    events = (await log.read_verified()).events
    assert len(events) == 2
    assert events[0].event_id != events[1].event_id
    assert all(event.reason_codes == (RegistryFailure.CAPABILITY_DENIED.value,) for event in events)


async def test_repeated_cancellation_drains_authorization_and_commit(tmp_path: Path) -> None:
    underlying = _log(tmp_path)
    entered = asyncio.Event()
    release = asyncio.Event()

    class BlockingAudit:
        async def write(self, event: AuditEvent) -> AuditEvent:
            return await underlying.write(event)

        async def write_once(self, event: AuditEvent) -> AuditEvent:
            entered.set()
            await release.wait()
            return await underlying.write_once(event)

        async def read_verified(self, *, require_checkpoint: bool = False) -> object:
            return await underlying.read_verified(require_checkpoint=require_checkpoint)

    plane, registry, _ = _control_plane(
        tmp_path,
        _principal("registry:agent:register"),
        audit_log=BlockingAudit(),
    )
    task = asyncio.create_task(
        plane.register(
            RegisterAgentCommand(operation_id="register", target_agent_id="agent-1", name="One"),
            "secret",
        )
    )
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert (await registry.resolve("agent-1")).name == "One"


async def test_cancellation_preserves_safe_audit_failure_evidence(tmp_path: Path) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    class FailingAfterCancellationAudit:
        async def write_once(self, event: AuditEvent) -> AuditEvent:
            entered.set()
            await release.wait()
            raise OSError("sensitive backend detail")

    plane, registry, _ = _control_plane(
        tmp_path,
        _principal("registry:agent:register"),
        audit_log=FailingAfterCancellationAudit(),
    )
    with capture_logs() as logs:
        task = asyncio.create_task(
            plane.register(
                RegisterAgentCommand(
                    operation_id="register",
                    target_agent_id="agent-1",
                    name="One",
                ),
                "secret",
            )
        )
        await entered.wait()
        task.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    failures = [
        entry for entry in logs if entry["event"] == "registry_mutation_failed_during_cancellation"
    ]
    assert len(failures) == 1
    assert failures[0]["error_type"] == "OSError"
    assert "sensitive backend detail" not in str(failures)
    assert (await registry.snapshot()).records == ()


async def test_concurrent_same_base_prepares_allow_only_one_commit(tmp_path: Path) -> None:
    underlying = _log(tmp_path)
    entered = 0
    both_entered = asyncio.Event()
    release = asyncio.Event()

    class BlockingAudit:
        async def write(self, event: AuditEvent) -> AuditEvent:
            return await underlying.write(event)

        async def write_once(self, event: AuditEvent) -> AuditEvent:
            nonlocal entered
            entered += 1
            if entered == 2:
                both_entered.set()
            await release.wait()
            return await underlying.write_once(event)

        async def read_verified(self, *, require_checkpoint: bool = False) -> object:
            return await underlying.read_verified(require_checkpoint=require_checkpoint)

    principal = _principal("registry:agent:register")
    plane, registry, _ = _control_plane(tmp_path, principal, audit_log=BlockingAudit())
    first = asyncio.create_task(
        plane.register(
            RegisterAgentCommand(
                operation_id="one",
                target_agent_id="agent-1",
                name="One",
                expected_registry_revision=0,
            ),
            "secret",
        )
    )
    second = asyncio.create_task(
        plane.register(
            RegisterAgentCommand(
                operation_id="two",
                target_agent_id="agent-2",
                name="Two",
                expected_registry_revision=0,
            ),
            "secret",
        )
    )
    await both_entered.wait()
    release.set()
    results = await asyncio.gather(first, second, return_exceptions=True)

    assert sum(isinstance(result, RegistryError) for result in results) == 1
    assert (await registry.snapshot()).registry_revision == 1
    states = {
        (await _bind_registry_control_plane(registry).get_operation("one")).state,  # type: ignore[union-attr]
        (await _bind_registry_control_plane(registry).get_operation("two")).state,  # type: ignore[union-attr]
    }
    assert states == {RegistryOperationState.COMMITTED, RegistryOperationState.CONFLICTED}
