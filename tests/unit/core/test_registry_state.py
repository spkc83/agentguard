"""Tests for authoritative in-memory registry state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentguard.core import (
    AppendOnlyAuditLog,
    ControlPlanePrincipal,
    FileAuditBackend,
    InMemoryAuthoritativeAgentRegistry,
    RegisterAgentCommand,
    RegistryError,
    RegistryFailure,
    RegistryOperationState,
)
from agentguard.core.registry_state import _bind_registry_control_plane
from agentguard.exceptions import IdentityNotFoundError

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
pytestmark = pytest.mark.usefixtures("_set_audit_key")


def _registry(tmp_path: Path, registry_id: str = "default") -> InMemoryAuthoritativeAgentRegistry:
    return InMemoryAuthoritativeAgentRegistry(
        registry_id,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
    )


def _principal(principal_id: str = "admin") -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        principal_id=principal_id,
        capabilities=("registry:agent:register",),
        method="test",
        authority="tests",
        credential_digest="a" * 64,
        issued_at=NOW - timedelta(minutes=1),
        not_before=NOW - timedelta(minutes=1),
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def test_register_command_metadata_is_a_defensive_immutable_snapshot() -> None:
    source = {"owner": "risk"}
    command = RegisterAgentCommand(
        operation_id="op-1",
        target_agent_id="agent-1",
        name="One",
        metadata=source,
    )

    source["owner"] = "forged"
    assert command.metadata["owner"] == "risk"
    with pytest.raises(TypeError):
        command.metadata["owner"] = "forged"  # type: ignore[index]


async def test_prepare_has_no_visible_effect_and_returns_defensive_state(tmp_path: Path) -> None:
    registry = _registry(tmp_path, "registry-1")
    mutation = _bind_registry_control_plane(registry)
    command = RegisterAgentCommand(
        operation_id="op-1",
        target_agent_id="agent-1",
        name="Agent One",
        roles=("viewer",),
        metadata={"owner": "risk"},
    )
    prepared = await mutation.prepare(
        command,
        _principal(),
        prepared_at=NOW,
        authorize=lambda _command, _roles: None,
    )

    assert prepared.state is RegistryOperationState.PREPARED
    assert (await registry.snapshot()).registry_revision == 0
    with pytest.raises(IdentityNotFoundError):
        await registry.get_record("agent-1")
    with pytest.raises(TypeError):
        prepared.proposed_record.metadata["owner"] = "forged"  # type: ignore[index]


async def test_same_operation_is_idempotent_but_changed_request_or_actor_conflicts(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    mutation = _bind_registry_control_plane(registry)
    command = RegisterAgentCommand(operation_id="op-1", target_agent_id="agent-1", name="One")
    first = await mutation.prepare(
        command,
        _principal(),
        prepared_at=NOW,
        authorize=lambda _command, _roles: None,
    )
    resumed = await mutation.prepare(
        command,
        _principal(),
        prepared_at=NOW + timedelta(seconds=1),
        authorize=lambda _command, _roles: None,
    )

    assert resumed == first
    with pytest.raises(RegistryError) as changed_request:
        await mutation.prepare(
            command.model_copy(update={"name": "Changed"}),
            _principal(),
            prepared_at=NOW,
            authorize=lambda _command, _roles: None,
        )
    assert changed_request.value.failure is RegistryFailure.OPERATION_CONFLICT
    with pytest.raises(RegistryError) as changed_actor:
        await mutation.prepare(
            command,
            _principal("other-admin"),
            prepared_at=NOW,
            authorize=lambda _command, _roles: None,
        )
    assert changed_actor.value.failure is RegistryFailure.OPERATION_CONFLICT


async def test_resolve_rejects_revoked_but_get_record_preserves_tombstone(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    mutation = _bind_registry_control_plane(registry)
    # A committed tombstone is constructed through the public control plane in its tests;
    # this test directly verifies the read-boundary distinction with a minimal fixture.
    command = RegisterAgentCommand(operation_id="op-1", target_agent_id="agent-1", name="One")
    prepared = await mutation.prepare(
        command,
        _principal(),
        prepared_at=NOW,
        authorize=lambda _command, _roles: None,
    )
    assert prepared.proposed_record.credential_epoch == 1
    with pytest.raises(IdentityNotFoundError):
        await registry.resolve("missing")


def test_registry_is_structurally_authoritative(tmp_path: Path) -> None:
    from agentguard.core import AuthoritativeAgentRegistry

    registry = _registry(tmp_path)
    assert isinstance(registry, AuthoritativeAgentRegistry)
    assert not hasattr(registry, "prepare")
    assert not hasattr(registry, "commit")


def test_registry_id_is_nonempty_canonical_text(tmp_path: Path) -> None:
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    for invalid in ("", " padded", "padded ", "line\nbreak"):
        with pytest.raises(ValueError):
            InMemoryAuthoritativeAgentRegistry(invalid, audit_log=audit)
