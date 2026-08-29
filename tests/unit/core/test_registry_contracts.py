"""Tests for authoritative-registry contracts and stable failures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agentguard.core import (
    AgentIdentityResolver,
    AgentRegistryRecord,
    AgentRegistrySnapshot,
    AgentStatus,
    AuthoritativeAgentRegistry,
    RegistryError,
    RegistryFailure,
)
from agentguard.guardrails.reason_codes import RUNTIME_REASON_CODES, is_valid_reason_code

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)


def _record(**updates: object) -> AgentRegistryRecord:
    values: dict[str, object] = {
        "agent_id": "agent-1",
        "name": "Underwriter",
        "roles": ("viewer", "operator"),
        "metadata": {"owner": "risk"},
        "credential_epoch": 1,
        "record_revision": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }
    values.update(updates)
    return AgentRegistryRecord.model_validate(values)


def test_record_is_defensive_sorted_and_frozen() -> None:
    source = {"owner": "risk"}
    record = _record(roles=("viewer", "operator", "viewer"), metadata=source)
    source["owner"] = "forged"

    assert record.roles == ("operator", "viewer")
    assert record.metadata == {"owner": "risk"}
    with pytest.raises(TypeError):
        record.metadata["owner"] = "forged"  # type: ignore[index]
    with pytest.raises(ValidationError):
        record.status = AgentStatus.REVOKED


def test_empty_roles_are_valid_for_deny_by_default_identity() -> None:
    assert _record(roles=()).roles == ()


@pytest.mark.parametrize("field", ["created_at", "updated_at", "revoked_at"])
def test_record_rejects_naive_timestamps(field: str) -> None:
    with pytest.raises(ValidationError):
        _record(**{field: NOW.replace(tzinfo=None)})


def test_record_normalizes_timestamps_and_enforces_status_invariants() -> None:
    offset = NOW.astimezone(timezone(timedelta(hours=-5)))
    active = _record(created_at=offset, updated_at=offset)
    revoked = _record(
        status="revoked",
        credential_epoch=2,
        record_revision=2,
        updated_at=NOW + timedelta(minutes=1),
        revoked_at=NOW + timedelta(minutes=1),
    )

    assert active.created_at.tzinfo is UTC
    assert revoked.status is AgentStatus.REVOKED
    with pytest.raises(ValidationError):
        _record(status="revoked")
    with pytest.raises(ValidationError):
        _record(revoked_at=NOW)


@pytest.mark.parametrize("field", ["credential_epoch", "record_revision"])
def test_record_revisions_start_at_one(field: str) -> None:
    with pytest.raises(ValidationError):
        _record(**{field: 0})


@pytest.mark.parametrize(
    "updates",
    [
        {"credential_epoch": 2, "record_revision": 1},
        {"status": "revoked", "revoked_at": NOW, "record_revision": 1},
        {"status": "revoked", "revoked_at": NOW, "credential_epoch": 1},
    ],
)
def test_record_rejects_impossible_revision_and_epoch_states(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _record(**updates)


def test_snapshot_is_full_defensive_and_canonical() -> None:
    second = _record(agent_id="agent-2")
    first = _record(agent_id="agent-1")
    snapshot = AgentRegistrySnapshot(
        registry_id="registry-1",
        registry_revision=1,
        records=(second, first),
    )

    assert [record.agent_id for record in snapshot.records] == ["agent-1", "agent-2"]
    with pytest.raises(ValidationError):
        AgentRegistrySnapshot(registry_id="registry-1", registry_revision=1, records=(first, first))
    with pytest.raises(ValidationError):
        AgentRegistrySnapshot(
            registry_id="registry-1",
            registry_revision=0,
            records=(first,),
        )


def test_runtime_protocols_are_structural_and_read_only() -> None:
    class Registry:
        async def resolve(self, agent_id: str) -> AgentRegistryRecord:
            return _record(agent_id=agent_id)

        async def get_record(self, agent_id: str) -> AgentRegistryRecord:
            return _record(agent_id=agent_id)

        async def snapshot(self) -> AgentRegistrySnapshot:
            return AgentRegistrySnapshot(registry_id="registry-1", registry_revision=0)

    registry = Registry()
    assert isinstance(registry, AgentIdentityResolver)
    assert isinstance(registry, AuthoritativeAgentRegistry)
    for forbidden in ("register", "replace_roles", "rotate_credentials", "revoke"):
        assert forbidden not in vars(AuthoritativeAgentRegistry)


def test_registry_failures_are_safe_registered_codes() -> None:
    for failure in RegistryFailure:
        error = RegistryError(failure)
        assert error.reason_code == failure.value
        assert failure.value in RUNTIME_REASON_CODES
        assert is_valid_reason_code(failure.value)
    with pytest.raises(TypeError):
        RegistryError("REGISTRY.UNKNOWN_ROLE")  # type: ignore[arg-type]
