"""The collector's dedup index must stay complete while its event cache is bounded."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 -- pytest resolves fixture annotations at runtime

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.audit_collector import AuditCollectorServer, SigningAuditBackend
from agentguard.exceptions import AuditCollectorProtocolError
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext

_CACHE_LIMIT = 2


def _event(event_id: str, *, action: str = "tool:test") -> AuditEvent:
    identity = AgentIdentity(agent_id="bounds-client", name="Bounds client", roles=[])
    permission = PermissionContext(
        agent=identity,
        requested_action=action,
        resource="resource",
        granted=True,
    )
    return AuditEvent(
        event_id=event_id,
        timestamp=datetime(2026, 8, 28, tzinfo=UTC),
        agent_id=identity.agent_id,
        action=action,
        resource="resource",
        permission_context=permission,
        result="allowed",
        duration_ms=1.0,
        trace_id=f"trace-{event_id}",
    )


@pytest.fixture
async def bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[AuditCollectorServer, SigningAuditBackend, Path, Path]]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "bounds-test-key-0123456789abcdef01")
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        max_cached_events=_CACHE_LIMIT,
    )
    await server.start()
    try:
        yield server, SigningAuditBackend(socket_path), audit_directory, state_path
    finally:
        await server.close()


async def test_cache_is_bounded_while_the_dedup_index_stays_complete(
    bounded: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    server, client, _, _ = bounded

    for index in range(5):
        await client.write(_event(f"evt-{index}"))

    assert len(server._recent_events) == _CACHE_LIMIT
    assert len(server._event_index) == 5


async def test_retry_of_an_evicted_event_returns_the_committed_event(
    bounded: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    server, client, _, _ = bounded
    first = await client.write(_event("evt-evicted"))
    for index in range(5):
        await client.write(_event(f"evt-filler-{index}"))
    assert "evt-evicted" not in server._recent_events

    retried = await client.write(_event("evt-evicted"))

    assert retried == first


async def test_conflicting_retry_of_an_evicted_event_is_still_rejected(
    bounded: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    server, client, _, _ = bounded
    await client.write(_event("evt-conflict"))
    for index in range(5):
        await client.write(_event(f"evt-filler-{index}"))
    assert "evt-conflict" not in server._recent_events

    with pytest.raises(AuditCollectorProtocolError, match="event_id_conflict"):
        await client.write(_event("evt-conflict", action="tool:other"))


async def test_evicted_retry_never_returns_a_tampered_record_from_the_log(
    bounded: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    """The reload path reads unverified JSONL and must re-prove what it found."""

    server, client, audit_directory, _ = bounded
    original = await client.write(_event("evt-substituted"))
    for index in range(5):
        await client.write(_event(f"evt-filler-{index}"))
    assert "evt-substituted" not in server._recent_events
    committed_digest = server._event_index["evt-substituted"].fingerprint_digest

    log_file = next(audit_directory.glob("audit-*.jsonl"))
    lines = log_file.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"action":"tool:test"', '"action":"tool:attacker"', 1)
    assert '"action":"tool:attacker"' in lines[0]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditCollectorProtocolError, match="event_index_desynchronized"):
        await client.write(_event("evt-substituted"))

    assert original.action == "tool:test"
    # The dedup anchor must survive contact with the tampered log.
    assert server._event_index["evt-substituted"].fingerprint_digest == committed_digest


async def test_restart_rebuilds_a_complete_index_and_a_bounded_cache(
    bounded: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
    tmp_path: Path,
) -> None:
    server, client, audit_directory, state_path = bounded
    first = await client.write(_event("evt-restart-0"))
    for index in range(1, 5):
        await client.write(_event(f"evt-restart-{index}"))
    await server.close()

    socket_path = tmp_path / "run" / "restarted.sock"
    restarted = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        max_cached_events=_CACHE_LIMIT,
    )
    await restarted.start()
    try:
        assert len(restarted._event_index) == 5
        assert len(restarted._recent_events) == _CACHE_LIMIT
        reclient = SigningAuditBackend(socket_path)
        assert await reclient.write(_event("evt-restart-0")) == first
        with pytest.raises(AuditCollectorProtocolError, match="event_id_conflict"):
            await reclient.write(_event("evt-restart-0", action="tool:other"))
    finally:
        await restarted.close()


def test_cache_bound_must_be_positive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "bounds-test-key-0123456789abcdef01")
    with pytest.raises(ValueError, match="max_cached_events"):
        AuditCollectorServer(
            socket_path=tmp_path / "run" / "collector.sock",
            audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
            state_path=tmp_path / "anchor" / "state.json",
            max_cached_events=0,
        )
