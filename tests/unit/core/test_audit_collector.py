"""Security-contract tests for the Unix-domain-socket audit collector."""

from __future__ import annotations

import asyncio
import json
import os
import struct
import time
from collections.abc import AsyncIterator
from contextlib import suppress
from datetime import UTC, datetime
from multiprocessing import get_context
from pathlib import Path  # noqa: TC003 -- pytest resolves fixture annotations at runtime
from typing import Any

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.audit_collector import AuditCollectorServer, SigningAuditBackend
from agentguard.exceptions import (
    AuditCollectorOwnershipError,
    AuditCollectorProtocolError,
    AuditCollectorUnavailableError,
    AuditKeyRotationRefusedError,
    RegistryFailure,
)
from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    AuthenticationEvidence,
    GuardrailEvaluation,
    HitlEvidence,
    PermissionContext,
    ReconciliationEvidence,
    RegistryMutationEvidence,
)


def _event(event_id: str, *, action: str = "tool:test") -> AuditEvent:
    identity = AgentIdentity(agent_id="collector-client", name="Collector client", roles=[])
    permission = PermissionContext(
        agent=identity,
        requested_action=action,
        resource="resource",
        granted=True,
    )
    return AuditEvent(
        event_id=event_id,
        timestamp=datetime(2026, 8, 26, tzinfo=UTC),
        agent_id=identity.agent_id,
        action=action,
        resource="resource",
        permission_context=permission,
        result="allowed",
        duration_ms=1.0,
        trace_id=f"trace-{event_id}",
    )


def _authentication_event(evidence: AuthenticationEvidence) -> AuditEvent:
    identity = AgentIdentity(agent_id=evidence.agent_id, name="Collector client", roles=[])
    permission = PermissionContext(
        agent=identity,
        requested_action="authenticate",
        resource="agent",
        granted=True,
    )
    return AuditEvent(
        event_id="evt-authentication",
        timestamp=datetime(2026, 8, 26, tzinfo=UTC),
        agent_id=identity.agent_id,
        action="authenticate",
        resource="agent",
        permission_context=permission,
        result="allowed",
        duration_ms=1.0,
        trace_id="trace-evt-authentication",
        event_type="authentication_succeeded",
        authentication_evidence=evidence,
    )


def _run_collector_process(
    socket_path: str,
    audit_directory: str,
    state_path: str,
    key: str,
    ready: Any,
    stop: Any,
) -> None:
    os.environ["AGENTGUARD_AUDIT_KEY"] = key

    async def run() -> None:
        server = AuditCollectorServer(
            socket_path=Path(socket_path),
            audit_log=AppendOnlyAuditLog(FileAuditBackend(Path(audit_directory))),
            state_path=Path(state_path),
        )
        await server.start()
        ready.set()
        try:
            while not stop.is_set():
                await asyncio.sleep(0.01)
        finally:
            await server.close()

    asyncio.run(run())


@pytest.fixture
async def collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[AuditCollectorServer, SigningAuditBackend, Path, Path]]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "collector-test-key-0123456789abcdef")
    audit_directory = tmp_path / "audit"
    socket_path = tmp_path / "run" / "collector.sock"
    state_path = tmp_path / "anchor" / "collector-state.json"
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_directory))
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=audit_log,
        state_path=state_path,
    )
    await server.start()
    try:
        yield server, SigningAuditBackend(socket_path), audit_directory, socket_path
    finally:
        await server.close()


_ROTATED_KEY_ID = "collector-epoch-2"
_ROTATED_KEY = "collector-rotated-key-0123456789abcdef"


@pytest.fixture
async def declaring_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[AuditCollectorServer, SigningAuditBackend]]:
    """A collector whose environment already declares the next signing epoch."""

    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "collector-test-key-0123456789abcdef")
    monkeypatch.setenv(
        "AGENTGUARD_AUDIT_KEYS",
        json.dumps({_ROTATED_KEY_ID: {"key": _ROTATED_KEY, "activation_sequence": 2}}),
    )
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "collector-state.json",
    )
    await server.start()
    try:
        yield server, SigningAuditBackend(socket_path)
    finally:
        await server.close()


async def test_real_uds_round_trip_returns_attestable_verified_snapshot(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector

    committed = await client.write(_event("evt-round-trip"))
    snapshot = await client.read_verified(require_checkpoint=True)

    assert snapshot.events == (committed,)
    assert snapshot.verification.valid is True
    assert snapshot.verification.attestable is True


async def test_guardrail_evaluations_round_trip_through_collector(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector
    evaluation = GuardrailEvaluation(
        guardrail_id="pii-redaction",
        guardrail_version="1.2.0",
        stage="input",
        effect="transform",
        reason_codes=("PII_REDACTED",),
        duration_ms=0.25,
        enforced=True,
    )

    committed = await client.write(
        _event("evt-evaluation").model_copy(update={"guardrail_evaluations": (evaluation,)})
    )
    snapshot = await client.read_verified(require_checkpoint=True)

    assert committed.hash_schema_version == 8
    assert snapshot.events[0].guardrail_evaluations == (evaluation,)


async def test_hitl_evidence_round_trips_through_collector(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector
    evidence = HitlEvidence(
        escalation_id="esc-collector",
        state="requested",
        expires_at=datetime(2026, 8, 26, 1, tzinfo=UTC),
    )

    committed = await client.write(
        _event("evt-hitl").model_copy(
            update={
                "event_type": "escalation_requested",
                "result": "escalated",
                "hitl_evidence": evidence,
            }
        )
    )
    snapshot = await client.read_verified(require_checkpoint=True)

    assert committed.hash_schema_version == 8
    assert snapshot.events[0].hitl_evidence == evidence


async def test_reconciliation_evidence_round_trips_through_collector(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector
    evidence = ReconciliationEvidence(
        escalation_id="esc-collector",
        claim_id="claim-collector",
        reconciliation_id="reconcile-collector",
        classification="claimed_without_terminal",
        state="in_doubt",
        reconciler_id="operator-collector",
        reason_digest="a" * 64,
        assessed_at=datetime(2026, 8, 26, 1, tzinfo=UTC),
        audit_chain_id="chain-collector",
        audit_head_sequence=1,
        audit_head_event_hash="b" * 64,
        journal_revision=1,
        journal_digest="c" * 64,
    )

    committed = await client.write(
        _event("evt-reconciliation").model_copy(
            update={
                "event_type": "execution_in_doubt",
                "result": "escalated",
                "reconciliation_evidence": evidence,
            }
        )
    )
    snapshot = await client.read_verified(require_checkpoint=True)

    assert committed.hash_schema_version == 8
    assert snapshot.events[0].reconciliation_evidence == evidence


async def test_authentication_evidence_round_trips_through_collector(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector
    evidence = AuthenticationEvidence(
        state="verified",
        method="workload_identity",
        authority="trust-domain.example",
        agent_id="collector-client",
        credential_digest="d" * 64,
        authenticated_at=datetime(2026, 8, 26, 1, tzinfo=UTC),
        issued_at=datetime(2026, 8, 26, 0, tzinfo=UTC),
        not_before=datetime(2026, 8, 26, 0, 30, tzinfo=UTC),
        expires_at=datetime(2026, 8, 26, 2, tzinfo=UTC),
        registry_revision=4,
    )

    committed = await client.write(_authentication_event(evidence))
    snapshot = await client.read_verified(require_checkpoint=True)

    assert committed.hash_schema_version == 8
    assert snapshot.events[0].authentication_evidence == evidence


async def test_registry_mutation_evidence_round_trips_through_collector(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector
    evidence = RegistryMutationEvidence(
        state="rejected",
        operation_id="operation-collector",
        registry_id="collector-registry",
        mutation="replace_roles",
        principal_id="administrator-collector",
        authentication_method="hardware_token",
        authentication_authority="admin.example",
        credential_digest="1" * 64,
        capabilities_digest="2" * 64,
        target_agent_id="collector-client",
        request_digest="3" * 64,
        prepared_at=datetime(2026, 8, 26, 1, tzinfo=UTC),
        failure_reason=RegistryFailure.UNKNOWN_ROLE,
    )
    identity = AgentIdentity(
        agent_id=evidence.principal_id,
        name=evidence.principal_id,
        roles=[],
    )
    permission = PermissionContext(
        agent=identity,
        requested_action="registry.replace_roles",
        resource="agent_registry:collector-registry",
        granted=False,
        reason=RegistryFailure.UNKNOWN_ROLE.value,
    )
    event = AuditEvent(
        event_id="evt-registry-mutation",
        timestamp=datetime(2026, 8, 26, tzinfo=UTC),
        agent_id=identity.agent_id,
        action="registry.replace_roles",
        resource="agent_registry:collector-registry",
        permission_context=permission,
        result="rejected",
        duration_ms=1.0,
        trace_id="trace-registry-mutation",
        event_type="registry_mutation_rejected",
        reason_codes=(RegistryFailure.UNKNOWN_ROLE.value,),
        registry_mutation_evidence=evidence,
    )

    committed = await client.write(event)
    snapshot = await client.read_verified(require_checkpoint=True)

    assert committed.hash_schema_version == 8
    assert snapshot.events[0].registry_mutation_evidence == evidence


def _await_ready(ready: Any, process: Any, timeout: float = 60.0) -> None:
    """Wait for the spawned collector to signal readiness.

    A traced cold interpreter (coverage's ``process_startup`` hook fires in
    every spawned child) can take many seconds to import the package under
    full-suite CPU contention, so the deadline is generous — but a child that
    died is reported within half a second instead of waiting out the budget.
    """
    deadline = time.monotonic() + timeout
    while not ready.wait(0.5):
        if not process.is_alive():
            raise AssertionError(f"collector process exited early: exitcode={process.exitcode}")
        if time.monotonic() > deadline:
            raise AssertionError("collector process never became ready")


async def test_application_process_uses_real_collector_without_key_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = get_context("spawn")
    ready = context.Event()
    stop = context.Event()
    socket_path = tmp_path / "run" / "collector.sock"
    process = context.Process(
        target=_run_collector_process,
        args=(
            str(socket_path),
            str(tmp_path / "audit"),
            str(tmp_path / "anchor" / "state.json"),
            "subprocess-only-audit-key-0123456789abcdef",
            ready,
            stop,
        ),
    )
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEY", raising=False)
    process.start()
    try:
        await asyncio.to_thread(_await_ready, ready, process)
        assert "AGENTGUARD_AUDIT_KEY" not in os.environ
        client = SigningAuditBackend(socket_path, request_timeout=30.0)
        committed = await client.write(_event("evt-subprocess"))
        assert committed.sequence == 1
    finally:
        stop.set()
        await asyncio.to_thread(process.join, 30)
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 5)
    assert process.exitcode == 0


async def test_concurrent_clients_receive_one_contiguous_global_sequence(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, socket_path = collector
    clients = [SigningAuditBackend(socket_path) for _ in range(20)]

    committed = await asyncio.gather(
        *(candidate.write(_event(f"evt-{index:02d}")) for index, candidate in enumerate(clients))
    )

    sequences = [event.sequence for event in committed]
    assert all(sequence is not None for sequence in sequences)
    assert sorted(sequence for sequence in sequences if sequence is not None) == list(range(1, 21))
    snapshot = await client.read_verified(require_checkpoint=True)
    assert [event.sequence for event in snapshot.events] == list(range(1, 21))


async def test_client_contains_no_signing_key_material(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector

    client_state = repr(vars(client)).encode()

    assert b"collector-test-key" not in client_state
    assert not any("key" in name.lower() for name in vars(client))


async def test_unavailable_collector_fails_closed(tmp_path: Path) -> None:
    client = SigningAuditBackend(tmp_path / "missing" / "collector.sock", request_timeout=0.05)

    with pytest.raises(AuditCollectorUnavailableError):
        await client.write(_event("evt-unavailable"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_hash", "caller-hash"),
        ("prev_hash", "caller-previous"),
        ("sequence", 42),
        ("key_id", "caller-key"),
        ("chain_id", "caller-chain"),
    ],
)
async def test_caller_supplied_integrity_field_is_rejected(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
    field: str,
    value: object,
) -> None:
    _, client, _, _ = collector
    event = _event(f"evt-integrity-{field}").model_copy(update={field: value})

    with pytest.raises((ValueError, AuditCollectorProtocolError)):
        await client.write(event)


async def test_identical_event_retry_is_idempotent(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector
    event = _event("evt-retry")

    first = await client.write(event)
    second = await client.write(event)

    assert second == first
    snapshot = await client.read_verified(require_checkpoint=True)
    assert [item.event_id for item in snapshot.events] == ["evt-retry"]


async def test_conflicting_duplicate_event_id_is_rejected(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector
    await client.write(_event("evt-conflict", action="tool:first"))

    with pytest.raises(AuditCollectorProtocolError):
        await client.write(_event("evt-conflict", action="tool:second"))


async def test_oversized_frame_is_rejected_without_stopping_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "collector-test-key-0123456789abcdef")
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "state.json",
        max_frame_bytes=2048,
    )
    await server.start()
    try:
        reader, writer = await asyncio.open_unix_connection(socket_path)
        writer.write(struct.pack(">I", 2049))
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=1)
        writer.close()
        await writer.wait_closed()

        assert len(response) <= 2048 + 4
        committed = await SigningAuditBackend(socket_path, max_frame_bytes=2048).write(
            _event("evt-after-oversized")
        )
        assert committed.sequence == 1
    finally:
        await server.close()


async def test_malformed_frame_is_rejected_without_stopping_collector(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, socket_path = collector
    reader, writer = await asyncio.open_unix_connection(socket_path)
    payload = b"not-json"
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout=1)
    writer.close()
    await writer.wait_closed()

    assert response
    committed = await client.write(_event("evt-after-malformed"))
    assert committed.sequence == 1


async def test_second_collector_for_same_log_directory_is_refused(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
    tmp_path: Path,
) -> None:
    _, _, audit_directory, _ = collector
    competing = AuditCollectorServer(
        socket_path=tmp_path / "other-run" / "collector.sock",
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=tmp_path / "other-anchor" / "state.json",
    )

    with pytest.raises(AuditCollectorOwnershipError):
        await competing.start()


async def test_socket_has_owner_only_permissions(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, _, _, socket_path = collector

    assert os.stat(socket_path).st_mode & 0o777 == 0o600
    assert os.stat(socket_path.parent).st_mode & 0o777 == 0o700


async def test_snapshot_event_cap_is_enforced_server_side(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "collector-test-key-0123456789abcdef")
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "state.json",
        max_snapshot_events=1,
    )
    await server.start()
    try:
        client = SigningAuditBackend(socket_path)
        await client.write(_event("evt-cap-1"))
        await client.write(_event("evt-cap-2"))

        with pytest.raises(AuditCollectorProtocolError):
            await client.read_verified(require_checkpoint=True)
    finally:
        await server.close()


async def test_snapshot_byte_cap_is_enforced_server_side(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "collector-test-key-0123456789abcdef")
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "state.json",
        max_snapshot_bytes=512,
    )
    await server.start()
    try:
        client = SigningAuditBackend(socket_path)
        await client.write(_event("evt-byte-cap").model_copy(update={"resource": "x" * 1024}))

        with pytest.raises(AuditCollectorProtocolError):
            await client.read_verified(require_checkpoint=True)
    finally:
        await server.close()


async def test_snapshot_is_internally_consistent_during_concurrent_append(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, socket_path = collector
    for index in range(20):
        await client.write(_event(f"evt-snapshot-{index:02d}"))

    snapshot, _ = await asyncio.gather(
        client.read_verified(require_checkpoint=True),
        SigningAuditBackend(socket_path).write(_event("evt-concurrent")),
    )

    count = len(snapshot.events)
    assert count in {20, 21}
    assert snapshot.verification.event_count == count
    assert [event.sequence for event in snapshot.events] == list(range(1, count + 1))
    assert snapshot.verification.head_sequence == count


async def test_connection_limit_rejects_excess_socket_before_reading_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "connection-limit-key-padded-abcd")
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "state.json",
        max_connections=1,
    )
    await server.start()
    first_reader, first_writer = await asyncio.open_unix_connection(socket_path)
    del first_reader
    try:
        for _ in range(100):
            if server._active_connections == 1:
                break
            await asyncio.sleep(0)
        second_reader, second_writer = await asyncio.open_unix_connection(socket_path)
        try:
            assert await asyncio.wait_for(second_reader.read(), 1) == b""
            assert server._active_connections == 1
        finally:
            second_writer.close()
            await second_writer.wait_closed()
    finally:
        first_writer.close()
        await first_writer.wait_closed()
        await server.close()


async def test_shutdown_retains_singleton_until_active_operation_finishes(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, client, audit_directory, _ = collector
    entered = asyncio.Event()
    release = asyncio.Event()
    original_dispatch = server._dispatch

    async def blocked_dispatch(request: object) -> dict[str, object]:
        entered.set()
        await release.wait()
        return await original_dispatch(request)  # type: ignore[arg-type]

    monkeypatch.setattr(server, "_dispatch", blocked_dispatch)
    request = asyncio.create_task(client.verify_chain())
    await asyncio.wait_for(entered.wait(), 1)
    closing = asyncio.create_task(server.close())
    await asyncio.sleep(0)
    replacement = AuditCollectorServer(
        socket_path=tmp_path / "replacement" / "collector.sock",
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=server._state_path,
    )
    with pytest.raises(AuditCollectorOwnershipError):
        await replacement.start()

    release.set()
    with suppress(AuditCollectorUnavailableError, AuditCollectorProtocolError):
        await request
    await closing
    await replacement.start()
    await replacement.close()


async def test_client_stops_snapshot_when_page_exceeds_advertised_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = SigningAuditBackend(tmp_path / "unused.sock", max_snapshot_bytes=256)
    event = _event("evt-malicious-page").model_copy(update={"resource": "x" * 1024})

    async def fake_rpc(operation: str, _payload: dict[str, object]) -> dict[str, object]:
        if operation == "snapshot_open":
            return {
                "token": "snapshot",
                "total": 1,
                "total_bytes": 1,
                "verification": {
                    "valid": True,
                    "event_count": 1,
                    "checkpoint_status": "verified",
                    "attestable": True,
                },
            }
        return {
            "token": "snapshot",
            "offset": 0,
            "total": 1,
            "events": [event.model_dump(mode="json")],
        }

    monkeypatch.setattr(client, "_rpc", fake_rpc)
    with pytest.raises(AuditCollectorProtocolError, match="snapshot_too_large"):
        await client.read_verified(require_checkpoint=True)


async def test_operation_payload_rejects_unknown_fields(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    _, client, _, _ = collector
    with pytest.raises(AuditCollectorProtocolError, match="invalid_request"):
        await client._rpc("verify", {"unexpected": True})
    with pytest.raises(AuditCollectorProtocolError, match="invalid_request"):
        await client._rpc("snapshot_open", {"require_checkpoint": "false"})


async def test_timed_out_operation_retains_capacity_until_it_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "operation-capacity-key-padded-ab")
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "state.json",
        operation_timeout=0.01,
        max_operations=1,
    )
    await server.start()
    entered = asyncio.Event()
    release = asyncio.Event()
    original_dispatch = server._dispatch

    async def blocked_dispatch(request: object) -> dict[str, object]:
        entered.set()
        await release.wait()
        return await original_dispatch(request)  # type: ignore[arg-type]

    monkeypatch.setattr(server, "_dispatch", blocked_dispatch)
    client = SigningAuditBackend(socket_path)
    first = asyncio.create_task(client.verify_chain())
    await asyncio.wait_for(entered.wait(), 1)
    with pytest.raises(AuditCollectorProtocolError, match="operation_timeout"):
        await first
    assert len(server._operation_tasks) == 1
    with pytest.raises(AuditCollectorProtocolError, match="collector_overloaded"):
        await client.verify_chain()
    assert len(server._operation_tasks) == 1
    unfinished = tuple(server._operation_tasks)
    release.set()
    await asyncio.wait_for(asyncio.gather(*unfinished), 1)
    await asyncio.sleep(0)
    assert not server._operation_tasks
    await server.close()


async def test_live_socket_cannot_be_rebound_to_a_different_log(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
    tmp_path: Path,
) -> None:
    _, client, _, socket_path = collector
    competing = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "different-audit")),
        state_path=tmp_path / "different-anchor" / "state.json",
    )
    with pytest.raises(AuditCollectorOwnershipError, match="socket"):
        await competing.start()
    assert (await client.write(_event("evt-original-socket"))).sequence == 1


async def test_restart_rolls_signed_external_state_forward_from_verified_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "restart-reconciliation-key-padde")
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"
    first_server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await first_server.start()
    client = SigningAuditBackend(socket_path)
    await client.write(_event("evt-reconcile-1"))
    assert first_server._state is not None
    old_state = first_server._state
    await client.write(_event("evt-reconcile-2"))
    await first_server.close()
    state_path.write_text(old_state.model_dump_json())

    replacement = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await replacement.start()
    try:
        assert replacement._state is not None
        assert replacement._state.checkpoint is not None
        assert replacement._state.checkpoint.head_sequence == 2
    finally:
        await replacement.close()


async def test_restart_rejects_corrupt_external_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "restart-corruption-key-padded-ab")
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await server.start()
    await SigningAuditBackend(socket_path).write(_event("evt-corrupt-state"))
    await server.close()
    state = json.loads(state_path.read_text())
    state["signature"] = "0" * 64
    state_path.write_text(json.dumps(state))

    replacement = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    with pytest.raises(AuditCollectorOwnershipError, match="signature"):
        await replacement.start()


async def test_rotation_signs_new_events_with_new_epoch_and_preserves_old_verification(
    declaring_collector: tuple[AuditCollectorServer, SigningAuditBackend],
) -> None:
    server, client = declaring_collector
    before = await client.write(_event("evt-before-rotation"))

    epoch = await server.rotate_key(_ROTATED_KEY_ID, _ROTATED_KEY.encode())
    after = await client.write(_event("evt-after-rotation"))
    snapshot = await client.read_verified(require_checkpoint=True)

    assert epoch.activation_sequence == 2
    assert before.key_id != epoch.key_id
    assert after.key_id == epoch.key_id
    assert snapshot.events == (before, after)
    assert snapshot.verification.valid is True


async def test_confirming_the_same_declared_epoch_twice_is_idempotent(
    declaring_collector: tuple[AuditCollectorServer, SigningAuditBackend],
) -> None:
    server, client = declaring_collector
    await client.write(_event("evt-before-repeat-rotation"))

    first = await server.rotate_key(_ROTATED_KEY_ID, _ROTATED_KEY.encode())
    second = await server.rotate_key(_ROTATED_KEY_ID, _ROTATED_KEY.encode())

    assert first == second


async def test_idempotent_retry_cannot_downgrade_rotated_state_signer(
    declaring_collector: tuple[AuditCollectorServer, SigningAuditBackend],
) -> None:
    server, client = declaring_collector
    original = _event("evt-before-state-rotation")
    committed = await client.write(original)
    epoch = await server.rotate_key(_ROTATED_KEY_ID, _ROTATED_KEY.encode())

    assert server._state is not None
    assert server._state.signing_key_id == epoch.key_id
    assert await client.write(original) == committed
    assert server._state.signing_key_id == epoch.key_id


async def test_checkpoint_rpc_refuses_locally_committed_unanchored_head(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, client, _, _ = collector
    with monkeypatch.context() as patcher:
        patcher.setattr(
            server,
            "_write_state_sync",
            lambda _state: (_ for _ in ()).throw(OSError("anchor unavailable")),
        )
        with pytest.raises(AuditCollectorProtocolError):
            await client.write(_event("evt-unanchored-head"))

    with pytest.raises(AuditCollectorProtocolError, match="anchor_mismatch"):
        await client.export_checkpoint()


async def test_rotation_to_an_epoch_the_environment_never_declared_is_rejected(
    collector: tuple[AuditCollectorServer, SigningAuditBackend, Path, Path],
) -> None:
    server, client, _, _ = collector
    await client.write(_event("evt-before-pending-rotation"))

    with pytest.raises(AuditKeyRotationRefusedError, match="AGENTGUARD_AUDIT_KEYS"):
        await server.rotate_key("undeclared-key", b"undeclared-secret-0123456789abcdef")
