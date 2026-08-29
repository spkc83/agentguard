"""Adversarial tests for signed authoritative registry persistence."""

from __future__ import annotations

import asyncio
import fcntl
import json
import multiprocessing
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import pytest

from agentguard.core import (
    AgentRegistryControlPlane,
    AppendOnlyAuditLog,
    ControlPlanePrincipal,
    FileAuditBackend,
    RegisterAgentCommand,
    RegistryError,
    RegistryFailure,
    RegistryOperationState,
    RoleGrantPolicy,
    SignedFileAuthoritativeAgentRegistry,
)
from agentguard.core.registry_state import _bind_registry_control_plane

if TYPE_CHECKING:
    from agentguard.models import AuditEvent

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
KEY = b"registry-test-signing-key-material-32-bytes"
pytestmark = pytest.mark.usefixtures("_set_audit_key")


class _Authenticator:
    async def authenticate(self, _credential: object) -> ControlPlanePrincipal:
        return ControlPlanePrincipal(
            principal_id="admin",
            capabilities=("registry:agent:register",),
            method="test",
            authority="tests",
            credential_digest="a" * 64,
            issued_at=NOW - timedelta(minutes=1),
            not_before=NOW - timedelta(minutes=1),
            authenticated_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )


def _audit(tmp_path: Path) -> AppendOnlyAuditLog:
    return AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))


async def _store(
    tmp_path: Path,
    audit: AppendOnlyAuditLog,
    *,
    key: bytes = KEY,
    key_id: str = "registry-key",
) -> SignedFileAuthoritativeAgentRegistry:
    trusted_directory = tmp_path / "trusted"
    trusted_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return await SignedFileAuthoritativeAgentRegistry.open(
        tmp_path / "registry",
        trusted_checkpoint_path=trusted_directory / "registry-1.checkpoint",
        registry_id="registry-1",
        signing_key=key,
        key_id=key_id,
        audit_log=audit,
    )


def _plane(
    store: SignedFileAuthoritativeAgentRegistry,
    audit: AppendOnlyAuditLog,
) -> AgentRegistryControlPlane:
    return AgentRegistryControlPlane(
        store,
        _Authenticator(),
        audit,
        RoleGrantPolicy(),
        clock=lambda: NOW,
    )


def _command(operation_id: str, agent_id: str) -> RegisterAgentCommand:
    return RegisterAgentCommand(
        operation_id=operation_id,
        target_agent_id=agent_id,
        name=agent_id,
    )


class _ResultQueue(Protocol):
    def put(self, value: str) -> None: ...


class _MemoryAuditBackend:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> None:
        self.events.append(event)

    async def read_all(self) -> list[AuditEvent]:
        return list(self.events)


def _multiprocess_register(
    root: str,
    operation_id: str,
    agent_id: str,
    results: _ResultQueue,
) -> None:
    async def run() -> None:
        path = Path(root)
        audit = _audit(path)
        try:
            store = await _store(path, audit)
            command = _command(operation_id, agent_id).model_copy(
                update={"expected_registry_revision": 0}
            )
            await _plane(store, audit).register(command, "secret")
        except RegistryError as error:
            results.put(error.failure.value)
        else:
            results.put("committed")

    asyncio.run(run())


async def test_signed_store_round_trip_and_restart(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    registered = await _plane(store, audit).register(_command("op-1", "agent-1"), "secret")

    reopened = await _store(tmp_path, audit)

    assert await reopened.resolve("agent-1") == registered
    assert (await reopened.snapshot()).registry_revision == 1
    state = json.loads((tmp_path / "registry" / "registry-state.json").read_text())
    assert state["schema_version"] == 1
    assert state["key_id"] == "registry-key"
    assert state["last_committed_audit_binding"]["event_id"]


async def test_store_rejects_audit_without_durable_checkpoints_before_creation(
    tmp_path: Path,
) -> None:
    audit = AppendOnlyAuditLog(_MemoryAuditBackend())

    with pytest.raises(RegistryError) as rejected:
        await _store(tmp_path, audit)

    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED
    assert not (tmp_path / "registry").exists()


async def test_wrong_key_key_id_and_modified_state_fail_closed(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    await _store(tmp_path, audit)

    for key, key_id in ((b"x" * 32, "registry-key"), (KEY, "other-key")):
        with pytest.raises(RegistryError) as rejected:
            await _store(tmp_path, audit, key=key, key_id=key_id)
        assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED

    path = tmp_path / "registry" / "registry-state.json"
    original = path.read_bytes()
    for forged in (original[:-3], original.replace(b'"store_revision":0', b'"store_revision":9')):
        path.write_bytes(forged)
        with pytest.raises(RegistryError) as rejected:
            await _store(tmp_path, audit)
        assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED
        path.write_bytes(original)

    path.write_bytes(b" " + original)
    with pytest.raises(RegistryError) as noncanonical:
        await _store(tmp_path, audit)
    assert noncanonical.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_fifo_and_oversized_state_fail_before_reading(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    await _store(tmp_path, audit)
    state = tmp_path / "registry" / "registry-state.json"

    state.unlink()
    os.mkfifo(state, mode=0o600)
    with pytest.raises(RegistryError) as fifo:
        await asyncio.wait_for(_store(tmp_path, audit), timeout=1)
    assert fifo.value.failure is RegistryFailure.TAMPER_DETECTED

    state.unlink()
    state.touch(mode=0o600)
    with state.open("r+b") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    with pytest.raises(RegistryError) as oversized:
        await _store(tmp_path, audit)
    assert oversized.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_insecure_mode_symlink_and_hardlink_fail_closed(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    await _store(tmp_path, audit)
    state = tmp_path / "registry" / "registry-state.json"

    state.chmod(0o644)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)
    state.chmod(0o600)

    hardlink = tmp_path / "state-copy"
    os.link(state, hardlink)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)
    hardlink.unlink()

    original = state.read_bytes()
    state.unlink()
    target = tmp_path / "target"
    target.write_bytes(original)
    state.symlink_to(target)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)


async def test_registry_checkpoint_mode_symlink_and_hardlink_fail_closed(
    tmp_path: Path,
) -> None:
    audit = _audit(tmp_path)
    await _store(tmp_path, audit)
    checkpoint = tmp_path / "registry" / ".registry-state.checkpoint"

    checkpoint.chmod(0o644)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)
    checkpoint.chmod(0o600)

    hardlink = tmp_path / "checkpoint-copy"
    os.link(checkpoint, hardlink)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)
    hardlink.unlink()

    original = checkpoint.read_bytes()
    checkpoint.unlink()
    target = tmp_path / "checkpoint-target"
    target.write_bytes(original)
    target.chmod(0o600)
    checkpoint.symlink_to(target)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)


async def test_trusted_checkpoint_mode_symlink_and_hardlink_fail_closed(
    tmp_path: Path,
) -> None:
    audit = _audit(tmp_path)
    await _store(tmp_path, audit)
    trusted = tmp_path / "trusted" / "registry-1.checkpoint"

    trusted.chmod(0o644)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)
    trusted.chmod(0o600)

    hardlink = tmp_path / "trusted-copy"
    os.link(trusted, hardlink)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)
    hardlink.unlink()

    original = trusted.read_bytes()
    trusted.unlink()
    target = tmp_path / "trusted-target"
    target.write_bytes(original)
    target.chmod(0o600)
    trusted.symlink_to(target)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)


async def test_directory_and_lock_security_are_enforced(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    store_dir = tmp_path / "registry"
    store_dir.mkdir(mode=0o755)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)

    store_dir.chmod(0o700)
    await _store(tmp_path, audit)
    lock = store_dir / ".registry-state.lock"
    lock.chmod(0o644)
    with pytest.raises(RegistryError):
        await _store(tmp_path, audit)


async def test_symlinked_parent_directory_is_rejected(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    audit = _audit(tmp_path)

    with pytest.raises(RegistryError) as rejected:
        await SignedFileAuthoritativeAgentRegistry.open(
            alias / "registry",
            trusted_checkpoint_path=tmp_path / "trusted" / "registry-1.checkpoint",
            registry_id="registry-1",
            signing_key=KEY,
            key_id="registry-key",
            audit_log=audit,
        )
    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_signed_rollback_is_rejected_against_audit_history(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    plane = _plane(store, audit)
    await plane.register(_command("op-1", "agent-1"), "secret")
    state_path = tmp_path / "registry" / "registry-state.json"
    old_state = state_path.read_bytes()
    await plane.register(_command("op-2", "agent-2"), "secret")

    state_path.write_bytes(old_state)
    with pytest.raises(RegistryError) as rejected:
        await _store(tmp_path, audit)
    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_coordinated_registry_files_rollback_is_rejected_by_trusted_checkpoint(
    tmp_path: Path,
) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    principal = await _Authenticator().authenticate("secret")
    port = _bind_registry_control_plane(store)
    await port.prepare(
        _command("op-1", "agent-1"),
        principal,
        prepared_at=NOW,
        authorize=lambda _command, _roles: None,
    )
    state_path = tmp_path / "registry" / "registry-state.json"
    checkpoint_path = tmp_path / "registry" / ".registry-state.checkpoint"
    old_state = state_path.read_bytes()
    old_checkpoint = checkpoint_path.read_bytes()
    await port.prepare(
        _command("op-2", "agent-2"),
        principal,
        prepared_at=NOW,
        authorize=lambda _command, _roles: None,
    )

    state_path.write_bytes(old_state)
    checkpoint_path.write_bytes(old_checkpoint)
    with pytest.raises(RegistryError) as rejected:
        await _store(tmp_path, audit)
    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_missing_trusted_checkpoint_fails_closed_even_at_revision_zero(
    tmp_path: Path,
) -> None:
    audit = _audit(tmp_path)
    await _store(tmp_path, audit)
    (tmp_path / "trusted" / "registry-1.checkpoint").unlink()

    with pytest.raises(RegistryError) as rejected:
        await _store(tmp_path, audit)

    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_stale_registry_checkpoint_cannot_skip_multiple_revisions(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    principal = await _Authenticator().authenticate("secret")
    port = _bind_registry_control_plane(store)
    checkpoint_path = tmp_path / "registry" / ".registry-state.checkpoint"
    old_checkpoint = checkpoint_path.read_bytes()
    for operation_id, agent_id in (("op-1", "agent-1"), ("op-2", "agent-2")):
        await port.prepare(
            _command(operation_id, agent_id),
            principal,
            prepared_at=NOW,
            authorize=lambda _command, _roles: None,
        )

    checkpoint_path.write_bytes(old_checkpoint)
    with pytest.raises(RegistryError) as rejected:
        await _store(tmp_path, audit)
    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_audit_rollback_after_rejection_is_rejected_by_anchored_head(
    tmp_path: Path,
) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    plane = _plane(store, audit)
    await plane.register(_command("op-1", "agent-1"), "secret")
    audit_dir = tmp_path / "audit"
    log_path = next(audit_dir.glob("audit-*.jsonl"))
    checkpoint_path = audit_dir / "audit-head.json"
    old_log = log_path.read_bytes()
    old_checkpoint = checkpoint_path.read_bytes()

    conflicting = _command("op-1", "different-agent")
    with pytest.raises(RegistryError) as rejected:
        await plane.register(conflicting, "secret")
    assert rejected.value.failure is RegistryFailure.OPERATION_CONFLICT

    log_path.write_bytes(old_log)
    checkpoint_path.write_bytes(old_checkpoint)
    with pytest.raises(RegistryError) as rollback:
        await _store(tmp_path, audit)
    assert rollback.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_prepared_operation_survives_restart_and_resumes(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    command = _command("op-1", "agent-1")
    principal = await _Authenticator().authenticate("secret")
    prepared = await _bind_registry_control_plane(store).prepare(
        command,
        principal,
        prepared_at=NOW,
        authorize=lambda _command, _roles: None,
    )
    assert prepared.state is RegistryOperationState.PREPARED

    reopened = await _store(tmp_path, audit)
    result = await _plane(reopened, audit).register(command, "secret")

    assert result.agent_id == "agent-1"
    assert (await reopened.snapshot()).registry_revision == 1


async def test_mismatched_control_plane_audit_cannot_bypass_store_audit(
    tmp_path: Path,
) -> None:
    authoritative_audit = _audit(tmp_path / "authoritative")
    forged_audit = _audit(tmp_path / "forged")
    store = await _store(tmp_path, authoritative_audit)
    mismatched_plane = _plane(store, forged_audit)

    with pytest.raises(RegistryError) as rejected:
        await mismatched_plane.register(_command("op-1", "agent-1"), "secret")

    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED
    assert (await store.snapshot()).registry_revision == 0
    assert (await authoritative_audit.read_verified()).events == ()


async def test_mismatched_rejection_audit_cannot_advance_store_audit_head(
    tmp_path: Path,
) -> None:
    class NoCapabilityAuthenticator:
        async def authenticate(self, credential: object) -> ControlPlanePrincipal:
            del credential
            return (await _Authenticator().authenticate("secret")).model_copy(
                update={"capabilities": ()}
            )

    authoritative_audit = _audit(tmp_path / "authoritative")
    mismatched_audit = _audit(tmp_path / "mismatched")
    store = await _store(tmp_path, authoritative_audit)
    plane = AgentRegistryControlPlane(
        store,
        NoCapabilityAuthenticator(),
        mismatched_audit,
        RoleGrantPolicy(),
        clock=lambda: NOW,
    )

    with pytest.raises(RegistryError) as rejected:
        await plane.register(_command("op-1", "agent-1"), "secret")

    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED
    assert (await store.snapshot()).registry_revision == 0
    assert (await authoritative_audit.read_verified()).events == ()


async def test_audit_written_crash_window_recovers_to_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    plane = _plane(store, audit)

    def crash_after_audited(_operation: object) -> object:
        raise RuntimeError("simulated crash")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_commit_audited_locked", crash_after_audited)
        with pytest.raises(RuntimeError, match="simulated crash"):
            await plane.register(_command("op-1", "agent-1"), "secret")

    reopened = await _store(tmp_path, audit)
    assert (await reopened.resolve("agent-1")).agent_id == "agent-1"


async def test_state_ahead_of_checkpoint_recovers_one_atomic_crash_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    original = store._write_checkpoint_locked
    crashed = False

    def fail_once(checkpoint: object) -> None:
        nonlocal crashed
        if not crashed:
            crashed = True
            raise OSError("simulated checkpoint write crash")
        original(checkpoint)  # type: ignore[arg-type]

    with monkeypatch.context() as patch:
        patch.setattr(store, "_write_checkpoint_locked", fail_once)
        with pytest.raises(OSError, match="simulated checkpoint write crash"):
            await _plane(store, audit).register(_command("op-1", "agent-1"), "secret")

    reopened = await _store(tmp_path, audit)
    result = await _plane(reopened, audit).register(_command("op-1", "agent-1"), "secret")
    assert result.agent_id == "agent-1"


async def test_initial_checkpoint_before_state_crash_is_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = SignedFileAuthoritativeAgentRegistry._write_envelope_locked
    crashed = False

    def fail_once(
        store: SignedFileAuthoritativeAgentRegistry,
        envelope: object,
    ) -> None:
        nonlocal crashed
        if not crashed:
            crashed = True
            raise OSError("simulated initial state write crash")
        original(store, envelope)  # type: ignore[arg-type]

    with monkeypatch.context() as patch:
        patch.setattr(SignedFileAuthoritativeAgentRegistry, "_write_envelope_locked", fail_once)
        with pytest.raises(OSError, match="simulated initial state write crash"):
            await _store(tmp_path, _audit(tmp_path))

    reopened = await _store(tmp_path, _audit(tmp_path))
    assert (await reopened.snapshot()).registry_revision == 0


async def test_local_checkpoint_ahead_of_trusted_head_recovers_crash_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    original = store._write_trusted_checkpoint_locked
    crashed = False

    def fail_once(checkpoint: object) -> None:
        nonlocal crashed
        if not crashed:
            crashed = True
            raise OSError("simulated trusted checkpoint write crash")
        original(checkpoint)  # type: ignore[arg-type]

    with monkeypatch.context() as patch:
        patch.setattr(store, "_write_trusted_checkpoint_locked", fail_once)
        with pytest.raises(OSError, match="simulated trusted checkpoint write crash"):
            await _plane(store, audit).register(_command("op-1", "agent-1"), "secret")

    reopened = await _store(tmp_path, audit)
    result = await _plane(reopened, audit).register(_command("op-1", "agent-1"), "secret")
    assert result.agent_id == "agent-1"


async def test_file_lock_contention_does_not_block_event_loop(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    store = await _store(tmp_path, audit)
    lock_path = tmp_path / "registry" / ".registry-state.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
    fcntl.flock(descriptor, fcntl.LOCK_EX)

    def release() -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    timer = threading.Timer(0.25, release)
    timer.start()
    heartbeats = 0
    snapshot_task = asyncio.create_task(store.snapshot())
    try:
        while not snapshot_task.done():
            await asyncio.sleep(0.01)
            heartbeats += 1
        await snapshot_task
    finally:
        timer.join(timeout=1)

    assert heartbeats >= 5


async def test_two_instances_serialize_writers_without_lost_update(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    first = await _store(tmp_path, audit)
    second = await _store(tmp_path, audit)

    results = await asyncio.gather(
        _plane(first, audit).register(_command("op-1", "agent-1"), "secret"),
        _plane(second, audit).register(_command("op-2", "agent-2"), "secret"),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, BaseException) for result in results) == 1
    assert sum(isinstance(result, RegistryError) for result in results) == 1
    reopened = await _store(tmp_path, audit)
    assert (await reopened.snapshot()).registry_revision == 1


async def test_multiprocess_writers_conflict_without_lost_update(tmp_path: Path) -> None:
    audit = _audit(tmp_path)
    await _store(tmp_path, audit)
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    processes = [
        context.Process(
            target=_multiprocess_register,
            args=(str(tmp_path), f"op-{index}", f"agent-{index}", results),
        )
        for index in (1, 2)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    outcomes = sorted(results.get(timeout=1) for _ in processes)
    assert outcomes == [RegistryFailure.REVISION_CONFLICT.value, "committed"]
    reopened = await _store(tmp_path, _audit(tmp_path))
    assert (await reopened.snapshot()).registry_revision == 1


def test_signing_key_minimum_is_enforced_before_filesystem_access(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        SignedFileAuthoritativeAgentRegistry(
            tmp_path,
            trusted_checkpoint_path=tmp_path / "trusted" / "registry-1.checkpoint",
            registry_id="registry-1",
            signing_key=b"short",
            key_id="key",
            audit_log=_audit(tmp_path),
        )


async def test_trusted_checkpoint_must_be_outside_registry_directory(tmp_path: Path) -> None:
    audit = _audit(tmp_path)

    with pytest.raises(RegistryError) as rejected:
        await SignedFileAuthoritativeAgentRegistry.open(
            tmp_path / "registry",
            trusted_checkpoint_path=tmp_path / "registry" / "trusted.json",
            registry_id="registry-1",
            signing_key=KEY,
            key_id="registry-key",
            audit_log=audit,
        )

    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED


async def test_symlinked_trusted_checkpoint_parent_is_rejected(tmp_path: Path) -> None:
    actual = tmp_path / "actual-trusted"
    actual.mkdir(mode=0o700)
    alias = tmp_path / "trusted-alias"
    alias.symlink_to(actual, target_is_directory=True)

    with pytest.raises(RegistryError) as rejected:
        await SignedFileAuthoritativeAgentRegistry.open(
            tmp_path / "registry",
            trusted_checkpoint_path=alias / "registry-1.checkpoint",
            registry_id="registry-1",
            signing_key=KEY,
            key_id="registry-key",
            audit_log=_audit(tmp_path),
        )

    assert rejected.value.failure is RegistryFailure.TAMPER_DETECTED
