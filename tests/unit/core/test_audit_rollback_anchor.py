"""Off-host rollback anchor: witness export, verification, and collector gating."""

from __future__ import annotations

import asyncio
import shutil
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 -- pytest resolves fixture annotations at runtime

import pytest
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.core.audit import AppendOnlyAuditLog, AuditCheckpoint, FileAuditBackend
from agentguard.core.audit_collector import AuditCollectorServer, SigningAuditBackend
from agentguard.exceptions import AuditCollectorOwnershipError, AuditRollbackDetectedError
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext

runner = CliRunner()

_AUDIT_KEY = "anchor-test-key-0123456789abcdef0123456789"


def _event(event_id: str) -> AuditEvent:
    identity = AgentIdentity(agent_id="anchor-client", name="Anchor client", roles=[])
    permission = PermissionContext(
        agent=identity,
        requested_action="tool:test",
        resource="resource",
        granted=True,
    )
    return AuditEvent(
        event_id=event_id,
        timestamp=datetime(2026, 8, 28, tzinfo=UTC),
        agent_id=identity.agent_id,
        action="tool:test",
        resource="resource",
        permission_context=permission,
        result="allowed",
        duration_ms=1.0,
        trace_id=f"trace-{event_id}",
    )


async def _append(directory: Path, count: int, *, prefix: str) -> AuditCheckpoint:
    log = AppendOnlyAuditLog(FileAuditBackend(directory))
    for index in range(count):
        await log.write(_event(f"{prefix}-{index}"))
    checkpoint = await log.export_checkpoint()
    assert checkpoint is not None
    return checkpoint


@pytest.fixture
def _anchor_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _AUDIT_KEY)


@pytest.mark.usefixtures("_anchor_key")
def test_export_checkpoint_writes_the_signed_head_to_stdout(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    committed = asyncio.run(_append(directory, 2, prefix="stdout"))

    result = runner.invoke(app, ["audit", "export-checkpoint", "--audit-dir", str(directory)])

    assert result.exit_code == 0
    assert AuditCheckpoint.model_validate_json(result.output.strip()) == committed


@pytest.mark.usefixtures("_anchor_key")
def test_export_checkpoint_writes_an_owner_only_witness_file(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    witness = tmp_path / "offhost" / "audit-head.json"
    committed = asyncio.run(_append(directory, 2, prefix="file"))

    result = runner.invoke(
        app,
        [
            "audit",
            "export-checkpoint",
            "--audit-dir",
            str(directory),
            "--output",
            str(witness),
        ],
    )

    assert result.exit_code == 0
    assert AuditCheckpoint.model_validate_json(witness.read_text(encoding="utf-8")) == committed
    assert witness.stat().st_mode & 0o777 == 0o600


@pytest.mark.usefixtures("_anchor_key")
def test_export_checkpoint_refuses_to_roll_the_witness_back(tmp_path: Path) -> None:
    """Re-exporting from a rolled-back copy of the same chain must not rewind."""

    directory = tmp_path / "audit"
    snapshot = tmp_path / "snapshot"
    witness = tmp_path / "offhost" / "audit-head.json"
    asyncio.run(_append(directory, 1, prefix="rewind"))
    shutil.copytree(directory, snapshot)
    asyncio.run(_append(directory, 2, prefix="rewind-more"))
    export = ["audit", "export-checkpoint", "--output", str(witness), "--audit-dir"]
    assert runner.invoke(app, [*export, str(directory)]).exit_code == 0
    original = witness.read_text(encoding="utf-8")
    shutil.rmtree(directory)
    shutil.copytree(snapshot, directory)

    result = runner.invoke(app, [*export, str(directory)])

    assert result.exit_code == 1
    assert "rollback" in result.output.lower()
    assert witness.read_text(encoding="utf-8") == original


@pytest.mark.usefixtures("_anchor_key")
def test_export_checkpoint_is_idempotent_for_an_unchanged_head(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    witness = tmp_path / "offhost" / "audit-head.json"
    asyncio.run(_append(directory, 2, prefix="idempotent"))
    export = ["audit", "export-checkpoint", "--audit-dir", str(directory), "--output", str(witness)]
    assert runner.invoke(app, export).exit_code == 0

    assert runner.invoke(app, export).exit_code == 0


@pytest.mark.usefixtures("_anchor_key")
def test_export_checkpoint_fails_on_an_empty_log(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    directory.mkdir()

    result = runner.invoke(app, ["audit", "export-checkpoint", "--audit-dir", str(directory)])

    assert result.exit_code == 1
    assert "no signed audit head" in result.output.lower()


@pytest.mark.usefixtures("_anchor_key")
def test_verify_accepts_a_log_that_extends_the_trusted_checkpoint(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    witness = tmp_path / "offhost" / "audit-head.json"
    asyncio.run(_append(directory, 1, prefix="extend"))
    assert (
        runner.invoke(
            app,
            [
                "audit",
                "export-checkpoint",
                "--audit-dir",
                str(directory),
                "--output",
                str(witness),
            ],
        ).exit_code
        == 0
    )
    asyncio.run(_append(directory, 2, prefix="extend-more"))

    result = runner.invoke(
        app,
        ["audit", "verify", "--log-dir", str(directory), "--trusted-checkpoint", str(witness)],
    )

    assert result.exit_code == 0
    assert "verified" in result.output.lower()


@pytest.mark.usefixtures("_anchor_key")
def test_verify_detects_a_log_rolled_back_behind_the_trusted_checkpoint(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    witness = tmp_path / "offhost" / "audit-head.json"
    asyncio.run(_append(directory, 3, prefix="rollback"))
    assert (
        runner.invoke(
            app,
            [
                "audit",
                "export-checkpoint",
                "--audit-dir",
                str(directory),
                "--output",
                str(witness),
            ],
        ).exit_code
        == 0
    )
    # A root attacker restores the whole log directory, including the local
    # head checkpoint. Only the off-host witness survives.
    shutil.rmtree(directory)
    asyncio.run(_append(directory, 1, prefix="rollback-replacement"))

    result = runner.invoke(
        app,
        ["audit", "verify", "--log-dir", str(directory), "--trusted-checkpoint", str(witness)],
    )

    assert result.exit_code == 1
    assert "rollback" in result.output.lower()


@pytest.mark.usefixtures("_anchor_key")
def test_verify_detects_a_completely_deleted_log_against_the_witness(tmp_path: Path) -> None:
    """Deleting the whole directory leaves zero events; the witness still convicts."""

    directory = tmp_path / "audit"
    witness = tmp_path / "offhost" / "audit-head.json"
    asyncio.run(_append(directory, 3, prefix="erased"))
    assert (
        runner.invoke(
            app,
            [
                "audit",
                "export-checkpoint",
                "--audit-dir",
                str(directory),
                "--output",
                str(witness),
            ],
        ).exit_code
        == 0
    )
    shutil.rmtree(directory)

    result = runner.invoke(
        app,
        ["audit", "verify", "--log-dir", str(directory), "--trusted-checkpoint", str(witness)],
    )

    assert result.exit_code == 1
    assert "rollback" in result.output.lower()


@pytest.mark.usefixtures("_anchor_key")
def test_export_refuses_to_rebind_a_witness_to_a_forked_chain(tmp_path: Path) -> None:
    """A higher head on a different chain must not be able to replace the witness."""

    original = tmp_path / "original"
    fork = tmp_path / "fork"
    witness = tmp_path / "offhost" / "audit-head.json"
    asyncio.run(_append(original, 2, prefix="original"))
    asyncio.run(_append(fork, 5, prefix="fork"))
    export = ["audit", "export-checkpoint", "--output", str(witness), "--audit-dir"]
    assert runner.invoke(app, [*export, str(original)]).exit_code == 0
    before = witness.read_text(encoding="utf-8")

    result = runner.invoke(app, [*export, str(fork)])

    assert result.exit_code == 1
    assert "chain mismatch" in result.output.lower()
    assert witness.read_text(encoding="utf-8") == before


@pytest.mark.usefixtures("_anchor_key")
def test_export_refuses_an_unauthentic_existing_witness(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    witness = tmp_path / "offhost" / "audit-head.json"
    asyncio.run(_append(directory, 1, prefix="unsigned"))
    witness.parent.mkdir(parents=True)
    witness.write_text(
        AuditCheckpoint(
            chain_id="forged-chain",
            head_sequence=9_000,
            head_event_hash="f" * 64,
            event_count=9_000,
            signing_key_id="forged-key",
            signed_at=datetime(2026, 8, 28, tzinfo=UTC),
            signature="0" * 64,
        ).model_dump_json(),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "audit",
            "export-checkpoint",
            "--audit-dir",
            str(directory),
            "--output",
            str(witness),
        ],
    )

    assert result.exit_code == 1
    assert "not authentic" in result.output.lower()


async def test_collector_refuses_to_start_when_a_configured_witness_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unmounted or deleted witness must not be silently re-bootstrapped."""

    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _AUDIT_KEY)
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"
    witness = tmp_path / "offhost" / "audit-head.json"

    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        trusted_checkpoint_path=witness,
    )
    await server.start()
    try:
        await SigningAuditBackend(socket_path).write(_event("evt-witness-lost"))
    finally:
        await server.close()
    witness.unlink()

    replacement = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        trusted_checkpoint_path=witness,
    )
    with pytest.raises(AuditCollectorOwnershipError, match="absent"):
        await replacement.start()


@pytest.mark.usefixtures("_anchor_key")
def test_verify_reports_a_missing_trusted_checkpoint_file(tmp_path: Path) -> None:
    directory = tmp_path / "audit"
    asyncio.run(_append(directory, 1, prefix="missing-witness"))

    result = runner.invoke(
        app,
        [
            "audit",
            "verify",
            "--log-dir",
            str(directory),
            "--trusted-checkpoint",
            str(tmp_path / "absent.json"),
        ],
    )

    assert result.exit_code == 1


def test_rolled_back_log_is_detected_against_the_surviving_witness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _AUDIT_KEY)
    directory = tmp_path / "audit"
    trusted = asyncio.run(_append(directory, 3, prefix="library"))
    shutil.rmtree(directory)
    asyncio.run(_append(directory, 1, prefix="library-replacement"))

    log = AppendOnlyAuditLog(FileAuditBackend(directory), trusted_checkpoint=trusted)

    with pytest.raises(AuditRollbackDetectedError) as failure:
        asyncio.run(log.verify_chain())
    assert failure.value.trusted_head_sequence == 3
    assert failure.value.local_head_sequence == 1


async def test_collector_creates_the_witness_when_it_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _AUDIT_KEY)
    audit_directory = tmp_path / "audit"
    witness = tmp_path / "offhost" / "audit-head.json"
    server = AuditCollectorServer(
        socket_path=tmp_path / "run" / "collector.sock",
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=tmp_path / "anchor" / "state.json",
        trusted_checkpoint_path=witness,
    )
    await server.start()
    try:
        await SigningAuditBackend(tmp_path / "run" / "collector.sock").write(_event("evt-witness"))
    finally:
        await server.close()

    committed = AuditCheckpoint.model_validate_json(witness.read_text(encoding="utf-8"))
    assert committed.head_sequence == 1
    assert witness.stat().st_mode & 0o777 == 0o600


async def test_collector_advances_the_witness_after_every_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _AUDIT_KEY)
    socket_path = tmp_path / "run" / "collector.sock"
    witness = tmp_path / "offhost" / "audit-head.json"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "state.json",
        trusted_checkpoint_path=witness,
    )
    await server.start()
    heads: list[int] = []
    try:
        client = SigningAuditBackend(socket_path)
        for index in range(3):
            await client.write(_event(f"evt-advance-{index}"))
            heads.append(
                AuditCheckpoint.model_validate_json(
                    witness.read_text(encoding="utf-8")
                ).head_sequence
            )
    finally:
        await server.close()

    assert heads == [1, 2, 3]


async def test_collector_starts_when_the_witness_is_behind_local_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _AUDIT_KEY)
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"
    witness = tmp_path / "offhost" / "audit-head.json"

    first = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        trusted_checkpoint_path=witness,
    )
    await first.start()
    try:
        await SigningAuditBackend(socket_path).write(_event("evt-behind-1"))
    finally:
        await first.close()
    # The log grows while the witness stays where the last export left it.
    await _append(audit_directory, 2, prefix="offline-growth")

    replacement = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        trusted_checkpoint_path=witness,
    )
    await replacement.start()
    try:
        advanced = AuditCheckpoint.model_validate_json(witness.read_text(encoding="utf-8"))
    finally:
        await replacement.close()

    assert advanced.head_sequence == 3


async def test_collector_refuses_to_start_behind_a_surviving_witness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _AUDIT_KEY)
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"
    witness = tmp_path / "offhost" / "audit-head.json"

    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        trusted_checkpoint_path=witness,
    )
    await server.start()
    try:
        client = SigningAuditBackend(socket_path)
        await client.write(_event("evt-rollback-1"))
        rolled_back_audit = tmp_path / "snapshot-audit"
        rolled_back_state = tmp_path / "snapshot-state.json"
        shutil.copytree(audit_directory, rolled_back_audit)
        rolled_back_state.write_bytes(state_path.read_bytes())
        await client.write(_event("evt-rollback-2"))
        await client.write(_event("evt-rollback-3"))
    finally:
        await server.close()

    # The attacker restores both same-host failure domains; the off-host
    # witness still commits to head sequence 3.
    shutil.rmtree(audit_directory)
    shutil.copytree(rolled_back_audit, audit_directory)
    state_path.write_bytes(rolled_back_state.read_bytes())

    replacement = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        trusted_checkpoint_path=witness,
    )
    with pytest.raises(AuditRollbackDetectedError):
        await replacement.start()


@pytest.mark.usefixtures("_anchor_key")
def test_collector_rejects_a_witness_inside_the_audit_directory(tmp_path: Path) -> None:
    audit_directory = tmp_path / "audit"
    with pytest.raises(ValueError, match="outside the audit log directory"):
        AuditCollectorServer(
            socket_path=tmp_path / "run" / "collector.sock",
            audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
            state_path=tmp_path / "anchor" / "state.json",
            trusted_checkpoint_path=audit_directory / "witness.json",
        )


@pytest.mark.usefixtures("_anchor_key")
def test_collector_rejects_a_witness_inside_the_state_directory(tmp_path: Path) -> None:
    state_path = tmp_path / "anchor" / "state.json"
    with pytest.raises(ValueError, match="outside the collector state directory"):
        AuditCollectorServer(
            socket_path=tmp_path / "run" / "collector.sock",
            audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
            state_path=state_path,
            trusted_checkpoint_path=state_path.parent / "witness.json",
        )
