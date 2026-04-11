"""Tests for agentguard.core.audit — immutable HMAC-chained audit log."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 — used in fixture type hints resolved at runtime

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.exceptions import AuditKeyMissingError, AuditTamperDetectedError
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext


def _make_event(event_id: str = "evt-001", agent_id: str = "a") -> AuditEvent:
    """Helper to create a minimal AuditEvent for testing."""
    identity = AgentIdentity(agent_id=agent_id, name="Test", roles=["readonly"])
    ctx = PermissionContext(
        agent=identity, requested_action="tool:test", resource="res", granted=True
    )
    return AuditEvent(
        event_id=event_id,
        timestamp=datetime(2026, 4, 10, 12, 0, 0, tzinfo=UTC),
        agent_id=agent_id,
        action="tool:test",
        resource="res",
        permission_context=ctx,
        result="allowed",
        duration_ms=1.0,
        trace_id="trace-001",
    )


class TestFileAuditBackend:
    """Tests for the JSONL file-based audit storage."""

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_creates_file(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        event = _make_event()
        await backend.append(event)

        files = list(tmp_audit_dir.glob("*.jsonl"))
        assert len(files) == 1

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_and_read_back(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        event = _make_event()
        await backend.append(event)

        events = await backend.read_all()
        assert len(events) == 1
        assert events[0].event_id == "evt-001"

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_multiple(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        for i in range(5):
            await backend.append(_make_event(event_id=f"evt-{i:03d}"))

        events = await backend.read_all()
        assert len(events) == 5


class TestAppendOnlyAuditLog:
    """Tests for the HMAC-chained audit log."""

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_write_sets_hashes(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        event = _make_event()
        written = await log.write(event)

        assert written.event_hash != ""
        assert written.prev_hash == ""  # First event has no predecessor

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_chain_links(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        e1 = await log.write(_make_event(event_id="evt-001"))
        e2 = await log.write(_make_event(event_id="evt-002"))

        assert e2.prev_hash == e1.event_hash
        assert e2.event_hash != e1.event_hash

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_verify_chain_passes(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        for i in range(10):
            await log.write(_make_event(event_id=f"evt-{i:03d}"))

        result = await log.verify_chain()
        assert result.valid is True
        assert result.event_count == 10

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_verify_detects_tampering(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        for i in range(5):
            await log.write(_make_event(event_id=f"evt-{i:03d}"))

        # Tamper with the log file: modify event at index 2
        log_files = list(tmp_audit_dir.glob("*.jsonl"))
        assert len(log_files) == 1
        lines = log_files[0].read_text().strip().split("\n")
        tampered = json.loads(lines[2])
        tampered["action"] = "tool:HACKED"
        lines[2] = json.dumps(tampered)
        log_files[0].write_text("\n".join(lines) + "\n")

        with pytest.raises(AuditTamperDetectedError) as exc_info:
            await log.verify_chain()
        assert exc_info.value.event_index == 2

    async def test_missing_key_raises(
        self, tmp_audit_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without AGENTGUARD_AUDIT_KEY, constructing the log should fail."""
        monkeypatch.delenv("AGENTGUARD_AUDIT_KEY", raising=False)
        with pytest.raises(AuditKeyMissingError):
            AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_empty_log_verifies(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        result = await log.verify_chain()
        assert result.valid is True
        assert result.event_count == 0
