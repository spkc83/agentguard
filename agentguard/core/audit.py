"""Immutable, HMAC-chained append-only audit log.

Design principle: log-first, act-second. If the audit write fails,
the action MUST be blocked. The HMAC chain provides tamper evidence —
modifying any past event breaks the chain, detectable via verify_chain().

The audit key is read from the AGENTGUARD_AUDIT_KEY environment variable.
This is required — there is no default key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import date
from pathlib import Path  # noqa: TC003 — used at runtime in FileAuditBackend
from typing import Protocol, runtime_checkable

import structlog
from pydantic import BaseModel

from agentguard.exceptions import AuditKeyMissingError, AuditTamperDetectedError
from agentguard.models import AuditEvent

logger = structlog.get_logger()


class ChainVerificationResult(BaseModel):
    """Result of verifying the HMAC chain integrity."""

    valid: bool
    event_count: int
    error_index: int | None = None
    error_event_id: str | None = None


@runtime_checkable
class AuditBackend(Protocol):
    """Protocol for pluggable audit log storage backends."""

    async def append(self, event: AuditEvent) -> None: ...
    async def read_all(self) -> list[AuditEvent]: ...


class FileAuditBackend:
    """JSONL file-based audit storage.

    Events are written one-per-line to a date-stamped JSONL file
    in the configured directory. Files are named audit-YYYY-MM-DD.jsonl.

    Args:
        directory: Path to the directory where audit log files are stored.
    """

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._directory.mkdir(parents=True, exist_ok=True)

    def _log_file(self) -> Path:
        return self._directory / f"audit-{date.today().isoformat()}.jsonl"

    async def append(self, event: AuditEvent) -> None:
        """Append event as a JSON line to today's audit file."""
        line = event.model_dump_json() + "\n"
        log_file = self._log_file()
        with open(log_file, "a") as f:
            f.write(line)
        logger.debug("audit_event_written", event_id=event.event_id, file=str(log_file))

    async def read_all(self) -> list[AuditEvent]:
        """Read all events from all JSONL files in the directory, sorted by filename."""
        events: list[AuditEvent] = []
        for log_file in sorted(self._directory.glob("audit-*.jsonl")):
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(AuditEvent.model_validate_json(line))
        return events


class AppendOnlyAuditLog:
    """HMAC-chained immutable audit log.

    Each event's hash covers its content + the hash of the previous event,
    forming a tamper-evident chain. Modifying any event invalidates all
    subsequent hashes.

    Args:
        backend: Storage backend (default: FileAuditBackend).

    Raises:
        AuditKeyMissingError: If AGENTGUARD_AUDIT_KEY env var is not set.
    """

    def __init__(self, backend: AuditBackend) -> None:
        key = os.environ.get("AGENTGUARD_AUDIT_KEY", "")
        if not key:
            raise AuditKeyMissingError()
        self._key = key.encode("utf-8")
        self._backend = backend
        self._prev_hash = ""

    def _compute_hash(self, event: AuditEvent) -> str:
        """Compute HMAC-SHA256 over event content + prev_hash."""
        data = event.model_copy(update={"event_hash": "", "prev_hash": event.prev_hash})
        payload = data.model_dump_json().encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    async def write(self, event: AuditEvent) -> AuditEvent:
        """Write an event to the audit log with HMAC chain linking.

        Args:
            event: The audit event to write. event_hash and prev_hash
                   will be set automatically.

        Returns:
            The event with event_hash and prev_hash populated.
        """
        chained = event.model_copy(update={"prev_hash": self._prev_hash})
        event_hash = self._compute_hash(chained)
        chained = chained.model_copy(update={"event_hash": event_hash})

        await self._backend.append(chained)
        self._prev_hash = event_hash

        logger.info(
            "audit_event_logged",
            event_id=chained.event_id,
            action=chained.action,
            result=chained.result,
        )
        return chained

    async def verify_chain(self) -> ChainVerificationResult:
        """Verify the HMAC chain integrity of the entire audit log.

        Returns:
            ChainVerificationResult with valid=True if chain is intact.

        Raises:
            AuditTamperDetectedError: If tampering is detected.
        """
        events = await self._backend.read_all()
        if not events:
            return ChainVerificationResult(valid=True, event_count=0)

        prev_hash = ""
        for i, event in enumerate(events):
            check_event = event.model_copy(update={"event_hash": "", "prev_hash": prev_hash})
            expected_hash = self._compute_hash(check_event)

            if event.prev_hash != prev_hash:
                raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)

            if event.event_hash != expected_hash:
                raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)

            prev_hash = event.event_hash

        return ChainVerificationResult(valid=True, event_count=len(events))
