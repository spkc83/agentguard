"""Bounded Unix-socket audit collector with out-of-process key ownership."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import hmac
import json
import os
import socket
import stat
import struct
import tempfile
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentguard.core.audit import (
    AppendOnlyAuditLog,
    AuditCheckpoint,
    AuditKeyEpoch,
    AuditKeyring,
    ChainVerificationResult,
    FileAuditBackend,
    VerifiedAuditSnapshot,
)
from agentguard.exceptions import (
    AuditCollectorOwnershipError,
    AuditCollectorProtocolError,
    AuditCollectorUnavailableError,
    AuditError,
    AuditKeyRotationRefusedError,
    AuditRollbackDetectedError,
)
from agentguard.models import AuditEvent

if TYPE_CHECKING:
    from pathlib import Path

logger = structlog.get_logger()

PROTOCOL_VERSION = 1
DEFAULT_MAX_FRAME_BYTES = 1_048_576
_STATE_DOMAIN = b"agentguard.audit.collector-state.v1\0"
_INTEGRITY_FIELDS = ("event_hash", "prev_hash", "sequence", "key_id", "chain_id")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _CollectorRequest(_StrictModel):
    protocol_version: Literal[1] = 1
    request_id: str = Field(min_length=1, max_length=64)
    operation: Literal["append", "verify", "checkpoint", "snapshot_open", "snapshot_page"]
    payload: dict[str, Any] = Field(default_factory=dict)


class _CollectorFault(_StrictModel):
    code: str
    detail: str


class _CollectorResponse(_StrictModel):
    protocol_version: Literal[1] = 1
    request_id: str
    ok: bool
    result: dict[str, Any] = Field(default_factory=dict)
    error: _CollectorFault | None = None


class _EmptyPayload(_StrictModel):
    pass


class _AppendPayload(_StrictModel):
    event: AuditEvent


class _SnapshotOpenPayload(_StrictModel):
    require_checkpoint: bool = False


class _SnapshotPagePayload(_StrictModel):
    token: str = Field(min_length=1, max_length=64)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)


class CollectorState(_StrictModel):
    """Signed external commitment to the audit head and immutable key epochs."""

    state_schema_version: Literal[1] = 1
    checkpoint: AuditCheckpoint | None = None
    key_epochs: tuple[AuditKeyEpoch, ...]
    signing_key_id: str
    signature: str = ""


@dataclass(frozen=True, slots=True)
class _IndexedEvent:
    """Everything dedup needs about a committed event, without retaining it."""

    sequence: int | None
    fingerprint_digest: str


@dataclass(frozen=True)
class _Snapshot:
    events: tuple[AuditEvent, ...]
    verification: ChainVerificationResult
    created_at: float
    total_bytes: int


def _canonical_json(model: BaseModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _frame(payload: bytes, maximum: int) -> bytes:
    if len(payload) > maximum:
        raise AuditCollectorProtocolError("frame_too_large", str(len(payload)))
    return struct.pack(">I", len(payload)) + payload


async def _read_frame(
    reader: asyncio.StreamReader,
    *,
    maximum: int,
    timeout: float,
) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(4), timeout)
    (size,) = struct.unpack(">I", header)
    if size > maximum:
        raise AuditCollectorProtocolError("frame_too_large", str(size))
    return await asyncio.wait_for(reader.readexactly(size), timeout)


def _unsigned_event(event: AuditEvent) -> AuditEvent:
    return event.model_copy(
        update={
            "event_hash": "",
            "prev_hash": "",
            "sequence": None,
            "key_id": "",
            "chain_id": "",
            "hash_schema_version": 8,
        }
    )


def _event_fingerprint(event: AuditEvent) -> bytes:
    return _canonical_json(_unsigned_event(event))


def _event_fingerprint_digest(event: AuditEvent) -> str:
    """Constant-size stand-in for the unsigned content of a committed event."""

    return hashlib.sha256(_event_fingerprint(event)).hexdigest()


class SigningAuditBackend:
    """Keyless application-side audit sink backed by a UDS collector."""

    def __init__(
        self,
        socket_path: Path,
        *,
        request_timeout: float = 2.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_snapshot_events: int = 100_000,
        max_snapshot_bytes: int = 64 * 1024 * 1024,
        page_size: int = 256,
    ) -> None:
        self._socket_path = socket_path
        self._request_timeout = request_timeout
        self._max_frame_bytes = max_frame_bytes
        self._max_snapshot_events = max_snapshot_events
        self._max_snapshot_bytes = max_snapshot_bytes
        self._page_size = page_size

    @property
    def socket_path(self) -> Path:
        """Collector endpoint; exposed for diagnostics without exposing key material."""

        return self._socket_path

    @property
    def supports_durable_checkpoints(self) -> bool:
        """Collector snapshots are checkpoint-capable by protocol contract."""

        return True

    async def _rpc(self, operation: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = _CollectorRequest(
            request_id=uuid.uuid4().hex,
            operation=operation,  # type: ignore[arg-type]
            payload=payload,
        )
        encoded = _canonical_json(request)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self._socket_path),
                self._request_timeout,
            )
        except (OSError, TimeoutError) as exc:
            raise AuditCollectorUnavailableError(str(exc)) from exc
        try:
            writer.write(_frame(encoded, self._max_frame_bytes))
            await asyncio.wait_for(writer.drain(), self._request_timeout)
            raw = await _read_frame(
                reader,
                maximum=self._max_frame_bytes,
                timeout=self._request_timeout,
            )
        except AuditCollectorProtocolError:
            raise
        except (OSError, TimeoutError, asyncio.IncompleteReadError) as exc:
            raise AuditCollectorUnavailableError(str(exc)) from exc
        finally:
            writer.close()
            await writer.wait_closed()
        try:
            response = _CollectorResponse.model_validate_json(raw)
        except ValidationError as exc:
            raise AuditCollectorProtocolError("malformed_response", str(exc)) from exc
        if response.request_id != request.request_id:
            raise AuditCollectorProtocolError("request_id_mismatch", response.request_id)
        if not response.ok:
            fault = response.error or _CollectorFault(code="collector_error", detail="")
            raise AuditCollectorProtocolError(fault.code, fault.detail)
        return response.result

    async def write(self, event: AuditEvent) -> AuditEvent:
        if any(getattr(event, field) for field in _INTEGRITY_FIELDS):
            raise ValueError("audit chain integrity fields are assigned by the audit sink")
        result = await self._rpc("append", {"event": event.model_dump(mode="json")})
        return AuditEvent.model_validate(result["event"])

    async def write_once(self, event: AuditEvent) -> AuditEvent:
        """Collector appends are already idempotent by stable event ID."""

        return await self.write(event)

    async def verify_chain(self) -> ChainVerificationResult:
        result = await self._rpc("verify", {})
        return ChainVerificationResult.model_validate(result["verification"])

    async def export_checkpoint(self) -> AuditCheckpoint | None:
        result = await self._rpc("checkpoint", {})
        checkpoint = result.get("checkpoint")
        return AuditCheckpoint.model_validate(checkpoint) if checkpoint is not None else None

    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot:
        opened = await self._rpc("snapshot_open", {"require_checkpoint": require_checkpoint})
        token = opened["token"]
        total = opened["total"]
        total_bytes = opened["total_bytes"]
        if (
            not isinstance(token, str)
            or type(total) is not int
            or type(total_bytes) is not int
            or total < 0
            or total_bytes < 0
        ):
            raise AuditCollectorProtocolError("malformed_snapshot", "invalid totals")
        if total > self._max_snapshot_events or total_bytes > self._max_snapshot_bytes:
            raise AuditCollectorProtocolError("snapshot_too_large", str(total))
        events: list[AuditEvent] = []
        offset = 0
        consumed_bytes = 0
        while offset < total:
            page = await self._rpc(
                "snapshot_page",
                {"token": token, "offset": offset, "limit": self._page_size},
            )
            if page.get("total") != total or page.get("offset") != offset:
                raise AuditCollectorProtocolError("snapshot_changed", token)
            batch = [AuditEvent.model_validate(item) for item in page["events"]]
            if not batch:
                raise AuditCollectorProtocolError("empty_snapshot_page", token)
            if offset + len(batch) > total:
                raise AuditCollectorProtocolError("snapshot_page_overshoot", token)
            consumed_bytes += sum(len(event.model_dump_json().encode()) for event in batch)
            if consumed_bytes > total_bytes or consumed_bytes > self._max_snapshot_bytes:
                raise AuditCollectorProtocolError("snapshot_too_large", token)
            events.extend(batch)
            offset += len(batch)
            if len(events) > self._max_snapshot_events:
                raise AuditCollectorProtocolError("snapshot_too_large", str(len(events)))
        if len(events) != total or consumed_bytes != total_bytes:
            raise AuditCollectorProtocolError("snapshot_size_mismatch", token)
        return VerifiedAuditSnapshot(
            events=tuple(events),
            verification=ChainVerificationResult.model_validate(opened["verification"]),
        )


class AuditCollectorServer:
    """Single-writer collector that sequences, signs, persists, and anchors events."""

    def __init__(
        self,
        *,
        socket_path: Path,
        audit_log: AppendOnlyAuditLog,
        state_path: Path,
        trusted_checkpoint_path: Path | None = None,
        allowed_uids: set[int] | None = None,
        adopt_existing: bool = False,
        adopt_declared_epochs: bool = False,
        request_timeout: float = 2.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_connections: int = 32,
        max_operations: int = 32,
        backlog: int = 64,
        operation_timeout: float = 5.0,
        max_snapshot_events: int = 100_000,
        max_snapshot_bytes: int = 64 * 1024 * 1024,
        max_snapshots: int = 16,
        snapshot_ttl: float = 30.0,
        max_page_size: int = 512,
        max_cached_events: int = 8192,
    ) -> None:
        if not isinstance(audit_log.backend, FileAuditBackend):
            raise TypeError("collector requires FileAuditBackend")
        if max_cached_events < 1:
            raise ValueError("max_cached_events must be at least 1")
        self._socket_path = socket_path
        self._audit_log = audit_log
        self._backend = audit_log.backend
        self._state_path = state_path
        self._trusted_checkpoint_path = trusted_checkpoint_path
        self._allowed_uids = frozenset({os.getuid()} if allowed_uids is None else allowed_uids)
        self._adopt_existing = adopt_existing
        self._adopt_declared_epochs = adopt_declared_epochs
        self._request_timeout = request_timeout
        self._operation_timeout = operation_timeout
        self._max_frame_bytes = max_frame_bytes
        self._max_connections = max_connections
        self._max_operations = max_operations
        self._active_connections = 0
        self._handler_tasks: set[asyncio.Task[None]] = set()
        self._operation_tasks: set[asyncio.Task[dict[str, Any]]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._backlog = backlog
        self._max_snapshot_events = max_snapshot_events
        self._max_snapshot_bytes = max_snapshot_bytes
        self._max_snapshots = max_snapshots
        self._snapshot_ttl = snapshot_ttl
        self._max_page_size = max_page_size
        self._operation_lock = asyncio.Lock()
        self._snapshots: OrderedDict[str, _Snapshot] = OrderedDict()
        self._max_cached_events = max_cached_events
        # Dedup detection must stay complete for every event ever committed, so
        # the index keeps only a digest per event. Whole events are cached
        # separately and evicted, since they are needed solely to answer a
        # duplicate append with the exact committed record.
        self._event_index: dict[str, _IndexedEvent] = {}
        self._recent_events: OrderedDict[str, AuditEvent] = OrderedDict()
        self._state: CollectorState | None = None
        self._server: asyncio.AbstractServer | None = None
        self._owner_file: Any = None
        self._socket_owner_file: Any = None
        self._socket_identity: tuple[int, int] | None = None

        log_directory = self._backend.directory.resolve()
        try:
            state_path.resolve().relative_to(log_directory)
        except ValueError:
            pass
        else:
            raise ValueError("collector state must be stored outside the audit log directory")

        if trusted_checkpoint_path is not None:
            # A witness that shares a failure domain with the log or the state it
            # is supposed to outlive proves nothing about a rollback of either.
            witness = trusted_checkpoint_path.resolve()
            for boundary, label in (
                (log_directory, "audit log"),
                (state_path.resolve().parent, "collector state"),
            ):
                try:
                    witness.relative_to(boundary)
                except ValueError:
                    continue
                raise ValueError(
                    f"collector trusted checkpoint must be stored outside the {label} directory"
                )

    async def __aenter__(self) -> AuditCollectorServer:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def start(self) -> None:
        if self._server is not None:
            return
        self._acquire_owner_lock()
        try:
            await self._initialize_state()
            self._prepare_socket_parent()
            self._acquire_socket_lock()
            self._prepare_socket_path()
            self._server = await asyncio.start_unix_server(
                self._handle_client,
                path=self._socket_path,
                backlog=self._backlog,
            )
            socket_info = self._socket_path.lstat()
            self._socket_identity = (socket_info.st_dev, socket_info.st_ino)
            os.chmod(self._socket_path, 0o600)
        except BaseException:
            if self._server is not None:
                self._server.close()
                await self._server.wait_closed()
                self._server = None
            self._remove_owned_socket()
            self._release_socket_lock()
            self._release_owner_lock()
            raise

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        for writer in tuple(self._writers):
            writer.close()
        if self._handler_tasks:
            await asyncio.gather(*tuple(self._handler_tasks), return_exceptions=True)
        if self._operation_tasks:
            await asyncio.gather(*tuple(self._operation_tasks), return_exceptions=True)
        self._remove_owned_socket()
        self._release_socket_lock()
        self._release_owner_lock()

    def _remove_owned_socket(self) -> None:
        try:
            info = self._socket_path.lstat()
            identity = (info.st_dev, info.st_ino)
            if (
                self._socket_identity == identity
                and stat.S_ISSOCK(info.st_mode)
                and info.st_uid == os.getuid()
            ):
                self._socket_path.unlink()
        except FileNotFoundError:
            pass
        finally:
            self._socket_identity = None

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        await self._server.serve_forever()

    def _acquire_owner_lock(self) -> None:
        lock_path = self._backend.directory / ".collector-owner.lock"
        owner_file = lock_path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(owner_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            owner_file.close()
            raise AuditCollectorOwnershipError(
                f"another collector owns {self._backend.directory}"
            ) from exc
        self._owner_file = owner_file

    def _release_owner_lock(self) -> None:
        if self._owner_file is None:
            return
        fcntl.flock(self._owner_file.fileno(), fcntl.LOCK_UN)
        self._owner_file.close()
        self._owner_file = None

    def _prepare_socket_parent(self) -> None:
        parent = self._socket_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = parent.stat()
        if info.st_uid != os.getuid():
            raise AuditCollectorOwnershipError(f"socket directory not owned by uid {os.getuid()}")
        os.chmod(parent, 0o700)

    def _acquire_socket_lock(self) -> None:
        lock_path = self._socket_path.with_name(f".{self._socket_path.name}.lock")
        owner_file = lock_path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(owner_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            owner_file.close()
            raise AuditCollectorOwnershipError(
                f"another collector owns socket {self._socket_path}"
            ) from exc
        self._socket_owner_file = owner_file

    def _release_socket_lock(self) -> None:
        if self._socket_owner_file is None:
            return
        fcntl.flock(self._socket_owner_file.fileno(), fcntl.LOCK_UN)
        self._socket_owner_file.close()
        self._socket_owner_file = None

    def _prepare_socket_path(self) -> None:
        try:
            socket_info = self._socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != os.getuid():
            raise AuditCollectorOwnershipError("refusing unsafe existing socket path")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.1)
            probe.connect(str(self._socket_path))
        except (ConnectionRefusedError, FileNotFoundError):
            pass
        except OSError as exc:
            raise AuditCollectorOwnershipError("cannot prove existing socket is stale") from exc
        else:
            raise AuditCollectorOwnershipError("refusing live existing socket")
        finally:
            probe.close()
        self._socket_path.unlink()

    def _peer_allowed(self, writer: asyncio.StreamWriter) -> bool:
        transport_socket = writer.get_extra_info("socket")
        if transport_socket is None or not hasattr(socket, "SO_PEERCRED"):
            return False
        credentials = transport_socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", credentials)
        return uid in self._allowed_uids

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._active_connections >= self._max_connections:
            writer.close()
            await writer.wait_closed()
            return
        self._active_connections += 1
        current = asyncio.current_task()
        if current is not None:
            self._handler_tasks.add(current)
        self._writers.add(writer)
        try:
            await self._serve_client(reader, writer)
        finally:
            self._writers.discard(writer)
            if current is not None:
                self._handler_tasks.discard(current)
            self._active_connections -= 1

    async def _serve_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request_id = "unknown"
        try:
            if not self._peer_allowed(writer):
                raise AuditCollectorProtocolError("peer_denied", "untrusted uid")
            raw = await _read_frame(
                reader,
                maximum=self._max_frame_bytes,
                timeout=self._request_timeout,
            )
            request = _CollectorRequest.model_validate_json(raw)
            request_id = request.request_id
            if len(self._operation_tasks) >= self._max_operations:
                raise AuditCollectorProtocolError(
                    "collector_overloaded", "too many unfinished operations"
                )
            operation = asyncio.create_task(self._dispatch(request))
            self._operation_tasks.add(operation)
            operation.add_done_callback(self._operation_finished)
            try:
                result = await asyncio.wait_for(asyncio.shield(operation), self._operation_timeout)
            except TimeoutError as exc:
                raise AuditCollectorProtocolError("operation_timeout", request.operation) from exc
            response = _CollectorResponse(
                request_id=request_id,
                ok=True,
                result=result,
            )
        except AuditCollectorProtocolError as exc:
            response = _CollectorResponse(
                request_id=request_id,
                ok=False,
                error=_CollectorFault(code=exc.code, detail=exc.detail),
            )
        except (ValidationError, ValueError, KeyError, TypeError) as exc:
            response = _CollectorResponse(
                request_id=request_id,
                ok=False,
                error=_CollectorFault(code="invalid_request", detail=str(exc)),
            )
        except (TimeoutError, asyncio.IncompleteReadError):
            response = _CollectorResponse(
                request_id=request_id,
                ok=False,
                error=_CollectorFault(code="request_timeout", detail="incomplete frame"),
            )
        except AuditError as exc:
            response = _CollectorResponse(
                request_id=request_id,
                ok=False,
                error=_CollectorFault(code="audit_error", detail=str(exc)),
            )
        except Exception:
            response = _CollectorResponse(
                request_id=request_id,
                ok=False,
                error=_CollectorFault(code="internal_error", detail="collector failed closed"),
            )
        try:
            writer.write(_frame(_canonical_json(response), self._max_frame_bytes))
            await asyncio.wait_for(writer.drain(), self._request_timeout)
        except (OSError, TimeoutError, AuditCollectorProtocolError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    def _operation_finished(self, task: asyncio.Task[dict[str, Any]]) -> None:
        self._operation_tasks.discard(task)
        if not task.cancelled():
            task.exception()

    async def _dispatch(self, request: _CollectorRequest) -> dict[str, Any]:
        if request.operation == "append":
            return await self._append(_AppendPayload.model_validate(request.payload))
        if request.operation == "verify":
            _EmptyPayload.model_validate(request.payload)
            snapshot = await self._anchored_snapshot(require_checkpoint=False)
            return {"verification": snapshot.verification.model_dump(mode="json")}
        if request.operation == "checkpoint":
            _EmptyPayload.model_validate(request.payload)
            checkpoint = await self._anchored_checkpoint()
            return {
                "checkpoint": checkpoint.model_dump(mode="json") if checkpoint is not None else None
            }
        if request.operation == "snapshot_open":
            return await self._open_snapshot(_SnapshotOpenPayload.model_validate(request.payload))
        return self._page_snapshot(_SnapshotPagePayload.model_validate(request.payload))

    async def _append(self, payload: _AppendPayload) -> dict[str, Any]:
        event = payload.event
        if any(getattr(event, field) for field in _INTEGRITY_FIELDS):
            raise AuditCollectorProtocolError(
                "integrity_fields_forbidden", "collector assigns chain fields"
            )
        async with self._operation_lock:
            indexed = self._event_index.get(event.event_id)
            if indexed is not None:
                if not hmac.compare_digest(
                    indexed.fingerprint_digest, _event_fingerprint_digest(event)
                ):
                    raise AuditCollectorProtocolError("event_id_conflict", event.event_id)
                committed = await self._committed_event(event.event_id, indexed)
                await self._anchor_current_head()
            else:
                committed = await self._audit_log.write(event)
                self._remember(committed)
                await self._anchor_current_head()
        return {"event": committed.model_dump(mode="json")}

    def _remember(self, event: AuditEvent) -> None:
        """Index one verified committed event and cache it within the bound."""

        self._event_index[event.event_id] = _IndexedEvent(
            sequence=event.sequence,
            fingerprint_digest=_event_fingerprint_digest(event),
        )
        self._cache(event)

    def _cache(self, event: AuditEvent) -> None:
        """Retain a whole event for duplicate replies, evicting the least recent."""

        self._recent_events.pop(event.event_id, None)
        self._recent_events[event.event_id] = event
        while len(self._recent_events) > self._max_cached_events:
            self._recent_events.popitem(last=False)

    async def _committed_event(self, event_id: str, indexed: _IndexedEvent) -> AuditEvent:
        """Return the committed record for a duplicate append, reloading if evicted.

        The reload path reads unverified JSONL, so the record must re-prove it is
        the one this collector committed before it can be returned or cached. A
        mismatch means the log no longer holds that record and fails closed; the
        in-memory index is never re-derived from disk.
        """

        cached = self._recent_events.get(event_id)
        if cached is not None:
            self._recent_events.move_to_end(event_id)
            return cached
        events = await self._backend.read_all()
        index = (indexed.sequence or 0) - 1
        found: AuditEvent | None = None
        if 0 <= index < len(events) and events[index].event_id == event_id:
            found = events[index]
        else:
            found = next((item for item in events if item.event_id == event_id), None)
        if found is None or not hmac.compare_digest(
            _event_fingerprint_digest(found), indexed.fingerprint_digest
        ):
            raise AuditCollectorProtocolError("event_index_desynchronized", event_id)
        self._cache(found)
        return found

    async def _anchored_checkpoint(self) -> AuditCheckpoint | None:
        async with self._operation_lock:
            checkpoint = await self._audit_log.export_checkpoint()
            self._require_anchor_matches(checkpoint)
            return self._state.checkpoint if self._state is not None else None

    async def _anchored_snapshot(self, *, require_checkpoint: bool) -> VerifiedAuditSnapshot:
        async with self._operation_lock:
            snapshot = await self._audit_log.read_verified(require_checkpoint=False)
            checkpoint = await self._audit_log.export_checkpoint()
            self._require_anchor_matches(checkpoint)
            verification = snapshot.verification.model_copy(
                update={
                    "checkpoint_status": "verified"
                    if checkpoint is not None
                    else snapshot.verification.checkpoint_status,
                    "attestable": checkpoint is not None and bool(snapshot.events),
                }
            )
            if require_checkpoint and not verification.attestable:
                raise AuditCollectorProtocolError("not_attestable", verification.checkpoint_status)
            return snapshot.model_copy(update={"verification": verification})

    async def _open_snapshot(self, payload: _SnapshotOpenPayload) -> dict[str, Any]:
        snapshot = await self._anchored_snapshot(require_checkpoint=payload.require_checkpoint)
        total_bytes = sum(len(event.model_dump_json().encode()) for event in snapshot.events)
        if (
            len(snapshot.events) > self._max_snapshot_events
            or total_bytes > self._max_snapshot_bytes
        ):
            raise AuditCollectorProtocolError("snapshot_too_large", str(len(snapshot.events)))
        now = time.monotonic()
        self._expire_snapshots(now)
        if len(self._snapshots) >= self._max_snapshots:
            raise AuditCollectorProtocolError("snapshot_capacity", str(self._max_snapshots))
        token = uuid.uuid4().hex
        self._snapshots[token] = _Snapshot(
            events=snapshot.events,
            verification=snapshot.verification,
            created_at=now,
            total_bytes=total_bytes,
        )
        return {
            "token": token,
            "total": len(snapshot.events),
            "total_bytes": total_bytes,
            "verification": snapshot.verification.model_dump(mode="json"),
        }

    def _page_snapshot(self, payload: _SnapshotPagePayload) -> dict[str, Any]:
        self._expire_snapshots(time.monotonic())
        token = payload.token
        snapshot = self._snapshots.get(token)
        if snapshot is None:
            raise AuditCollectorProtocolError("snapshot_missing", token)
        offset = payload.offset
        requested = payload.limit
        limit = min(requested, self._max_page_size)
        events = list(snapshot.events[offset : offset + limit])
        while events:
            result = {
                "token": token,
                "offset": offset,
                "total": len(snapshot.events),
                "events": [event.model_dump(mode="json") for event in events],
            }
            probe = _CollectorResponse(request_id="x" * 64, ok=True, result=result)
            if len(_canonical_json(probe)) <= self._max_frame_bytes:
                return result
            events.pop()
        if offset < len(snapshot.events):
            raise AuditCollectorProtocolError("event_too_large", str(offset))
        return {
            "token": token,
            "offset": offset,
            "total": len(snapshot.events),
            "events": [],
        }

    def _expire_snapshots(self, now: float) -> None:
        expired = [
            token
            for token, snapshot in self._snapshots.items()
            if now - snapshot.created_at > self._snapshot_ttl
        ]
        for token in expired:
            self._snapshots.pop(token, None)

    async def rotate_key(self, key_id: str, key: bytes) -> AuditKeyEpoch:
        """Durably activate a new signing epoch before using it for events.

        An environment-sourced keyring can only be rebuilt from
        ``AGENTGUARD_AUDIT_KEY`` and ``AGENTGUARD_AUDIT_KEYS``, so the epoch must
        already be declared there: the declaration is what makes post-rotation
        events verifiable after a restart, and this call confirms the epoch the
        environment (and therefore the signed collector state) already commits
        to. Rotating to an undeclared epoch is a one-way door and is refused.
        A caller-injected keyring owns its own continuity and rotates in place.

        Args:
            key_id: Identifier of the epoch to activate.
            key: Its signing key material.

        Returns:
            The activated key epoch.

        Raises:
            AuditKeyRotationRefusedError: If an environment-sourced keyring has
                no matching declaration for this epoch.
        """

        async with self._operation_lock:
            if self._audit_log.keyring.environment_sourced:
                return self._confirm_declared_epoch(key_id, key)
            checkpoint = await self._audit_log.export_checkpoint()
            activation = (checkpoint.head_sequence if checkpoint is not None else 0) + 1
            old_ring = self._audit_log.keyring
            candidate = old_ring.with_rotation(
                key_id=key_id,
                key=key,
                activation_sequence=activation,
            )
            previous = self._state
            state = self._make_state(checkpoint, candidate, key_id)
            await asyncio.to_thread(self._write_state_sync, state)
            try:
                self._audit_log.install_keyring(candidate)
            except BaseException:
                if previous is not None:
                    await asyncio.to_thread(self._write_state_sync, previous)
                raise
            self._state = state
            return candidate.epochs[-1]

    def _confirm_declared_epoch(self, key_id: str, key: bytes) -> AuditKeyEpoch:
        """Confirm an epoch the environment and the signed state already commit to."""

        declared = next(
            (epoch for epoch in self._audit_log.keyring.epochs if epoch.key_id == key_id),
            None,
        )
        if declared is None or not hmac.compare_digest(
            declared.key_fingerprint, hashlib.sha256(key).hexdigest()
        ):
            raise AuditKeyRotationRefusedError(key_id)
        logger.warning(
            "audit_key_rotation_requires_environment_continuity",
            key_id=key_id,
            activation_sequence=declared.activation_sequence,
        )
        return declared

    async def _initialize_state(self) -> None:
        await self._audit_log.recover_interrupted_append()
        snapshot = await self._audit_log.read_verified(require_checkpoint=False)
        checkpoint = await self._audit_log.export_checkpoint()
        self._event_index = {}
        self._recent_events = OrderedDict()
        for event in snapshot.events:
            self._remember(event)
        stored = await asyncio.to_thread(self._read_state_sync)
        if stored is None:
            if snapshot.events and not self._adopt_existing:
                raise AuditCollectorOwnershipError(
                    "non-empty audit log has no external collector state; "
                    "explicit adoption required"
                )
            signer = self._audit_log.keyring.epochs[-1].key_id
            stored = self._make_state(checkpoint, self._audit_log.keyring, signer)
            await asyncio.to_thread(self._write_state_sync, stored)
        self._verify_state_signature(stored, self._audit_log.keyring)
        if stored.key_epochs != self._audit_log.keyring.epochs:
            stored = await self._commit_declared_epochs(stored, checkpoint)
        self._state = stored
        await self._reconcile_anchor(snapshot.events, checkpoint)
        await self._reconcile_trusted_checkpoint(snapshot.events, checkpoint)

    async def _reconcile_trusted_checkpoint(
        self,
        events: tuple[AuditEvent, ...],
        local: AuditCheckpoint | None,
    ) -> None:
        """Refuse to start behind the off-host witness, then advance it.

        The witness is the only artifact outside this host's failure domain, so
        a local head behind it is the rollback signal that same-host state
        cannot produce.
        """

        if self._trusted_checkpoint_path is None:
            return
        witness = await asyncio.to_thread(self._read_trusted_checkpoint_sync)
        if witness is None:
            # An absent witness beside a non-empty log is indistinguishable from
            # one an attacker unmounted or deleted, so it is only bootstrapped
            # for a fresh log or under explicit adoption.
            if local is not None and not self._adopt_existing:
                raise AuditCollectorOwnershipError(
                    "trusted checkpoint is configured but absent; explicit adoption required"
                )
            logger.warning(
                "audit_trusted_checkpoint_bootstrapped",
                path=str(self._trusted_checkpoint_path),
            )
        else:
            self._audit_log.verify_checkpoint_signature(witness)
            if local is None or local.head_sequence < witness.head_sequence:
                raise AuditRollbackDetectedError(
                    trusted_head_sequence=witness.head_sequence,
                    local_head_sequence=local.head_sequence if local is not None else 0,
                )
            anchored = events[witness.head_sequence - 1]
            if (
                anchored.event_hash != witness.head_event_hash
                or anchored.chain_id != witness.chain_id
            ):
                raise AuditCollectorOwnershipError(
                    "local history does not extend the trusted checkpoint"
                )
        if local is not None:
            await asyncio.to_thread(self._write_trusted_checkpoint_sync, local)

    async def _commit_declared_epochs(
        self,
        stored: CollectorState,
        local: AuditCheckpoint | None,
    ) -> CollectorState:
        """Durably extend the committed epoch set with newly declared future epochs.

        Only a strict suffix extension is accepted, and only when every added
        epoch activates after the committed head — an epoch that reaches back
        into committed history would reinterpret already-signed events.
        """

        epochs = self._audit_log.keyring.epochs
        added = epochs[len(stored.key_epochs) :]
        if not added or epochs[: len(stored.key_epochs)] != stored.key_epochs:
            raise AuditCollectorOwnershipError("collector key epochs differ from signed state")
        if not self._adopt_declared_epochs:
            # The environment declaration is unauthenticated, so committing it
            # into signed state is a deliberate operator action, never a
            # side effect of a restart that happens to see a new variable.
            raise AuditCollectorOwnershipError(
                "signed state does not commit the declared audit key epochs; "
                "explicit adoption required"
            )
        committed_head = local.head_sequence if local is not None else 0
        if any(epoch.activation_sequence <= committed_head for epoch in added):
            raise AuditCollectorOwnershipError(
                "declared audit key epoch would rewrite a committed sequence"
            )
        extended = self._make_state(stored.checkpoint, self._audit_log.keyring, epochs[-1].key_id)
        await asyncio.to_thread(self._write_state_sync, extended)
        logger.warning(
            "audit_key_epochs_committed",
            key_ids=[epoch.key_id for epoch in added],
            activation_sequences=[epoch.activation_sequence for epoch in added],
        )
        return extended

    async def _reconcile_anchor(
        self,
        events: tuple[AuditEvent, ...],
        local: AuditCheckpoint | None,
    ) -> None:
        assert self._state is not None
        anchored = self._state.checkpoint
        if anchored is None:
            if local is None:
                return
            if not self._adopt_existing:
                raise AuditCollectorOwnershipError("signed state does not anchor local history")
        elif local is None or anchored.head_sequence > local.head_sequence:
            raise AuditCollectorOwnershipError("external collector state is ahead of local history")
        elif anchored.head_sequence == local.head_sequence:
            if (
                anchored.head_event_hash != local.head_event_hash
                or anchored.chain_id != local.chain_id
            ):
                raise AuditCollectorOwnershipError("local and external audit heads conflict")
            return
        else:
            event = events[anchored.head_sequence - 1]
            if event.event_hash != anchored.head_event_hash or event.chain_id != anchored.chain_id:
                raise AuditCollectorOwnershipError("local history does not extend external state")
        signer = self._audit_log.keyring.epochs[-1].key_id
        advanced = self._make_state(local, self._audit_log.keyring, signer)
        await asyncio.to_thread(self._write_state_sync, advanced)
        self._state = advanced

    async def _anchor_current_head(self) -> None:
        checkpoint = await self._audit_log.export_checkpoint()
        signer = self._audit_log.keyring.epochs[-1].key_id
        state = self._make_state(checkpoint, self._audit_log.keyring, signer)
        await asyncio.to_thread(self._write_state_sync, state)
        self._state = state
        if self._trusted_checkpoint_path is not None and checkpoint is not None:
            await asyncio.to_thread(self._write_trusted_checkpoint_sync, checkpoint)

    def _require_anchor_matches(self, checkpoint: AuditCheckpoint | None) -> None:
        if self._state is None or self._state.checkpoint != checkpoint:
            raise AuditCollectorProtocolError("anchor_mismatch", "head is not externally committed")

    @staticmethod
    def _make_state(
        checkpoint: AuditCheckpoint | None,
        keyring: AuditKeyring,
        signing_key_id: str,
    ) -> CollectorState:
        if signing_key_id != keyring.epochs[-1].key_id:
            raise ValueError("collector state must use the newest committed key epoch")
        unsigned = CollectorState(
            checkpoint=checkpoint,
            key_epochs=keyring.epochs,
            signing_key_id=signing_key_id,
        )
        signature = hmac.new(
            keyring.key_for_id(signing_key_id),
            _STATE_DOMAIN + _canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return unsigned.model_copy(update={"signature": signature})

    @staticmethod
    def _verify_state_signature(state: CollectorState, keyring: AuditKeyring) -> None:
        if not state.key_epochs or state.signing_key_id != state.key_epochs[-1].key_id:
            raise AuditCollectorOwnershipError(
                "collector state signer is not the newest committed key epoch"
            )
        for epoch in state.key_epochs:
            fingerprint = hashlib.sha256(keyring.key_for_id(epoch.key_id)).hexdigest()
            if not hmac.compare_digest(fingerprint, epoch.key_fingerprint):
                raise AuditCollectorOwnershipError(f"key fingerprint mismatch for {epoch.key_id}")
        unsigned = state.model_copy(update={"signature": ""})
        expected = hmac.new(
            keyring.key_for_id(state.signing_key_id),
            _STATE_DOMAIN + _canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(state.signature, expected):
            raise AuditCollectorOwnershipError("invalid collector state signature")

    def _read_state_sync(self) -> CollectorState | None:
        try:
            return CollectorState.model_validate_json(self._state_path.read_bytes())
        except FileNotFoundError:
            return None

    def _write_state_sync(self, state: CollectorState) -> None:
        self._write_atomic_sync(self._state_path, _canonical_json(state))

    def _read_trusted_checkpoint_sync(self) -> AuditCheckpoint | None:
        assert self._trusted_checkpoint_path is not None
        try:
            return AuditCheckpoint.model_validate_json(self._trusted_checkpoint_path.read_bytes())
        except FileNotFoundError:
            return None

    def _write_trusted_checkpoint_sync(self, checkpoint: AuditCheckpoint) -> None:
        assert self._trusted_checkpoint_path is not None
        self._write_atomic_sync(
            self._trusted_checkpoint_path,
            checkpoint.model_dump_json().encode(),
        )

    @staticmethod
    def _write_atomic_sync(destination: Path, payload: bytes) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}-",
                delete=False,
            ) as stream:
                temporary_name = stream.name
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)


__all__ = ["AuditCollectorServer", "CollectorState", "SigningAuditBackend"]
