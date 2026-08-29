"""Sandboxed tool execution backends and immutable runtime obligations.

The Docker backend is an optional lazy dependency. It always uses the hardened
profile declared here; a guardrail can require sandbox execution but cannot
weaken the container or invent a command after authorization.
"""

from __future__ import annotations

import asyncio
import math
import time
from typing import Literal, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentguard.exceptions import SandboxError
from agentguard.models import SandboxResult

logger = structlog.get_logger()

SANDBOX_BACKEND_REQUIRED = "SANDBOX.BACKEND_REQUIRED"
SANDBOX_CONFIG_INVALID = "SANDBOX.CONFIG_INVALID"
SANDBOX_COMMAND_INVALID = "SANDBOX.COMMAND_INVALID"
SANDBOX_OBLIGATION_CONFLICT = "SANDBOX.OBLIGATION_CONFLICT"
SANDBOX_SDK_UNAVAILABLE = "SANDBOX.SDK_UNAVAILABLE"
SANDBOX_START_FAILED = "SANDBOX.START_FAILED"
SANDBOX_TIMEOUT = "SANDBOX.TIMEOUT"
SANDBOX_MEMORY_LIMIT = "SANDBOX.MEMORY_LIMIT"
SANDBOX_PROCESS_EXIT_NONZERO = "SANDBOX.PROCESS_EXIT_NONZERO"
SANDBOX_CLEANUP_FAILED = "SANDBOX.CLEANUP_FAILED"
SANDBOX_INTERNAL_ERROR = "SANDBOX.INTERNAL_ERROR"
SANDBOX_REQUIRED = "SANDBOX.REQUIRED"

_SANDBOX_USER = "65532:65532"
_CPU_PERIOD_US = 100_000
_MAX_COMMAND_ARGS = 256
_MAX_COMMAND_BYTES = 64 * 1024
_MAX_CAPTURE_BYTES = 1024 * 1024


class SandboxConfig(BaseModel):
    """Strict resource limits for one sandbox execution."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    timeout_seconds: float = Field(default=30.0, gt=0, le=3_600)
    network_enabled: bool = False
    memory_limit_mb: int = Field(default=256, ge=16, le=131_072)
    pids_limit: int = Field(default=64, ge=1, le=4_096)
    cpu_limit: float = Field(default=1.0, gt=0, le=64)

    @field_validator("timeout_seconds", "cpu_limit")
    @classmethod
    def _require_finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("sandbox numeric limits must be finite")
        return value


class SandboxObligation(BaseModel):
    """Require the already-authorized tool command to run in Docker.

    The command deliberately is not part of this post-policy decision. The
    kernel extracts it from the immutable transformed ``ToolCallPayload`` that
    resolvers, RBAC, and evidence hashing have already observed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    kind: Literal["sandbox"] = "sandbox"
    config: SandboxConfig = SandboxConfig()


def validate_sandbox_command(command: object) -> list[str]:
    """Return a defensive argv copy or raise a non-secret stable error."""

    if not isinstance(command, tuple | list) or not command or len(command) > _MAX_COMMAND_ARGS:
        raise SandboxError(
            "sandbox command must be a non-empty bounded argv",
            reason_code=SANDBOX_COMMAND_INVALID,
        )
    if any(
        not isinstance(argument, str) or not argument or "\x00" in argument for argument in command
    ):
        raise SandboxError(
            "sandbox argv contains an invalid argument",
            reason_code=SANDBOX_COMMAND_INVALID,
        )
    if sum(len(argument.encode("utf-8")) for argument in command) > _MAX_COMMAND_BYTES:
        raise SandboxError(
            "sandbox argv exceeds the size limit",
            reason_code=SANDBOX_COMMAND_INVALID,
        )
    return list(command)


@runtime_checkable
class SandboxBackend(Protocol):
    """Protocol for pluggable sandbox execution backends."""

    async def run(
        self, command: list[str], config: SandboxConfig | None = None
    ) -> SandboxResult: ...


class NoOpSandboxBackend:
    """Direct non-shell subprocess execution for development and tests only."""

    async def run(self, command: list[str], config: SandboxConfig | None = None) -> SandboxResult:
        """Run command with ``create_subprocess_exec`` and no shell."""

        argv = validate_sandbox_command(command)
        cfg = config or SandboxConfig()
        start = time.monotonic()
        proc: asyncio.subprocess.Process | None = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.timeout_seconds
            )
            exit_code = proc.returncode or 0
            return SandboxResult(
                stdout=stdout_bytes[:_MAX_CAPTURE_BYTES].decode("utf-8", errors="replace"),
                stderr=stderr_bytes[:_MAX_CAPTURE_BYTES].decode("utf-8", errors="replace"),
                exit_code=exit_code,
                duration_ms=(time.monotonic() - start) * 1000,
                backend="none",
                failure_reason=(SANDBOX_PROCESS_EXIT_NONZERO if exit_code else None),
            )
        except TimeoutError:
            if proc is not None:
                proc.kill()
                await proc.wait()
            logger.warning("sandbox_timeout", timeout=cfg.timeout_seconds)
            return SandboxResult(
                stdout="",
                stderr=f"Timed out after {cfg.timeout_seconds}s",
                exit_code=137,
                duration_ms=(time.monotonic() - start) * 1000,
                backend="none",
                failure_reason=SANDBOX_TIMEOUT,
            )
        except OSError as exc:
            raise SandboxError(
                "local sandbox process could not start",
                reason_code=SANDBOX_START_FAILED,
            ) from exc


class DockerSandboxBackend:
    """Ephemeral Docker execution with a fixed hardened isolation profile."""

    def __init__(self, image: str = "python:3.11-slim") -> None:
        if not image or image != image.strip() or not image.isprintable():
            raise ValueError("image must be canonical printable text")
        self._image = image

    async def run(self, command: list[str], config: SandboxConfig | None = None) -> SandboxResult:
        """Run a command off-loop and drain cleanup before propagating cancellation."""

        argv = validate_sandbox_command(command)
        cfg = config or SandboxConfig()
        if cfg.network_enabled:
            raise SandboxError(
                "the hardened Docker backend does not permit network access",
                reason_code=SANDBOX_CONFIG_INVALID,
            )
        task = asyncio.create_task(asyncio.to_thread(self._run_sync, argv, cfg))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
            if not task.cancelled():
                task.exception()
            raise

    def _run_sync(self, command: list[str], cfg: SandboxConfig) -> SandboxResult:
        start = time.monotonic()
        try:
            import docker
        except ImportError as exc:
            raise SandboxError(
                "Docker SDK not installed; install agentguard[sandbox]",
                reason_code=SANDBOX_SDK_UNAVAILABLE,
            ) from exc

        container = None
        client = None
        primary_error: BaseException | None = None
        try:
            try:
                client = docker.from_env()
                container = client.containers.run(
                    self._image,
                    command=command,
                    detach=True,
                    network_disabled=True,
                    mem_limit=f"{cfg.memory_limit_mb}m",
                    read_only=True,
                    user=_SANDBOX_USER,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    pids_limit=cfg.pids_limit,
                    cpu_period=_CPU_PERIOD_US,
                    cpu_quota=max(1_000, round(cfg.cpu_limit * _CPU_PERIOD_US)),
                    log_config={
                        "type": "json-file",
                        "config": {"max-size": f"{_MAX_CAPTURE_BYTES}b", "max-file": "1"},
                    },
                    remove=False,
                )
            except SandboxError:
                raise
            except Exception as exc:
                raise SandboxError(
                    "Docker container could not start",
                    reason_code=SANDBOX_START_FAILED,
                ) from exc

            try:
                exit_status = container.wait(timeout=math.ceil(cfg.timeout_seconds))
            except Exception as exc:
                if not _is_docker_timeout(exc):
                    raise SandboxError(
                        "Docker container wait failed",
                        reason_code=SANDBOX_INTERNAL_ERROR,
                    ) from exc
                try:
                    container.kill()
                except Exception as kill_exc:
                    raise SandboxError(
                        "timed-out Docker container could not be killed",
                        reason_code=SANDBOX_CLEANUP_FAILED,
                    ) from kill_exc
                return SandboxResult(
                    stdout="",
                    stderr=f"Timed out after {cfg.timeout_seconds}s",
                    exit_code=137,
                    duration_ms=(time.monotonic() - start) * 1000,
                    backend="docker",
                    failure_reason=SANDBOX_TIMEOUT,
                )

            try:
                stdout = _read_bounded_logs(container, stdout=True)
                stderr = _read_bounded_logs(container, stdout=False)
                exit_code = int(exit_status.get("StatusCode", 1))
                oom_killed = _container_was_oom_killed(container)
            except Exception as exc:
                raise SandboxError(
                    "Docker result collection failed",
                    reason_code=SANDBOX_INTERNAL_ERROR,
                ) from exc
            result = SandboxResult(
                stdout=stdout[:_MAX_CAPTURE_BYTES].decode("utf-8", errors="replace"),
                stderr=stderr[:_MAX_CAPTURE_BYTES].decode("utf-8", errors="replace"),
                exit_code=exit_code,
                duration_ms=(time.monotonic() - start) * 1000,
                backend="docker",
                failure_reason=(
                    SANDBOX_MEMORY_LIMIT
                    if oom_killed
                    else SANDBOX_PROCESS_EXIT_NONZERO
                    if exit_code
                    else None
                ),
            )
            logger.info(
                "sandbox_docker_completed",
                image=self._image,
                exit_code=exit_code,
                duration_ms=result.duration_ms,
            )
            return result
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            cleanup_error: BaseException | None = None
            if container is not None:
                try:
                    container.remove(force=True)
                except BaseException as exc:
                    cleanup_error = exc
            if client is not None:
                close = getattr(client, "close", None)
                if callable(close):
                    try:
                        close()
                    except BaseException as exc:
                        cleanup_error = cleanup_error or exc
            if cleanup_error is not None:
                if primary_error is None:
                    raise SandboxError(
                        "Docker sandbox cleanup failed",
                        reason_code=SANDBOX_CLEANUP_FAILED,
                    ) from cleanup_error
                logger.error("sandbox_cleanup_failed", error_type=type(cleanup_error).__name__)


def _is_docker_timeout(exc: BaseException) -> bool:
    """Recognize SDK/requests timeouts without importing optional dependencies.

    ``container.wait(timeout=N)`` surfaces its read timeout as
    ``requests.exceptions.ConnectionError`` raised FROM
    ``urllib3.exceptions.ReadTimeoutError`` (itself from ``socket.timeout``),
    so the timeout signal lives in the exception chain, not on the surface
    exception. Walk ``__cause__``/``__context__`` rather than matching only
    the outermost type; a genuine daemon connection failure carries no
    timeout anywhere in its chain and stays an internal error.
    """

    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, TimeoutError):
            return True
        if type(current).__name__ in {"ReadTimeout", "ReadTimeoutError"} and type(
            current
        ).__module__.startswith(("requests.", "urllib3.")):
            return True
        current = current.__cause__ or current.__context__
    return False


def _read_bounded_logs(container: object, *, stdout: bool) -> bytes:
    """Read at most the capture limit without materializing an unbounded stream."""

    kwargs = {"stdout": stdout, "stderr": not stdout, "stream": True, "follow": False}
    try:
        chunks = container.logs(**kwargs)  # type: ignore[attr-defined]
    except TypeError:
        # Compatibility with small test doubles and older SDKs; Docker's log rotation
        # remains bounded by ``log_config`` at container creation.
        chunks = container.logs(  # type: ignore[attr-defined]
            stdout=stdout,
            stderr=not stdout,
            tail=1_000,
        )
    if isinstance(chunks, bytes):
        return chunks[:_MAX_CAPTURE_BYTES]
    captured = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            continue
        remaining = _MAX_CAPTURE_BYTES - len(captured)
        if remaining <= 0:
            break
        captured.extend(chunk[:remaining])
    return bytes(captured)


def _container_was_oom_killed(container: object) -> bool:
    """Return Docker's authoritative OOM state for a completed container."""

    reload_state = getattr(container, "reload", None)
    if not callable(reload_state):
        raise RuntimeError("Docker container does not expose reload()")
    reload_state()
    attrs = getattr(container, "attrs", None)
    if not isinstance(attrs, dict):
        raise RuntimeError("Docker container does not expose state attributes")
    state = attrs.get("State")
    if not isinstance(state, dict):
        raise RuntimeError("Docker container does not expose OOMKilled state")
    oom_killed = state.get("OOMKilled")
    if not isinstance(oom_killed, bool):
        raise RuntimeError("Docker container does not expose OOMKilled state")
    return oom_killed


__all__ = [
    "SANDBOX_BACKEND_REQUIRED",
    "SANDBOX_CLEANUP_FAILED",
    "SANDBOX_COMMAND_INVALID",
    "SANDBOX_CONFIG_INVALID",
    "SANDBOX_INTERNAL_ERROR",
    "SANDBOX_MEMORY_LIMIT",
    "SANDBOX_OBLIGATION_CONFLICT",
    "SANDBOX_PROCESS_EXIT_NONZERO",
    "SANDBOX_REQUIRED",
    "SANDBOX_SDK_UNAVAILABLE",
    "SANDBOX_START_FAILED",
    "SANDBOX_TIMEOUT",
    "DockerSandboxBackend",
    "NoOpSandboxBackend",
    "SandboxBackend",
    "SandboxConfig",
    "SandboxObligation",
    "validate_sandbox_command",
]
