"""Sandboxed tool execution backends.

Two backends are provided:
- DockerSandboxBackend: full isolation in ephemeral containers (production).
- NoOpSandboxBackend: direct subprocess execution (development/testing).

Both implement the SandboxBackend protocol and return SandboxResult.

NOTE: NoOpSandboxBackend uses asyncio.create_subprocess_exec which is the safe,
non-shell subprocess API. No shell=True is ever used.
"""

from __future__ import annotations

import asyncio
import time
from typing import Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, ConfigDict

from agentguard.exceptions import SandboxError
from agentguard.models import SandboxResult

logger = structlog.get_logger()


class SandboxConfig(BaseModel):
    """Configuration for a sandbox execution.

    Args:
        timeout_seconds: Maximum execution time before kill.
        network_enabled: Whether the sandbox can access the network.
        memory_limit_mb: Memory limit in megabytes.
    """

    model_config = ConfigDict(frozen=True)

    timeout_seconds: float = 30.0
    network_enabled: bool = False
    memory_limit_mb: int = 256


@runtime_checkable
class SandboxBackend(Protocol):
    """Protocol for pluggable sandbox execution backends."""

    async def run(
        self, command: list[str], config: SandboxConfig | None = None
    ) -> SandboxResult: ...


class NoOpSandboxBackend:
    """Direct subprocess execution without sandboxing.

    Intended for development and testing only. Runs commands
    as local subprocesses with timeout enforcement.
    Uses asyncio.create_subprocess_exec (safe, no shell injection).
    """

    async def run(self, command: list[str], config: SandboxConfig | None = None) -> SandboxResult:
        """Run command as a local subprocess."""
        cfg = config or SandboxConfig()
        start = time.monotonic()
        proc = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.timeout_seconds
            )
            duration_ms = (time.monotonic() - start) * 1000
            return SandboxResult(
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace"),
                exit_code=proc.returncode or 0,
                duration_ms=duration_ms,
                backend="none",
            )
        except TimeoutError:
            if proc is not None:
                proc.kill()
            duration_ms = (time.monotonic() - start) * 1000
            logger.warning("sandbox_timeout", command=command, timeout=cfg.timeout_seconds)
            return SandboxResult(
                stdout="",
                stderr=f"Timed out after {cfg.timeout_seconds}s",
                exit_code=137,
                duration_ms=duration_ms,
                backend="none",
            )
        except OSError as e:
            duration_ms = (time.monotonic() - start) * 1000
            raise SandboxError(f"Failed to run command: {e}") from e


class DockerSandboxBackend:
    """Docker container-based sandbox for full isolation.

    Each run spawns an ephemeral container with:
    - Network disabled by default (opt-in per config)
    - Memory limits enforced
    - Timeout with container kill
    - No host filesystem access

    Args:
        image: Docker image to use for containers.
    """

    def __init__(self, image: str = "python:3.11-slim") -> None:
        self._image = image

    async def run(self, command: list[str], config: SandboxConfig | None = None) -> SandboxResult:
        """Run command in an ephemeral Docker container."""
        cfg = config or SandboxConfig()
        start = time.monotonic()

        try:
            import docker
        except ImportError as e:
            raise SandboxError(
                "Docker SDK not installed. Install with: pip install agentguard[sandbox]"
            ) from e

        try:
            client = docker.from_env()
            container = client.containers.run(
                self._image,
                command=command,
                detach=True,
                network_disabled=not cfg.network_enabled,
                mem_limit=f"{cfg.memory_limit_mb}m",
                remove=False,
            )

            try:
                exit_status = container.wait(timeout=int(cfg.timeout_seconds))
                stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
                exit_code = exit_status.get("StatusCode", 1)
            except Exception:
                container.kill()
                stdout = ""
                stderr = f"Timed out after {cfg.timeout_seconds}s"
                exit_code = 137
            finally:
                container.remove(force=True)

            duration_ms = (time.monotonic() - start) * 1000
            logger.info(
                "sandbox_docker_completed",
                image=self._image,
                exit_code=exit_code,
                duration_ms=duration_ms,
            )
            return SandboxResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration_ms=duration_ms,
                backend="docker",
            )
        except SandboxError:
            raise
        except Exception as e:
            duration_ms = (time.monotonic() - start) * 1000
            raise SandboxError(f"Docker run failed: {e}") from e
