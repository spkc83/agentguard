"""Red team tests for sandbox escape attempts.

These tests require Docker and are marked as integration + red_team.
They verify that sandboxed commands cannot:
- Access the host network
- Read host filesystem
- Exceed memory limits
"""

from __future__ import annotations

import pytest

from agentguard.core.sandbox import (
    SANDBOX_MEMORY_LIMIT,
    SANDBOX_PROCESS_EXIT_NONZERO,
    DockerSandboxBackend,
    SandboxConfig,
)

pytest.importorskip("docker", reason="Docker sandbox red-team tests require agentguard[sandbox]")


@pytest.mark.integration
@pytest.mark.red_team
class TestSandboxEscape:
    """Adversarial tests for Docker sandbox isolation."""

    async def test_no_network_access(self) -> None:
        """Container has no non-loopback network interface."""
        backend = DockerSandboxBackend()
        result = await backend.run(
            command=[
                "python3",
                "-c",
                (
                    "import socket, sys; "
                    "names=sorted(name for _, name in socket.if_nameindex()); "
                    "non_loopback=[name for name in names if name != 'lo']; "
                    "print(','.join(names)); sys.exit(42 if non_loopback else 0)"
                ),
            ],
            config=SandboxConfig(network_enabled=False, timeout_seconds=10.0),
        )
        assert result.reason_code == ""
        assert result.stdout.strip().split(",") == ["lo"]

    async def test_no_host_filesystem_read(self) -> None:
        """Container cannot read host /etc/passwd."""
        backend = DockerSandboxBackend()
        result = await backend.run(
            command=["cat", "/host/etc/passwd"],
            config=SandboxConfig(timeout_seconds=5.0),
        )
        assert result.reason_code == SANDBOX_PROCESS_EXIT_NONZERO
        assert "No such file or directory" in result.stderr

    async def test_memory_limit_enforced(self) -> None:
        """Container exceeding memory limit is killed."""
        backend = DockerSandboxBackend()
        result = await backend.run(
            command=["python3", "-c", "x = 'A' * (512 * 1024 * 1024)"],
            config=SandboxConfig(memory_limit_mb=64, timeout_seconds=10.0),
        )
        assert result.reason_code == SANDBOX_MEMORY_LIMIT
