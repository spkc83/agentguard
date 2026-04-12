"""Integration test for Docker sandbox — requires running Docker daemon."""

from __future__ import annotations

import pytest

from agentguard.core.sandbox import DockerSandboxBackend, SandboxConfig


@pytest.mark.integration
class TestDockerSandboxIntegration:
    async def test_echo(self) -> None:
        backend = DockerSandboxBackend(image="python:3.11-slim")
        result = await backend.run(
            command=["echo", "hello from docker"],
            config=SandboxConfig(timeout_seconds=30.0),
        )
        assert result.exit_code == 0
        assert "hello from docker" in result.stdout
        assert result.backend == "docker"

    async def test_python_run(self) -> None:
        backend = DockerSandboxBackend(image="python:3.11-slim")
        result = await backend.run(
            command=["python3", "-c", "print(2 + 2)"],
            config=SandboxConfig(timeout_seconds=30.0),
        )
        assert result.exit_code == 0
        assert "4" in result.stdout

    async def test_timeout_kills_container(self) -> None:
        backend = DockerSandboxBackend(image="python:3.11-slim")
        result = await backend.run(
            command=["sleep", "60"],
            config=SandboxConfig(timeout_seconds=3.0),
        )
        assert result.exit_code != 0
