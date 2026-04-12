"""Tests for agentguard.core.sandbox — sandboxed tool execution."""

from __future__ import annotations

import pytest

from agentguard.core.sandbox import DockerSandboxBackend, NoOpSandboxBackend, SandboxConfig


class TestSandboxConfig:
    def test_defaults(self) -> None:
        config = SandboxConfig()
        assert config.timeout_seconds == 30.0
        assert config.network_enabled is False
        assert config.memory_limit_mb == 256

    def test_custom(self) -> None:
        config = SandboxConfig(timeout_seconds=10.0, network_enabled=True, memory_limit_mb=512)
        assert config.timeout_seconds == 10.0
        assert config.network_enabled is True


class TestNoOpSandboxBackend:
    async def test_run_success(self) -> None:
        backend = NoOpSandboxBackend()
        result = await backend.run(
            command=["echo", "hello"],
            config=SandboxConfig(),
        )
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.backend == "none"

    async def test_run_failure(self) -> None:
        backend = NoOpSandboxBackend()
        result = await backend.run(
            command=["python3", "-c", "import sys; sys.exit(1)"],
            config=SandboxConfig(),
        )
        assert result.exit_code == 1
        assert result.success is False

    async def test_run_timeout(self) -> None:
        backend = NoOpSandboxBackend()
        result = await backend.run(
            command=["sleep", "10"],
            config=SandboxConfig(timeout_seconds=0.5),
        )
        assert result.exit_code != 0
        assert result.success is False

    async def test_run_captures_stderr(self) -> None:
        backend = NoOpSandboxBackend()
        result = await backend.run(
            command=["python3", "-c", "import sys; print('err', file=sys.stderr)"],
            config=SandboxConfig(),
        )
        assert "err" in result.stderr


class TestDockerSandboxBackend:
    def test_instantiation(self) -> None:
        """DockerSandboxBackend can be instantiated (doesn't require running Docker)."""
        backend = DockerSandboxBackend(image="python:3.11-slim")
        assert backend._image == "python:3.11-slim"

    async def test_missing_docker_sdk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Raises SandboxError if docker SDK is not importable."""
        import builtins

        from agentguard.exceptions import SandboxError

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "docker":
                raise ImportError("no docker")
            return real_import(name, *args, **kwargs)

        backend = DockerSandboxBackend()
        monkeypatch.setattr(builtins, "__import__", mock_import)
        with pytest.raises(SandboxError, match="Docker SDK not installed"):
            await backend.run(command=["echo", "hi"], config=SandboxConfig())
