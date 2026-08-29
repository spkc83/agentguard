"""Tests for agentguard.core.sandbox — sandboxed tool execution."""

from __future__ import annotations

import asyncio
import sys
import threading
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agentguard.core.sandbox import (
    SANDBOX_MEMORY_LIMIT,
    SANDBOX_PROCESS_EXIT_NONZERO,
    SANDBOX_TIMEOUT,
    DockerSandboxBackend,
    NoOpSandboxBackend,
    SandboxConfig,
    SandboxObligation,
    _read_bounded_logs,
)


class TestSandboxConfig:
    def test_defaults(self) -> None:
        config = SandboxConfig()
        assert config.timeout_seconds == 30.0
        assert config.network_enabled is False
        assert config.memory_limit_mb == 256
        assert config.pids_limit == 64
        assert config.cpu_limit == 1.0

    def test_custom(self) -> None:
        config = SandboxConfig(timeout_seconds=10.0, network_enabled=True, memory_limit_mb=512)
        assert config.timeout_seconds == 10.0
        assert config.network_enabled is True

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("timeout_seconds", 0),
            ("memory_limit_mb", 0),
            ("pids_limit", 0),
            ("cpu_limit", 0),
            ("cpu_limit", float("inf")),
        ],
    )
    def test_rejects_invalid_resource_limits(self, field: str, value: object) -> None:
        with pytest.raises(ValidationError):
            SandboxConfig.model_validate({field: value})


class TestSandboxObligation:
    def test_is_deeply_immutable_and_contains_no_post_authorization_command(self) -> None:
        obligation = SandboxObligation(config=SandboxConfig(timeout_seconds=4, memory_limit_mb=64))

        assert obligation.kind == "sandbox"
        assert obligation.config.timeout_seconds == 4
        with pytest.raises(Exception):
            obligation.config = SandboxConfig()
        with pytest.raises(ValidationError):
            SandboxObligation.model_validate({"command": ["sh"]})


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
        assert result.reason_code == SANDBOX_PROCESS_EXIT_NONZERO

    async def test_run_timeout(self) -> None:
        backend = NoOpSandboxBackend()
        result = await backend.run(
            command=["sleep", "10"],
            config=SandboxConfig(timeout_seconds=0.5),
        )
        assert result.exit_code != 0
        assert result.success is False
        assert result.reason_code == SANDBOX_TIMEOUT

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
        with pytest.raises(SandboxError, match="Docker SDK not installed") as raised:
            await backend.run(command=["echo", "hi"], config=SandboxConfig())
        assert raised.value.reason_code == "SANDBOX.SDK_UNAVAILABLE"

    async def test_run_forces_hardened_container_configuration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[dict[str, object]] = []

        class Container:
            attrs = {"State": {"OOMKilled": False}}

            def wait(self, *, timeout: int) -> dict[str, int]:
                assert timeout == 9
                return {"StatusCode": 0}

            def reload(self) -> None:
                pass

            def logs(self, *, stdout: bool, stderr: bool, tail: int) -> bytes:
                assert tail == 1_000
                return b"ok" if stdout and not stderr else b""

            def remove(self, *, force: bool) -> None:
                assert force

        class Containers:
            def run(self, image: str, **kwargs: object) -> Container:
                assert image == "python:3.11-slim"
                calls.append(kwargs)
                return Container()

        fake_docker = SimpleNamespace(
            from_env=lambda: SimpleNamespace(containers=Containers()),
        )
        monkeypatch.setitem(sys.modules, "docker", fake_docker)

        result = await DockerSandboxBackend().run(
            ["python3", "-c", "print('ok')"],
            SandboxConfig(
                timeout_seconds=9,
                memory_limit_mb=128,
                pids_limit=23,
                cpu_limit=0.75,
            ),
        )

        assert result.success
        assert calls == [
            {
                "command": ["python3", "-c", "print('ok')"],
                "detach": True,
                "network_disabled": True,
                "mem_limit": "128m",
                "read_only": True,
                "user": "65532:65532",
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "pids_limit": 23,
                "cpu_period": 100_000,
                "cpu_quota": 75_000,
                "log_config": {
                    "type": "json-file",
                    "config": {"max-size": "1048576b", "max-file": "1"},
                },
                "remove": False,
            }
        ]

    async def test_oom_kill_has_a_control_specific_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Container:
            attrs = {"State": {"OOMKilled": True}}

            def wait(self, *, timeout: int) -> dict[str, int]:
                assert timeout == 10
                return {"StatusCode": 137}

            def reload(self) -> None:
                pass

            def logs(self, **_kwargs: object) -> bytes:
                return b""

            def remove(self, *, force: bool) -> None:
                assert force

        fake_docker = SimpleNamespace(
            from_env=lambda: SimpleNamespace(
                containers=SimpleNamespace(run=lambda *_args, **_kwargs: Container())
            ),
        )
        monkeypatch.setitem(sys.modules, "docker", fake_docker)

        result = await DockerSandboxBackend().run(
            ["python3", "-c", "raise MemoryError"],
            SandboxConfig(timeout_seconds=10, memory_limit_mb=64),
        )

        assert result.reason_code == SANDBOX_MEMORY_LIMIT

    def test_oversized_single_log_chunk_is_bounded(self) -> None:
        class Container:
            def logs(self, *, stdout: bool, stderr: bool, tail: int) -> bytes:
                del stdout, stderr, tail
                return b"x" * (2 * 1024 * 1024)

        bounded = _read_bounded_logs(Container(), stdout=True)

        assert len(bounded) == 1024 * 1024

    async def test_network_opt_in_is_rejected_by_hardened_backend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(
            sys.modules,
            "docker",
            SimpleNamespace(from_env=lambda: pytest.fail("docker client must not be created")),
        )

        from agentguard.exceptions import SandboxError

        with pytest.raises(SandboxError) as raised:
            await DockerSandboxBackend().run(
                ["echo", "unsafe"],
                SandboxConfig(network_enabled=True),
            )

        assert raised.value.reason_code == "SANDBOX.CONFIG_INVALID"

    async def test_cancellation_waits_for_off_thread_cleanup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        started = threading.Event()
        cleaned = threading.Event()
        release = threading.Event()
        backend = DockerSandboxBackend()

        def run_sync(_command: list[str], _config: SandboxConfig) -> object:
            started.set()
            release.wait(timeout=2)
            cleaned.set()
            return SimpleNamespace()

        monkeypatch.setattr(backend, "_run_sync", run_sync)
        task = asyncio.create_task(backend.run(["echo", "ok"]))
        assert await asyncio.to_thread(started.wait, 1)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()

        with pytest.raises(asyncio.CancelledError):
            await task
        assert cleaned.is_set()


class TestDockerTimeoutClassifier:
    """`container.wait` timeouts arrive wrapped; the classifier must walk the chain."""

    def test_surface_read_timeout_is_a_timeout(self) -> None:
        from agentguard.core.sandbox import _is_docker_timeout

        read_timeout = type("ReadTimeout", (OSError,), {"__module__": "requests.exceptions"})
        assert _is_docker_timeout(read_timeout())

    def test_wrapped_wait_timeout_chain_is_a_timeout(self) -> None:
        """requests.ConnectionError <- urllib3.ReadTimeoutError <- socket.timeout.

        This is the exact chain docker-py surfaces when ``container.wait``
        exceeds its read timeout on a real daemon (observed in CI); the
        surface exception is neither a TimeoutError nor named ReadTimeout.
        """
        from agentguard.core.sandbox import _is_docker_timeout

        read_timeout_error = type(
            "ReadTimeoutError", (OSError,), {"__module__": "urllib3.exceptions"}
        )
        connection_error = type(
            "ConnectionError", (OSError,), {"__module__": "requests.exceptions"}
        )
        inner = read_timeout_error("Read timed out.")
        inner.__cause__ = TimeoutError("timed out")
        outer = connection_error(inner)
        outer.__cause__ = inner
        assert _is_docker_timeout(outer)

    def test_plain_connection_failure_is_not_a_timeout(self) -> None:
        """A daemon connection drop with no timeout in its chain stays internal."""
        from agentguard.core.sandbox import _is_docker_timeout

        connection_error = type(
            "ConnectionError", (OSError,), {"__module__": "requests.exceptions"}
        )
        protocol_error = type("ProtocolError", (OSError,), {"__module__": "urllib3.exceptions"})
        inner = protocol_error("Connection aborted.")
        outer = connection_error(inner)
        outer.__cause__ = inner
        assert not _is_docker_timeout(outer)

    def test_self_referential_chain_terminates(self) -> None:
        from agentguard.core.sandbox import _is_docker_timeout

        error = ValueError("loop")
        error.__context__ = error
        assert not _is_docker_timeout(error)
