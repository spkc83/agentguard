"""Tests for agentguard.core.circuit_breaker — circuit breaker + rate limiter."""

from __future__ import annotations

import asyncio

import pytest
from structlog.testing import capture_logs

from agentguard.core.circuit_breaker import CircuitBreaker, CircuitState, TokenBucketRateLimiter
from agentguard.exceptions import CircuitOpenError, RateLimitExceededError


async def _succeeding_fn() -> str:
    return "ok"


async def _failing_fn() -> str:
    raise RuntimeError("boom")


class TestCircuitBreaker:
    async def test_closed_passes_through(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=1.0)
        result = await cb.call(_succeeding_fn)
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    async def test_opens_after_threshold(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=1.0)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                await cb.call(_failing_fn)
        assert cb.state == CircuitState.OPEN

    async def test_open_rejects_calls(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=60.0)
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        assert cb.state == CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            await cb.call(_succeeding_fn)

    async def test_half_open_after_timeout(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.1)
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        assert cb.state == CircuitState.OPEN
        await asyncio.sleep(0.15)
        result = await cb.call(_succeeding_fn)
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    async def test_half_open_failure_reopens(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.1)
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        await asyncio.sleep(0.15)
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        assert cb.state == CircuitState.OPEN

    async def test_success_resets_failure_count(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=1.0)
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        await cb.call(_succeeding_fn)  # resets counter
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        assert cb.state == CircuitState.CLOSED  # only 1 failure after reset

    async def test_call_with_args(self) -> None:
        async def _add(a: int, b: int) -> int:
            return a + b

        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=1.0)
        result = await cb.call(_add, 2, 3)
        assert result == 5

    async def test_before_execute_runs_after_admission_before_executor(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=1.0)
        calls: list[str] = []

        async def _before() -> None:
            calls.append("before")

        async def _execute() -> str:
            calls.append("execute")
            return "ok"

        assert await cb.call(_execute, before_execute=_before) == "ok"
        assert calls == ["before", "execute"]

    async def test_before_execute_failure_never_calls_executor(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=1.0)
        executed = False

        async def _before() -> None:
            raise RuntimeError("audit unavailable")

        async def _execute() -> str:
            nonlocal executed
            executed = True
            return "unexpected"

        with pytest.raises(RuntimeError, match="audit unavailable"):
            await cb.call(_execute, before_execute=_before)
        assert executed is False

    async def test_only_one_half_open_probe_is_admitted(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.01)
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        await asyncio.sleep(0.02)

        probe_started = asyncio.Event()
        release_probe = asyncio.Event()

        async def _probe() -> str:
            probe_started.set()
            await release_probe.wait()
            return "ok"

        first = asyncio.create_task(cb.call(_probe))
        await probe_started.wait()
        with pytest.raises(CircuitOpenError):
            await cb.call(_succeeding_fn)
        release_probe.set()
        assert await first == "ok"
        assert cb.state == CircuitState.CLOSED

    async def test_cancelled_half_open_probe_does_not_wedge_breaker(self) -> None:
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.01)
        with pytest.raises(RuntimeError):
            await cb.call(_failing_fn)
        await asyncio.sleep(0.02)

        started = asyncio.Event()

        async def _cancelled_probe() -> str:
            started.set()
            await asyncio.Future()
            return "unreachable"

        task = asyncio.create_task(cb.call(_cancelled_probe))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert cb.state == CircuitState.OPEN
        await asyncio.sleep(0.02)
        assert await cb.call(_succeeding_fn) == "ok"
        assert cb.state == CircuitState.CLOSED


class TestTokenBucketRateLimiter:
    async def test_allows_within_limit(self) -> None:
        rl = TokenBucketRateLimiter(max_tokens=5, refill_rate=10.0)
        for _ in range(5):
            await rl.acquire("agent-1")

    async def test_rejects_over_limit(self) -> None:
        rl = TokenBucketRateLimiter(max_tokens=2, refill_rate=0.0)
        await rl.acquire("agent-1")
        await rl.acquire("agent-1")
        with pytest.raises(RateLimitExceededError):
            await rl.acquire("agent-1")

    async def test_separate_buckets_per_agent(self) -> None:
        rl = TokenBucketRateLimiter(max_tokens=1, refill_rate=0.0)
        await rl.acquire("agent-1")
        await rl.acquire("agent-2")  # separate bucket, should work

    async def test_separate_buckets_per_action(self) -> None:
        rl = TokenBucketRateLimiter(max_tokens=1, refill_rate=0.0)
        await rl.acquire("agent-1", "tool:a")
        await rl.acquire("agent-1", "tool:b")
        with pytest.raises(RateLimitExceededError) as exc_info:
            await rl.acquire("agent-1", "tool:a")
        assert exc_info.value.action == "tool:a"

    async def test_refill(self) -> None:
        rl = TokenBucketRateLimiter(max_tokens=1, refill_rate=20.0)
        await rl.acquire("agent-1")
        await asyncio.sleep(0.1)  # refills ~2 tokens
        await rl.acquire("agent-1")  # should succeed after refill

    async def test_concurrent_acquires_no_over_issue(self) -> None:
        """Concurrent acquirers must not collectively exceed the bucket capacity."""
        rl = TokenBucketRateLimiter(max_tokens=10, refill_rate=0.0)
        results = await asyncio.gather(
            *(rl.acquire("agent-1") for _ in range(30)),
            return_exceptions=True,
        )
        successes = [r for r in results if r is None]
        rate_errors = [r for r in results if isinstance(r, RateLimitExceededError)]
        assert len(successes) == 10
        assert len(rate_errors) == 20


class TestCircuitBreakerConcurrent:
    async def test_concurrent_failures_open_breaker_exactly_once(self) -> None:
        """Concurrent failures must still transition to OPEN without corrupting state."""
        cb = CircuitBreaker(name="concurrent", failure_threshold=5, recovery_timeout=60.0)
        with capture_logs() as logs:
            results = await asyncio.gather(
                *(cb.call(_failing_fn) for _ in range(20)),
                return_exceptions=True,
            )
        assert cb.state == CircuitState.OPEN
        assert any(isinstance(r, RuntimeError) for r in results)
        opened = [entry for entry in logs if entry.get("event") == "circuit_breaker_opened"]
        assert len(opened) == 1
