"""Tests for agentguard.core.circuit_breaker — circuit breaker + rate limiter."""

from __future__ import annotations

import asyncio

import pytest

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

    async def test_refill(self) -> None:
        rl = TokenBucketRateLimiter(max_tokens=1, refill_rate=20.0)
        await rl.acquire("agent-1")
        await asyncio.sleep(0.1)  # refills ~2 tokens
        await rl.acquire("agent-1")  # should succeed after refill
