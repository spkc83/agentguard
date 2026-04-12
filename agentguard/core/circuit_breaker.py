"""Circuit breaker and rate limiter for agent tool calls.

The circuit breaker protects downstream services from cascading failures.
The token bucket rate limiter enforces per-agent call frequency limits.
"""

from __future__ import annotations

import asyncio
import enum
import time
from typing import Any, Awaitable, Callable, TypeVar

import structlog

from agentguard.exceptions import CircuitOpenError, RateLimitExceededError

logger = structlog.get_logger()

T = TypeVar("T")


class CircuitState(enum.Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker with three states: CLOSED, OPEN, HALF_OPEN.

    Args:
        name: Identifier for this breaker (used in logs and errors).
        failure_threshold: Consecutive failures before opening.
        recovery_timeout: Seconds to wait in OPEN before trying HALF_OPEN.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> None:
        self._name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Current circuit breaker state."""
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self._recovery_timeout:
                return CircuitState.HALF_OPEN
        return self._state

    async def call(self, fn: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
        """Execute a function through the circuit breaker.

        Args:
            fn: Async callable to execute.
            *args: Positional arguments for fn.
            **kwargs: Keyword arguments for fn.

        Returns:
            The result of fn(*args, **kwargs).

        Raises:
            CircuitOpenError: If the breaker is OPEN and recovery timeout hasn't elapsed.
        """
        current_state = self.state

        if current_state == CircuitState.OPEN:
            logger.warning("circuit_breaker_rejected", breaker=self._name)
            raise CircuitOpenError(self._name)

        try:
            result = await fn(*args, **kwargs)
        except Exception:
            await self._record_failure()
            raise

        await self._record_success()
        return result

    async def _record_failure(self) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self._failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(
                    "circuit_breaker_opened",
                    breaker=self._name,
                    failures=self._failure_count,
                )

    async def _record_success(self) -> None:
        async with self._lock:
            self._failure_count = 0
            if self._state in (CircuitState.HALF_OPEN, CircuitState.OPEN):
                self._state = CircuitState.CLOSED
                logger.info("circuit_breaker_closed", breaker=self._name)


class TokenBucketRateLimiter:
    """Per-agent token bucket rate limiter.

    Args:
        max_tokens: Maximum tokens in the bucket (burst capacity).
        refill_rate: Tokens added per second.
    """

    def __init__(self, max_tokens: float, refill_rate: float) -> None:
        self._max_tokens = max_tokens
        self._refill_rate = refill_rate
        self._buckets: dict[str, tuple[float, float]] = {}  # agent_id -> (tokens, last_time)
        self._lock = asyncio.Lock()

    async def acquire(self, agent_id: str) -> None:
        """Consume one token for the given agent.

        Raises:
            RateLimitExceededError: If the agent's bucket is empty.
        """
        async with self._lock:
            now = time.monotonic()
            tokens, last_time = self._buckets.get(agent_id, (self._max_tokens, now))

            # Refill tokens based on elapsed time
            elapsed = now - last_time
            tokens = min(self._max_tokens, tokens + elapsed * self._refill_rate)

            if tokens < 1.0:
                raise RateLimitExceededError(agent_id, self._refill_rate)

            self._buckets[agent_id] = (tokens - 1.0, now)
