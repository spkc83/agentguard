"""Circuit breaker and rate limiter for agent tool calls.

The circuit breaker protects downstream services from cascading failures.
The token bucket rate limiter enforces per-agent call frequency limits.
"""

from __future__ import annotations

import asyncio
import enum
import time
from typing import TYPE_CHECKING, Any, TypeVar

import structlog

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

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
        self._half_open_probe_in_flight = False

    @property
    def state(self) -> CircuitState:
        """Current circuit breaker state."""
        if (
            self._state == CircuitState.OPEN
            and time.monotonic() - self._last_failure_time >= self._recovery_timeout
        ):
            return CircuitState.HALF_OPEN
        return self._state

    async def call(
        self,
        fn: Callable[..., Awaitable[T]],
        *args: Any,
        before_execute: Callable[[], Awaitable[None]] | None = None,
        **kwargs: Any,
    ) -> T:
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
        half_open_probe = await self._admit()

        if before_execute is not None:
            try:
                await before_execute()
            except BaseException:
                if half_open_probe:
                    await self._abort_half_open_probe()
                raise

        try:
            result = await fn(*args, **kwargs)
        except asyncio.CancelledError:
            if half_open_probe:
                await self._abort_half_open_probe()
            raise
        except Exception:
            await self._record_failure(half_open_probe=half_open_probe)
            raise

        await self._record_success(half_open_probe=half_open_probe)
        return result

    async def _admit(self) -> bool:
        """Atomically admit a call and reserve the sole HALF_OPEN probe."""
        async with self._lock:
            now = time.monotonic()
            if self._state == CircuitState.OPEN:
                if now - self._last_failure_time < self._recovery_timeout:
                    logger.warning("circuit_breaker_rejected", breaker=self._name)
                    raise CircuitOpenError(self._name)
                if self._half_open_probe_in_flight:
                    logger.warning("circuit_breaker_rejected", breaker=self._name)
                    raise CircuitOpenError(self._name)
                self._state = CircuitState.HALF_OPEN
                self._half_open_probe_in_flight = True
                return True

            if self._state == CircuitState.HALF_OPEN:
                logger.warning("circuit_breaker_rejected", breaker=self._name)
                raise CircuitOpenError(self._name)

            return False

    async def _abort_half_open_probe(self) -> None:
        """Return an admitted but unexecuted probe to OPEN backoff."""
        async with self._lock:
            self._half_open_probe_in_flight = False
            self._state = CircuitState.OPEN
            self._last_failure_time = time.monotonic()

    async def _record_failure(self, *, half_open_probe: bool) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if half_open_probe:
                self._half_open_probe_in_flight = False
            if self._failure_count >= self._failure_threshold and self._state != CircuitState.OPEN:
                self._state = CircuitState.OPEN
                logger.warning(
                    "circuit_breaker_opened",
                    breaker=self._name,
                    failures=self._failure_count,
                )

    async def _record_success(self, *, half_open_probe: bool) -> None:
        async with self._lock:
            if half_open_probe:
                self._half_open_probe_in_flight = False
                self._failure_count = 0
                self._state = CircuitState.CLOSED
                logger.info("circuit_breaker_closed", breaker=self._name)
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0


class TokenBucketRateLimiter:
    """Per-agent token bucket rate limiter.

    Args:
        max_tokens: Maximum tokens in the bucket (burst capacity).
        refill_rate: Tokens added per second.
    """

    def __init__(self, max_tokens: float, refill_rate: float) -> None:
        self._max_tokens = max_tokens
        self._refill_rate = refill_rate
        self._buckets: dict[tuple[str, str | None], tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, agent_id: str, action: str | None = None) -> None:
        """Consume one token for the given agent.

        Raises:
            RateLimitExceededError: If the agent's bucket is empty.
        """
        async with self._lock:
            now = time.monotonic()
            key = (agent_id, action)
            tokens, last_time = self._buckets.get(key, (self._max_tokens, now))

            # Refill tokens based on elapsed time
            elapsed = now - last_time
            tokens = min(self._max_tokens, tokens + elapsed * self._refill_rate)

            if tokens < 1.0:
                raise RateLimitExceededError(agent_id, self._refill_rate, action)

            self._buckets[key] = (tokens - 1.0, now)
