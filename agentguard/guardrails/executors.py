"""Trusted executor references and an immutable application-owned registry."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import GuardrailPayload

TrustedExecutor = Callable[[GuardrailPayload], Awaitable[object]]


class UnknownExecutorError(LookupError):
    """Raised when no trusted executor is registered for an ID."""


class ExecutorRefMismatchError(LookupError):
    """Raised when an ID exists but the complete authenticated reference differs."""


class ExecutorRef(BaseModel):
    """Stable authenticated reference to an application-owned executor."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    executor_id: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=256)
    fingerprint: str = Field(min_length=1, max_length=256)


class RegisteredExecutor(BaseModel):
    """One trusted executor paired with its complete stable reference."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    ref: ExecutorRef
    executor: TrustedExecutor

    @field_validator("executor")
    @classmethod
    def _validate_executor(cls, value: TrustedExecutor) -> TrustedExecutor:
        if not callable(value):
            raise TypeError("executor must be callable")
        call = type(value).__call__
        if not inspect.iscoroutinefunction(value) and not inspect.iscoroutinefunction(call):
            raise ValueError("executor must be async")
        return value


@runtime_checkable
class ExecutorResolver(Protocol):
    """Resolve only application-registered executors from authenticated references."""

    def resolve(self, executor_id: str) -> RegisteredExecutor: ...


class StaticExecutorRegistry:
    """Read-only executor registry that rejects ambiguous stable IDs."""

    def __init__(self, executors: Iterable[RegisteredExecutor]) -> None:
        by_id: dict[str, RegisteredExecutor] = {}
        for registered in executors:
            if not isinstance(registered, RegisteredExecutor):
                raise TypeError("registry entries must be RegisteredExecutor instances")
            executor_id = registered.ref.executor_id
            if executor_id in by_id:
                raise ValueError(f"duplicate executor id: {executor_id}")
            by_id[executor_id] = registered
        self._by_id = MappingProxyType(by_id)

    def resolve(self, executor_id: str) -> RegisteredExecutor:
        """Resolve an ID so the caller can compare the protected complete reference."""

        try:
            return self._by_id[executor_id]
        except KeyError as exc:
            raise UnknownExecutorError(executor_id) from exc
