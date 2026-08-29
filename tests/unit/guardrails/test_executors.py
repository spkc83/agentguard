from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentguard.guardrails import (
    ExecutorRef,
    ExecutorResolver,
    RegisteredExecutor,
    StaticExecutorRegistry,
    ToolCallPayload,
    UnknownExecutorError,
)


async def _execute(payload: object) -> object:
    return payload


def test_executor_ref_and_registration_are_frozen_exact_contracts() -> None:
    reference = ExecutorRef(executor_id="search", version="1", fingerprint="a" * 64)
    registered = RegisteredExecutor(ref=reference, executor=_execute)

    assert registered.ref == reference
    with pytest.raises(ValidationError):
        ExecutorRef(executor_id="search", version="1", fingerprint="a" * 64, extra=True)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        reference.version = "2"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="executor must be async"):
        RegisteredExecutor(ref=reference, executor=lambda payload: payload)  # type: ignore[arg-type]


def test_static_registry_resolves_only_the_full_registered_reference() -> None:
    registered = RegisteredExecutor(
        ref=ExecutorRef(executor_id="search", version="1", fingerprint="a" * 64),
        executor=_execute,
    )
    registry = StaticExecutorRegistry((registered,))

    assert isinstance(registry, ExecutorResolver)
    assert registry.resolve(registered.ref.executor_id) is registered
    mismatched = ExecutorRef(executor_id="search", version="2", fingerprint="b" * 64)
    assert registry.resolve(mismatched.executor_id).ref != mismatched
    with pytest.raises(UnknownExecutorError):
        registry.resolve("unknown")


def test_static_registry_rejects_duplicate_stable_ids() -> None:
    with pytest.raises(ValueError, match="duplicate executor id"):
        StaticExecutorRegistry(
            (
                RegisteredExecutor(
                    ref=ExecutorRef(executor_id="search", version="1", fingerprint="a" * 64),
                    executor=_execute,
                ),
                RegisteredExecutor(
                    ref=ExecutorRef(executor_id="search", version="2", fingerprint="b" * 64),
                    executor=_execute,
                ),
            )
        )


@pytest.mark.asyncio
async def test_registered_executor_accepts_immutable_governed_payload() -> None:
    registered = RegisteredExecutor(
        ref=ExecutorRef(executor_id="search", version="1", fingerprint="a" * 64),
        executor=_execute,
    )
    payload = ToolCallPayload(arguments={"query": "safe"})

    assert await registered.executor(payload) is payload
