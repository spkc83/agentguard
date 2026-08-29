from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import pytest

from agentguard.guardrails import (
    ChainCursor,
    ChainMode,
    Decision,
    GuardrailChain,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    IdentitySnapshot,
    MessagePayload,
    ToolCallPayload,
)
from agentguard.guardrails.reason_codes import (
    GUARDRAIL_INTERNAL_ERROR,
    GUARDRAIL_TIMEOUT,
)


class StubGuardrail:
    version = "1"

    def __init__(
        self,
        guardrail_id: str,
        result: Decision | Callable[[GuardrailContext], Awaitable[Decision]],
        *,
        stages: frozenset[GuardrailStage] | None = None,
        timeout_ms: int | None = None,
    ) -> None:
        self.id = guardrail_id
        self.stages = frozenset({GuardrailStage.INPUT}) if stages is None else stages
        self.result = result
        self.calls: list[GuardrailContext] = []
        if timeout_ms is not None:
            self.timeout_ms = timeout_ms
        self.resume_fingerprint = f"test:{guardrail_id}:v1"

    async def evaluate(self, context: GuardrailContext) -> Decision:
        self.calls.append(context)
        if callable(self.result):
            return await self.result(context)
        return self.result


def _context() -> GuardrailContext:
    return GuardrailContext(
        trace_id="trace",
        invocation_id="invocation",
        stage=GuardrailStage.INPUT,
        identity=IdentitySnapshot(agent_id="agent", name="Agent"),
        action="tool:call",
        resource="resource",
        payload=ToolCallPayload(arguments={"value": "raw"}),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("effect", "reason_codes", "blocked", "expected_calls"),
    [
        (GuardrailEffect.ALLOW, (), False, 2),
        (GuardrailEffect.WARN, (), False, 2),
        (GuardrailEffect.DENY, ("TEST.DENIED",), True, 1),
        (GuardrailEffect.ESCALATE, ("TEST.ESCALATED",), True, 1),
    ],
)
async def test_enforce_semantics_for_non_transform_decisions(
    effect: GuardrailEffect,
    reason_codes: tuple[str, ...],
    blocked: bool,
    expected_calls: int,
) -> None:
    first = StubGuardrail("first", Decision(effect=effect, reason_codes=reason_codes))
    second = StubGuardrail("second", Decision(effect=GuardrailEffect.ALLOW))

    result = await GuardrailChain([first, second]).run(_context())

    assert result.blocked is blocked
    assert len(result.decisions) == expected_calls
    assert len(first.calls) == 1
    assert len(second.calls) == expected_calls - 1
    assert result.terminal_decision is (result.decisions[-1] if blocked else None)
    assert all(item.enforced for item in result.decisions)
    assert all(item.duration_ms >= 0 for item in result.decisions)


@pytest.mark.asyncio
async def test_enforce_transform_propagates_same_kind_payload_and_prior_decisions() -> None:
    replacement = ToolCallPayload(arguments={"value": "masked"})
    transform = Decision(
        effect=GuardrailEffect.TRANSFORM,
        reason_codes=("TEST.TRANSFORMED",),
        replacement_payload=replacement,
    )
    first = StubGuardrail("transform", transform)
    second = StubGuardrail("observer", Decision(effect=GuardrailEffect.ALLOW))

    result = await GuardrailChain([first, second]).run(_context())

    assert result.payload == replacement
    assert second.calls[0].payload == replacement
    assert second.calls[0].prior == (transform,)
    assert [item.decision for item in result.decisions] == [
        transform,
        Decision(effect=GuardrailEffect.ALLOW),
    ]


@pytest.mark.asyncio
async def test_chain_filters_stages_without_reordering_applicable_guardrails() -> None:
    order: list[str] = []

    def evaluator(name: str) -> Callable[[GuardrailContext], Awaitable[Decision]]:
        async def evaluate(context: GuardrailContext) -> Decision:
            order.append(name)
            return Decision(effect=GuardrailEffect.ALLOW)

        return evaluate

    first = StubGuardrail("first", evaluator("first"))
    skipped = StubGuardrail(
        "skipped",
        evaluator("skipped"),
        stages=frozenset({GuardrailStage.POST_TOOL}),
    )
    third = StubGuardrail("third", evaluator("third"))

    await GuardrailChain([first, skipped, third]).run(_context())

    assert order == ["first", "third"]
    assert skipped.calls == []


@pytest.mark.asyncio
async def test_shadow_runs_every_guardrail_without_transforming_or_blocking() -> None:
    original = _context()
    replacement = ToolCallPayload(arguments={"value": "masked"})
    transform = Decision(
        effect=GuardrailEffect.TRANSFORM,
        replacement_payload=replacement,
    )
    guardrails = [
        StubGuardrail("transform", transform),
        StubGuardrail(
            "deny",
            Decision(effect=GuardrailEffect.DENY, reason_codes=("TEST.DENIED",)),
        ),
        StubGuardrail("allow", Decision(effect=GuardrailEffect.ALLOW)),
    ]

    result = await GuardrailChain(guardrails, mode=ChainMode.SHADOW).run(original)

    assert not result.blocked
    assert not result.enforced
    assert result.payload == original.payload
    assert result.terminal_decision is None
    assert len(result.decisions) == 3
    assert guardrails[1].calls[0].payload == original.payload
    assert guardrails[2].calls[0].prior == tuple(item.decision for item in result.decisions[:2])
    assert all(not item.enforced for item in result.decisions)


@pytest.mark.asyncio
async def test_off_skips_all_evaluation() -> None:
    guardrail = StubGuardrail(
        "guardrail",
        Decision(effect=GuardrailEffect.DENY, reason_codes=("TEST.DENIED",)),
    )
    context = _context()

    result = await GuardrailChain([guardrail], mode=ChainMode.OFF).run(context)

    assert result.payload == context.payload
    assert result.decisions == ()
    assert not result.blocked
    assert guardrail.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "reason_code"),
    [("exception", GUARDRAIL_INTERNAL_ERROR), ("timeout", GUARDRAIL_TIMEOUT)],
)
async def test_evaluation_failures_become_fail_closed_denials(
    failure: str,
    reason_code: str,
) -> None:
    async def fail(context: GuardrailContext) -> Decision:
        if failure == "exception":
            raise RuntimeError("boom")
        await asyncio.sleep(1)
        return Decision(effect=GuardrailEffect.ALLOW)

    failing = StubGuardrail("failing", fail)
    after = StubGuardrail("after", Decision(effect=GuardrailEffect.ALLOW))

    result = await GuardrailChain([failing, after], timeout_ms=5).run(_context())

    assert result.blocked
    assert result.terminal_decision is not None
    assert result.terminal_decision.decision.effect is GuardrailEffect.DENY
    assert result.terminal_decision.decision.reason_codes == (reason_code,)
    assert after.calls == []


@pytest.mark.asyncio
async def test_chain_timeout_caps_a_longer_guardrail_timeout() -> None:
    async def slow(context: GuardrailContext) -> Decision:
        await asyncio.sleep(1)
        return Decision(effect=GuardrailEffect.ALLOW)

    result = await GuardrailChain(
        [StubGuardrail("slow", slow, timeout_ms=10_000)],
        timeout_ms=5,
    ).run(_context())

    assert result.terminal_decision is not None
    assert result.terminal_decision.decision.reason_codes == (GUARDRAIL_TIMEOUT,)


@pytest.mark.asyncio
async def test_invalid_cross_kind_transform_fails_closed() -> None:
    cross_kind = Decision(
        effect=GuardrailEffect.TRANSFORM,
        replacement_payload=MessagePayload(message="not a tool call"),
    )

    result = await GuardrailChain([StubGuardrail("invalid", cross_kind)]).run(_context())

    assert result.blocked
    assert result.payload == _context().payload
    assert result.terminal_decision is not None
    assert result.terminal_decision.decision.reason_codes == (GUARDRAIL_INTERNAL_ERROR,)


@pytest.mark.asyncio
async def test_external_cancellation_propagates() -> None:
    async def wait_forever(context: GuardrailContext) -> Decision:
        await asyncio.Event().wait()
        return Decision(effect=GuardrailEffect.ALLOW)

    task = asyncio.create_task(
        GuardrailChain([StubGuardrail("waiting", wait_forever)]).run(_context())
    )
    await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_context_prior_precedes_current_chain_decisions() -> None:
    prior = Decision(effect=GuardrailEffect.WARN)
    context = _context().model_copy(update={"prior": (prior,)})
    observed: list[tuple[Decision, ...]] = []

    async def capture(current: GuardrailContext) -> Decision:
        observed.append(current.prior)
        return Decision(effect=GuardrailEffect.ALLOW)

    await GuardrailChain([StubGuardrail("first", capture), StubGuardrail("second", capture)]).run(
        context
    )

    assert observed == [(prior,), (prior, Decision(effect=GuardrailEffect.ALLOW))]


def test_decision_alias_and_chain_result_are_immutable() -> None:
    decision = Decision(effect=GuardrailEffect.ALLOW)

    assert isinstance(decision, GuardrailOutcome)
    with pytest.raises(Exception):
        decision.effect = GuardrailEffect.DENY


@pytest.mark.parametrize("timeout_ms", [0, -1, True, 1.5])
def test_chain_rejects_invalid_timeout(timeout_ms: object) -> None:
    with pytest.raises(ValueError, match="positive"):
        GuardrailChain([], timeout_ms=timeout_ms)  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout_ms", [0, -1, True])
def test_chain_rejects_invalid_guardrail_timeout(timeout_ms: int) -> None:
    guardrail = StubGuardrail(
        "guardrail",
        Decision(effect=GuardrailEffect.ALLOW),
        timeout_ms=timeout_ms,
    )

    with pytest.raises(ValueError, match="timeout_ms"):
        GuardrailChain([guardrail])


def test_chain_rejects_duplicate_ids_and_empty_stages() -> None:
    decision = Decision(effect=GuardrailEffect.ALLOW)
    with pytest.raises(ValueError, match="duplicate"):
        GuardrailChain([StubGuardrail("same", decision), StubGuardrail("same", decision)])
    with pytest.raises(ValueError, match="stage"):
        GuardrailChain([StubGuardrail("empty", decision, stages=frozenset())])


@pytest.mark.parametrize(
    ("attribute", "value", "match"),
    [
        ("id", 7, "id"),
        ("id", "   ", "id"),
        ("version", 1, "version"),
        ("version", "", "version"),
        ("stages", frozenset({"bogus"}), "stages"),
        ("resume_fingerprint", "", "resume_fingerprint"),
    ],
)
def test_chain_rejects_malformed_guardrail_descriptors(
    attribute: str,
    value: object,
    match: str,
) -> None:
    guardrail = StubGuardrail("guardrail", Decision(effect=GuardrailEffect.ALLOW))
    setattr(guardrail, attribute, value)

    with pytest.raises(ValueError, match=match):
        GuardrailChain([guardrail])


@pytest.mark.asyncio
async def test_chain_snapshots_mutable_guardrail_descriptors() -> None:
    guardrail = StubGuardrail("stable", Decision(effect=GuardrailEffect.ALLOW))
    chain = GuardrailChain([guardrail])
    guardrail.id = "changed"
    guardrail.version = "changed"
    guardrail.stages = frozenset({GuardrailStage.POST_TOOL})
    guardrail.timeout_ms = 0

    result = await chain.run(_context())

    assert len(result.decisions) == 1
    assert result.decisions[0].guardrail_id == "stable"
    assert result.decisions[0].guardrail_version == "1"


@pytest.mark.asyncio
async def test_non_yielding_guardrail_overrun_is_classified_after_return() -> None:
    async def busy(context: GuardrailContext) -> Decision:
        loop = asyncio.get_running_loop()
        started = loop.time()
        while loop.time() - started < 0.01:
            pass
        return Decision(effect=GuardrailEffect.ALLOW)

    result = await GuardrailChain(
        [StubGuardrail("busy", busy, timeout_ms=1)],
        timeout_ms=100,
    ).run(_context())

    assert result.blocked
    assert result.terminal_decision is not None
    assert result.terminal_decision.decision.reason_codes == (GUARDRAIL_TIMEOUT,)


def test_chain_descriptor_and_fingerprint_bind_effective_order_and_config() -> None:
    first = StubGuardrail("first", Decision(effect=GuardrailEffect.ALLOW), timeout_ms=50)
    first.config = {"threshold": 3}
    second = StubGuardrail(
        "second",
        Decision(effect=GuardrailEffect.ALLOW),
        stages=frozenset({GuardrailStage.POST_TOOL, GuardrailStage.INPUT}),
    )
    chain = GuardrailChain([first, second], mode=ChainMode.SHADOW, timeout_ms=75)

    assert chain.descriptor.mode is ChainMode.SHADOW
    assert chain.descriptor.timeout_ms == 75
    assert chain.descriptor.guardrails[0].model_dump(mode="json") == {
        "guardrail_id": "first",
        "guardrail_version": "1",
        "stages": ["input"],
        "timeout_ms": 50,
        "resume_fingerprint": "test:first:v1",
        "config": {"threshold": 3},
    }
    assert chain.descriptor.guardrails[1].stages == (
        GuardrailStage.INPUT,
        GuardrailStage.POST_TOOL,
    )
    assert len(chain.fingerprint) == 64
    assert (
        chain.fingerprint
        == GuardrailChain([first, second], mode=ChainMode.SHADOW, timeout_ms=75).fingerprint
    )
    assert (
        chain.fingerprint
        != GuardrailChain([second, first], mode=ChainMode.SHADOW, timeout_ms=75).fingerprint
    )
    assert (
        chain.fingerprint
        != GuardrailChain([first, second], mode=ChainMode.ENFORCE, timeout_ms=75).fingerprint
    )
    assert (
        chain.fingerprint
        != GuardrailChain([first, second], mode=ChainMode.SHADOW, timeout_ms=76).fingerprint
    )

    first.config["threshold"] = 4
    assert chain.descriptor.guardrails[0].config == {"threshold": 3}
    assert (
        chain.fingerprint
        != GuardrailChain([first, second], mode=ChainMode.SHADOW, timeout_ms=75).fingerprint
    )

    first.config["threshold"] = 3
    first.version = "2"
    assert (
        chain.fingerprint
        != GuardrailChain([first, second], mode=ChainMode.SHADOW, timeout_ms=75).fingerprint
    )

    first.version = "1"
    first.stages = frozenset({GuardrailStage.PRE_TOOL})
    assert (
        chain.fingerprint
        != GuardrailChain([first, second], mode=ChainMode.SHADOW, timeout_ms=75).fingerprint
    )

    first.stages = frozenset({GuardrailStage.INPUT})
    first.resume_fingerprint = "changed-semantic-binding"
    assert (
        chain.fingerprint
        != GuardrailChain([first, second], mode=ChainMode.SHADOW, timeout_ms=75).fingerprint
    )


@pytest.mark.asyncio
async def test_resume_starts_after_escalation_with_prior_and_transformed_payload() -> None:
    replacement = ToolCallPayload(arguments={"value": "masked"})
    transform = Decision(
        effect=GuardrailEffect.TRANSFORM,
        replacement_payload=replacement,
    )
    escalation = Decision(
        effect=GuardrailEffect.ESCALATE,
        reason_codes=("TEST.ESCALATED",),
    )
    first = StubGuardrail("transform", transform)
    skipped = StubGuardrail(
        "skipped",
        Decision(effect=GuardrailEffect.ALLOW),
        stages=frozenset({GuardrailStage.POST_TOOL}),
    )
    trigger = StubGuardrail("approval", escalation)
    after = StubGuardrail("after", Decision(effect=GuardrailEffect.ALLOW))
    chain = GuardrailChain([first, skipped, trigger, after])

    initial = await chain.run(_context())

    assert initial.cursor is not None
    assert initial.cursor.next_entry_index == 3
    assert initial.cursor.triggering_guardrail_id == "approval"
    assert initial.cursor.triggering_guardrail_version == "1"
    resumed = await chain.resume(_context(), initial.cursor)

    assert len(first.calls) == 1
    assert skipped.calls == []
    assert len(trigger.calls) == 1
    assert len(after.calls) == 1
    assert after.calls[0].payload == replacement
    assert after.calls[0].prior == (transform, escalation)
    assert resumed.payload == replacement
    assert resumed.decisions[: len(initial.decisions)] == initial.decisions
    assert resumed.decisions[-1].guardrail_id == "after"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mismatch",
    ["fingerprint", "stage", "index", "triggering guardrail", "payload"],
)
async def test_resume_rejects_cursor_mismatch(mismatch: str) -> None:
    trigger = StubGuardrail(
        "approval",
        Decision(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("TEST.ESCALATED",),
        ),
    )
    skipped = StubGuardrail(
        "skipped",
        Decision(effect=GuardrailEffect.ALLOW),
        stages=frozenset({GuardrailStage.POST_TOOL}),
    )
    after = StubGuardrail("after", Decision(effect=GuardrailEffect.ALLOW))
    chain = GuardrailChain([trigger, skipped, after])
    initial = await chain.run(_context())
    assert initial.cursor is not None
    update: dict[str, object]
    if mismatch == "fingerprint":
        update = {"chain_fingerprint": "0" * 64}
    elif mismatch == "stage":
        update = {"stage": GuardrailStage.POST_TOOL}
    elif mismatch == "index":
        update = {"next_entry_index": 2}
    elif mismatch == "triggering guardrail":
        update = {"triggering_guardrail_id": "other"}
    else:
        update = {"payload": ToolCallPayload(arguments={"value": "tampered"})}
    invalid = initial.cursor.model_copy(update=update)

    with pytest.raises(ValueError, match=mismatch):
        await chain.resume(_context(), invalid)

    assert after.calls == []


def test_cursor_is_immutable() -> None:
    cursor = ChainCursor(
        chain_fingerprint="0" * 64,
        stage=GuardrailStage.INPUT,
        next_entry_index=1,
        triggering_guardrail_id="approval",
        triggering_guardrail_version="1",
        decisions=(),
        payload=_context().payload,
    )

    with pytest.raises(Exception):
        cursor.next_entry_index = 2


@pytest.mark.asyncio
async def test_chain_without_explicit_semantic_binding_does_not_issue_cursor() -> None:
    trigger = StubGuardrail(
        "approval",
        Decision(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("TEST.ESCALATED",),
        ),
    )
    del trigger.resume_fingerprint
    chain = GuardrailChain([trigger])

    result = await chain.run(_context())

    assert not chain.resumable
    assert not chain.is_resumable(GuardrailStage.INPUT)
    assert result.cursor is None


@pytest.mark.asyncio
async def test_nonapplicable_unbound_guardrail_disables_complete_lifecycle_resume() -> None:
    applicable = StubGuardrail(
        "input",
        Decision(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("TEST.ESCALATED",),
        ),
    )
    unrelated = StubGuardrail(
        "post",
        Decision(effect=GuardrailEffect.ALLOW),
        stages=frozenset({GuardrailStage.POST_TOOL}),
    )
    del unrelated.resume_fingerprint
    chain = GuardrailChain([applicable, unrelated])

    assert not chain.resumable
    assert chain.is_resumable(GuardrailStage.INPUT)
    assert not chain.is_resumable(GuardrailStage.POST_TOOL)
    assert (await chain.run(_context())).cursor is None
