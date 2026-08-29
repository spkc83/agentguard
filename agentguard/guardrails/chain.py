"""Ordered, bounded execution of framework-independent guardrails."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from time import monotonic
from typing import TYPE_CHECKING, Any

from pydantic import field_serializer, field_validator

if TYPE_CHECKING:
    from collections.abc import Iterable

from .contracts import (
    Decision,
    Guardrail,
    GuardrailContext,
    GuardrailEffect,
    GuardrailPayload,
    GuardrailStage,
    _FrozenModel,
    validate_obligations,
    validate_transformation,
)
from .normalization import _FrozenMapping, canonical_json_bytes, normalize_payload, thaw_payload
from .reason_codes import GUARDRAIL_INTERNAL_ERROR, GUARDRAIL_TIMEOUT

_DEFAULT_TIMEOUT_MS = 1_000


@dataclass(frozen=True, slots=True)
class _GuardrailEntry:
    guardrail: Guardrail
    guardrail_id: str
    guardrail_version: str
    stages: frozenset[GuardrailStage]
    timeout_ms: int
    resume_fingerprint: str | None


class ChainMode(StrEnum):
    """Runtime enforcement mode for a guardrail chain."""

    ENFORCE = "enforce"
    SHADOW = "shadow"
    OFF = "off"


class EvaluatedDecision(_FrozenModel):
    """A decision annotated by the chain rather than trusted guardrail output."""

    guardrail_id: str
    guardrail_version: str
    decision: Decision
    duration_ms: float
    enforced: bool

    @field_validator("duration_ms")
    @classmethod
    def _validate_duration(cls, value: float) -> float:
        if value < 0:
            raise ValueError("duration_ms cannot be negative")
        return value


class GuardrailDescriptor(_FrozenModel):
    """Canonical, immutable identity of one configured chain entry."""

    guardrail_id: str
    guardrail_version: str
    stages: tuple[GuardrailStage, ...]
    timeout_ms: int
    resume_fingerprint: str | None = None
    config: _FrozenMapping = _FrozenMapping({})

    @field_validator("config", mode="before")
    @classmethod
    def _freeze_config(cls, value: object) -> _FrozenMapping:
        normalized = normalize_payload(value)
        if not isinstance(normalized, _FrozenMapping):
            raise TypeError("guardrail config must be a mapping")
        return normalized

    @field_serializer("config", when_used="json")
    def _serialize_config(self, value: _FrozenMapping) -> object:
        return thaw_payload(value)


class ChainDescriptor(_FrozenModel):
    """Canonical effective configuration of an ordered guardrail chain."""

    schema_version: int = 1
    mode: ChainMode
    timeout_ms: int
    guardrails: tuple[GuardrailDescriptor, ...]


class ChainCursor(_FrozenModel):
    """Authenticated continuation position for a stopped chain evaluation."""

    chain_fingerprint: str
    stage: GuardrailStage
    next_entry_index: int
    triggering_guardrail_id: str
    triggering_guardrail_version: str
    approved_escalation_indexes: tuple[int, ...] = ()
    decisions: tuple[EvaluatedDecision, ...]
    payload: GuardrailPayload

    @field_validator("chain_fingerprint")
    @classmethod
    def _validate_fingerprint(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("chain_fingerprint must be a lowercase SHA-256 digest")
        return value

    @field_validator("next_entry_index")
    @classmethod
    def _validate_next_entry_index(cls, value: int) -> int:
        if isinstance(value, bool) or value < 0:
            raise ValueError("next_entry_index cannot be negative")
        return value

    @field_validator("approved_escalation_indexes")
    @classmethod
    def _validate_approved_indexes(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(isinstance(index, bool) or index < 0 for index in value):
            raise ValueError("approved escalation indexes cannot be negative")
        if tuple(sorted(set(value))) != value:
            raise ValueError("approved escalation indexes must be unique and ordered")
        return value


class ChainResult(_FrozenModel):
    """Immutable aggregate of one guardrail-chain evaluation."""

    mode: ChainMode
    decisions: tuple[EvaluatedDecision, ...] = ()
    payload: GuardrailPayload
    terminal_decision: EvaluatedDecision | None = None
    cursor: ChainCursor | None = None

    @property
    def blocked(self) -> bool:
        """Whether enforcement stopped delivery or execution."""

        return self.terminal_decision is not None

    @property
    def enforced(self) -> bool:
        """Whether decisions were applied to runtime behavior."""

        return self.mode is ChainMode.ENFORCE


class GuardrailChain:
    """Run guardrails in order with fail-closed cooperative async deadlines.

    Guardrails must yield control and move blocking work behind their own
    bounded process or thread boundary. Python cannot preempt a coroutine that
    never yields; an eventual overrun is still classified as a timeout.
    """

    def __init__(
        self,
        guardrails: Iterable[Guardrail],
        *,
        mode: ChainMode = ChainMode.ENFORCE,
        timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    ) -> None:
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise ValueError("timeout_ms must be a positive integer")
        self._guardrails = tuple(guardrails)
        self._timeout_ms = timeout_ms
        self._mode = ChainMode(mode)
        self._entries = self._snapshot_guardrails()
        self._descriptor = ChainDescriptor(
            mode=self._mode,
            timeout_ms=self._timeout_ms,
            guardrails=tuple(
                _entry_descriptor(entry, chain_timeout_ms=self._timeout_ms)
                for entry in self._entries
            ),
        )
        self._fingerprint = hashlib.sha256(
            canonical_json_bytes(self._descriptor.model_dump(mode="json"))
        ).hexdigest()

    @property
    def mode(self) -> ChainMode:
        return self._mode

    @property
    def guardrails(self) -> tuple[Guardrail, ...]:
        return self._guardrails

    @property
    def descriptor(self) -> ChainDescriptor:
        """Return the immutable canonical effective chain configuration."""

        return self._descriptor

    @property
    def fingerprint(self) -> str:
        """Return the SHA-256 identity of :attr:`descriptor`."""

        return self._fingerprint

    @property
    def resumable(self) -> bool:
        """Whether every chain entry has an explicit semantic resume binding."""

        return all(entry.resume_fingerprint is not None for entry in self._entries)

    def is_resumable(self, stage: GuardrailStage) -> bool:
        """Whether all entries applicable to ``stage`` are restart-resumable."""

        return all(
            entry.resume_fingerprint is not None for entry in self._entries if stage in entry.stages
        )

    async def run(self, context: GuardrailContext) -> ChainResult:
        """Evaluate the chain for ``context`` according to the configured mode."""

        if self._mode is ChainMode.OFF:
            return ChainResult(mode=self._mode, payload=context.payload)

        return await self._run_from(
            context,
            start_index=0,
            decisions=(),
            current_payload=context.payload,
            approved_escalation_indexes=(),
        )

    async def resume(self, context: GuardrailContext, cursor: ChainCursor) -> ChainResult:
        """Continue after the escalation represented by a validated ``cursor``."""

        self._validate_cursor(context, cursor)
        return await self._run_from(
            context,
            start_index=cursor.next_entry_index,
            decisions=cursor.decisions,
            current_payload=cursor.payload,
            approved_escalation_indexes=(
                *cursor.approved_escalation_indexes,
                cursor.next_entry_index - 1,
            ),
        )

    def validate_cursor(self, context: GuardrailContext, cursor: ChainCursor) -> None:
        """Validate an authenticated cursor without executing a guardrail."""

        self._validate_cursor(context, cursor)

    async def _run_from(
        self,
        context: GuardrailContext,
        *,
        start_index: int,
        decisions: tuple[EvaluatedDecision, ...],
        current_payload: GuardrailPayload,
        approved_escalation_indexes: tuple[int, ...],
    ) -> ChainResult:
        evaluated_decisions = list(decisions)

        for entry_index in range(start_index, len(self._entries)):
            entry = self._entries[entry_index]
            if context.stage not in entry.stages:
                continue

            evaluation_context = context.model_copy(
                update={
                    "payload": current_payload,
                    "prior": (
                        *context.prior,
                        *(item.decision for item in evaluated_decisions),
                    ),
                }
            )
            decision, duration_ms = await self._evaluate(entry, evaluation_context)
            decision = self._validated_decision(decision, evaluation_context)
            evaluated = EvaluatedDecision(
                guardrail_id=entry.guardrail_id,
                guardrail_version=entry.guardrail_version,
                decision=decision,
                duration_ms=duration_ms,
                enforced=self._mode is ChainMode.ENFORCE,
            )
            evaluated_decisions.append(evaluated)

            if self._mode is ChainMode.SHADOW:
                continue
            if decision.effect is GuardrailEffect.TRANSFORM:
                replacement = decision.replacement_payload
                if replacement is not None:
                    current_payload = replacement
            elif decision.effect in {GuardrailEffect.DENY, GuardrailEffect.ESCALATE}:
                return ChainResult(
                    mode=self._mode,
                    decisions=tuple(evaluated_decisions),
                    payload=current_payload,
                    terminal_decision=evaluated,
                    cursor=(
                        ChainCursor(
                            chain_fingerprint=self._fingerprint,
                            stage=context.stage,
                            next_entry_index=entry_index + 1,
                            triggering_guardrail_id=entry.guardrail_id,
                            triggering_guardrail_version=entry.guardrail_version,
                            approved_escalation_indexes=approved_escalation_indexes,
                            decisions=tuple(evaluated_decisions),
                            payload=current_payload,
                        )
                        if decision.effect is GuardrailEffect.ESCALATE and self.resumable
                        else None
                    ),
                )

        return ChainResult(
            mode=self._mode,
            decisions=tuple(evaluated_decisions),
            payload=current_payload,
        )

    def _validate_cursor(self, context: GuardrailContext, cursor: ChainCursor) -> None:
        if self._mode is not ChainMode.ENFORCE:
            raise ValueError("cursor mode mismatch: only enforce chains can resume")
        if not self.resumable:
            raise ValueError("chain is not resumable")
        if cursor.chain_fingerprint != self._fingerprint:
            raise ValueError("cursor fingerprint mismatch")
        if cursor.stage is not context.stage:
            raise ValueError("cursor stage mismatch")
        if type(cursor.payload) is not type(context.payload):
            raise ValueError("cursor payload kind mismatch")
        index = cursor.next_entry_index
        if index <= 0 or index > len(self._entries):
            raise ValueError("cursor index mismatch")

        applicable_indexes = [
            entry_index
            for entry_index, entry in enumerate(self._entries[:index])
            if context.stage in entry.stages
        ]
        applicable = [self._entries[entry_index] for entry_index in applicable_indexes]
        if len(applicable) != len(cursor.decisions):
            raise ValueError("cursor index mismatch")
        for entry, evaluated in zip(applicable, cursor.decisions, strict=True):
            if (
                entry.guardrail_id != evaluated.guardrail_id
                or entry.guardrail_version != evaluated.guardrail_version
                or not evaluated.enforced
            ):
                raise ValueError("cursor index mismatch")
        approved_indexes = set(cursor.approved_escalation_indexes)
        if any(index >= cursor.next_entry_index - 1 for index in approved_indexes):
            raise ValueError("cursor index mismatch: approved escalation position is invalid")
        for position, (entry_index, evaluated) in enumerate(
            zip(applicable_indexes, cursor.decisions, strict=True)
        ):
            effect = evaluated.decision.effect
            if effect is GuardrailEffect.DENY:
                raise ValueError("cursor index mismatch: earlier decision was terminal")
            if (
                effect is GuardrailEffect.ESCALATE
                and entry_index not in approved_indexes
                and position != len(cursor.decisions) - 1
            ):
                raise ValueError("cursor index mismatch: escalation was not approved")
        for approved_index in approved_indexes:
            decision_position = (
                applicable_indexes.index(approved_index)
                if approved_index in applicable_indexes
                else None
            )
            if (
                decision_position is None
                or cursor.decisions[decision_position].decision.effect
                is not GuardrailEffect.ESCALATE
            ):
                raise ValueError("cursor index mismatch: approved position is not escalation")
        if not cursor.decisions or (
            cursor.decisions[-1].decision.effect is not GuardrailEffect.ESCALATE
        ):
            raise ValueError("cursor index mismatch: previous decision was not escalation")
        triggering_entry = self._entries[index - 1]
        if (
            context.stage not in triggering_entry.stages
            or cursor.triggering_guardrail_id != triggering_entry.guardrail_id
            or cursor.triggering_guardrail_version != triggering_entry.guardrail_version
        ):
            raise ValueError("cursor index mismatch: triggering guardrail does not match")

        expected_payload = context.payload
        for evaluated in cursor.decisions:
            replacement = evaluated.decision.replacement_payload
            if evaluated.decision.effect is GuardrailEffect.TRANSFORM and replacement is not None:
                expected_payload = replacement
        if cursor.payload != expected_payload:
            raise ValueError("cursor payload mismatch")

    async def _evaluate(
        self,
        entry: _GuardrailEntry,
        context: GuardrailContext,
    ) -> tuple[Decision, float]:
        effective_timeout_ms = min(entry.timeout_ms, self._timeout_ms)
        timeout_seconds = effective_timeout_ms / 1_000
        started = monotonic()
        try:
            async with asyncio.timeout(timeout_seconds):
                decision = await entry.guardrail.evaluate(context)
        except TimeoutError:
            return _failure_decision(GUARDRAIL_TIMEOUT), (monotonic() - started) * 1_000
        except Exception:
            return _failure_decision(GUARDRAIL_INTERNAL_ERROR), (monotonic() - started) * 1_000

        duration_ms = (monotonic() - started) * 1_000
        if not isinstance(decision, Decision):
            return _failure_decision(GUARDRAIL_INTERNAL_ERROR), duration_ms
        if duration_ms > effective_timeout_ms:
            return _failure_decision(GUARDRAIL_TIMEOUT), duration_ms
        return decision, duration_ms

    @staticmethod
    def _validated_decision(
        decision: Decision,
        context: GuardrailContext,
    ) -> Decision:
        try:
            validate_transformation(
                context.stage,
                decision.effect,
                decision.replacement_payload,
            )
            validate_obligations(context.stage, decision.obligations)
            replacement = decision.replacement_payload
            if replacement is not None and type(replacement) is not type(context.payload):
                raise ValueError("guardrail transforms must preserve payload kind")
        except (TypeError, ValueError):
            return _failure_decision(GUARDRAIL_INTERNAL_ERROR)
        return decision

    def _snapshot_guardrails(self) -> tuple[_GuardrailEntry, ...]:
        seen_ids: set[str] = set()
        entries: list[_GuardrailEntry] = []
        for guardrail in self._guardrails:
            guardrail_id = getattr(guardrail, "id", None)
            guardrail_version = getattr(guardrail, "version", None)
            if not isinstance(guardrail_id, str) or not guardrail_id.strip():
                raise ValueError("guardrail id must be a non-empty string")
            if not isinstance(guardrail_version, str) or not guardrail_version.strip():
                raise ValueError(f"guardrail {guardrail_id!r} version must be a non-empty string")
            if guardrail_id in seen_ids:
                raise ValueError(f"duplicate guardrail id: {guardrail_id}")
            seen_ids.add(guardrail_id)
            try:
                stages = frozenset(guardrail.stages)
            except (AttributeError, TypeError) as exc:
                raise ValueError(
                    f"guardrail {guardrail_id!r} stages must be GuardrailStage values"
                ) from exc
            if not stages:
                raise ValueError(f"guardrail {guardrail_id!r} must declare at least one stage")
            if any(not isinstance(stage, GuardrailStage) for stage in stages):
                raise ValueError(f"guardrail {guardrail_id!r} stages must be GuardrailStage values")
            timeout_ms = getattr(guardrail, "timeout_ms", self._timeout_ms)
            if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms <= 0:
                raise ValueError(
                    f"guardrail {guardrail_id!r} timeout_ms must be a positive integer"
                )
            resume_fingerprint = getattr(guardrail, "resume_fingerprint", None)
            if resume_fingerprint is not None and (
                not isinstance(resume_fingerprint, str) or not resume_fingerprint.strip()
            ):
                raise ValueError(
                    f"guardrail {guardrail_id!r} resume_fingerprint must be a non-empty string"
                )
            entries.append(
                _GuardrailEntry(
                    guardrail=guardrail,
                    guardrail_id=guardrail_id,
                    guardrail_version=guardrail_version,
                    stages=stages,
                    timeout_ms=timeout_ms,
                    resume_fingerprint=resume_fingerprint,
                )
            )
        return tuple(entries)


def _entry_descriptor(
    entry: _GuardrailEntry,
    *,
    chain_timeout_ms: int,
) -> GuardrailDescriptor:
    config: Any = getattr(entry.guardrail, "config", {})
    try:
        return GuardrailDescriptor(
            guardrail_id=entry.guardrail_id,
            guardrail_version=entry.guardrail_version,
            stages=tuple(sorted(entry.stages, key=lambda stage: stage.value)),
            timeout_ms=min(entry.timeout_ms, chain_timeout_ms),
            resume_fingerprint=entry.resume_fingerprint,
            config=config,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"guardrail {entry.guardrail_id!r} config must be a JSON-compatible mapping"
        ) from exc


def _failure_decision(reason_code: str) -> Decision:
    return Decision(
        effect=GuardrailEffect.DENY,
        reason_codes=(reason_code,),
    )
