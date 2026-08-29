"""Stable framework-independent guardrail contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol, TypeAlias, runtime_checkable

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from agentguard.core.sandbox import SandboxObligation  # noqa: TC001 - Pydantic runtime type

from .normalization import FrozenValue, _FrozenMapping, normalize_payload, thaw_payload
from .reason_codes import is_valid_reason_code


class GuardrailStage(StrEnum):
    """Supported runtime interception points."""

    INPUT = "input"
    PRE_TOOL = "pre_tool"
    POST_TOOL = "post_tool"
    PRE_MESSAGE = "pre_message"
    POST_MESSAGE = "post_message"
    ON_DECISION = "on_decision"
    ATTESTATION = "attestation"


class GuardrailEffect(StrEnum):
    """Portable guardrail actions understood by the runtime."""

    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    WARN = "warn"
    TRANSFORM = "transform"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)


class IdentitySnapshot(_FrozenModel):
    """Deeply immutable identity data captured for one guardrail evaluation."""

    agent_id: str
    name: str
    roles: tuple[str, ...] = ()
    metadata: _FrozenMapping = _FrozenMapping({})

    @field_validator("metadata", mode="before")
    @classmethod
    def _freeze_metadata(cls, value: object) -> _FrozenMapping:
        return _as_mapping(value, "identity metadata")


class ToolCallPayload(_FrozenModel):
    kind: Literal["tool_call"] = "tool_call"
    arguments: _FrozenMapping

    @field_validator("arguments", mode="before")
    @classmethod
    def _freeze_arguments(cls, value: object) -> _FrozenMapping:
        return _as_mapping(value, "tool arguments")


class ToolResultPayload(_FrozenModel):
    kind: Literal["tool_result"] = "tool_result"
    result: object

    @field_validator("result", mode="before")
    @classmethod
    def _freeze_result(cls, value: object) -> FrozenValue:
        return normalize_payload(value)

    @field_serializer("result", when_used="json")
    def _serialize_result(self, value: object) -> object:
        return thaw_payload(value)  # type: ignore[arg-type]


class MessagePayload(_FrozenModel):
    kind: Literal["message"] = "message"
    target: str = ""
    message: object

    @field_validator("message", mode="before")
    @classmethod
    def _freeze_message(cls, value: object) -> FrozenValue:
        return normalize_payload(value)

    @field_serializer("message", when_used="json")
    def _serialize_message(self, value: object) -> object:
        return thaw_payload(value)  # type: ignore[arg-type]


class DecisionPayload(_FrozenModel):
    """Immutable domain decision evaluated before external delivery."""

    kind: Literal["decision"] = "decision"
    domain: str
    decision_id: str
    outcome: str
    body: _FrozenMapping

    @field_validator("domain", "decision_id", "outcome")
    @classmethod
    def _validate_canonical_text(cls, value: str) -> str:
        if not value or value != value.strip() or not value.isprintable():
            raise ValueError("decision identifiers must be canonical printable text")
        return value

    @field_validator("body", mode="before")
    @classmethod
    def _freeze_body(cls, value: object) -> _FrozenMapping:
        return _as_mapping(value, "decision body")


GuardrailPayload: TypeAlias = ToolCallPayload | ToolResultPayload | MessagePayload | DecisionPayload


class GuardrailOutcome(_FrozenModel):
    """A serializable guardrail decision with machine-stable reason codes."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True, extra="forbid")

    effect: GuardrailEffect
    reason_codes: tuple[str, ...] = ()
    replacement_payload: GuardrailPayload | None = None
    # Obligations are runtime execution instructions. They are never persisted in
    # continuations/audit payloads; sandbox-before-escalation is intentionally non-resumable.
    obligations: tuple[SandboxObligation, ...] = Field(default=(), exclude=True)

    @model_validator(mode="after")
    def _validate_contract(self) -> GuardrailOutcome:
        for code in self.reason_codes:
            if not is_valid_reason_code(code):
                raise ValueError(f"reason code is not a stable registered identifier: {code!a}")
        if (
            self.effect in {GuardrailEffect.DENY, GuardrailEffect.ESCALATE}
            and not self.reason_codes
        ):
            raise ValueError(f"{self.effect.value} outcomes require at least one reason code")
        if self.effect is GuardrailEffect.TRANSFORM and self.replacement_payload is None:
            raise ValueError("transform outcomes require a replacement payload")
        if self.effect is not GuardrailEffect.TRANSFORM and self.replacement_payload is not None:
            raise ValueError("replacement payload is valid only for transform outcomes")
        if self.obligations and self.effect not in {GuardrailEffect.ALLOW, GuardrailEffect.WARN}:
            raise ValueError("obligations are valid only for allow or warn outcomes")
        return self


Decision: TypeAlias = GuardrailOutcome


class GuardrailContext(_FrozenModel):
    """Deeply immutable input to one guardrail evaluation."""

    trace_id: str
    invocation_id: str
    stage: GuardrailStage
    identity: IdentitySnapshot
    action: str
    resource: str
    payload: GuardrailPayload
    attributes: _FrozenMapping = _FrozenMapping({})
    prior: tuple[Decision, ...] = ()

    @field_validator("attributes", mode="before")
    @classmethod
    def _freeze_attributes(cls, value: object) -> _FrozenMapping:
        return _as_mapping(value, "guardrail attributes")


_TRANSFORM_STAGES = frozenset(
    {
        GuardrailStage.INPUT,
        GuardrailStage.POST_TOOL,
        GuardrailStage.POST_MESSAGE,
    }
)


def validate_transformation(
    stage: GuardrailStage,
    effect: GuardrailEffect,
    replacement_payload: GuardrailPayload | None,
) -> None:
    """Validate the reusable stage/effect/replacement legality invariant."""

    if effect is GuardrailEffect.TRANSFORM and stage not in _TRANSFORM_STAGES:
        raise ValueError(f"transformation is not legal at stage {stage.value}")
    if effect is GuardrailEffect.TRANSFORM and replacement_payload is None:
        raise ValueError("transform outcomes require a replacement payload")
    if effect is not GuardrailEffect.TRANSFORM and replacement_payload is not None:
        raise ValueError("replacement payload is valid only for transform outcomes")
    if (
        effect is GuardrailEffect.TRANSFORM
        and stage is GuardrailStage.INPUT
        and isinstance(replacement_payload, ToolResultPayload | DecisionPayload)
    ):
        raise ValueError("input transforms cannot replace an output payload")
    if (
        effect is GuardrailEffect.TRANSFORM
        and stage in {GuardrailStage.POST_TOOL, GuardrailStage.POST_MESSAGE}
        and isinstance(replacement_payload, ToolCallPayload | DecisionPayload)
    ):
        raise ValueError("tool/message output transforms require their matching payload kind")


def validate_obligations(
    stage: GuardrailStage,
    obligations: tuple[SandboxObligation, ...],
) -> None:
    """Allow execution obligations only where they can precede tool execution."""

    if obligations and stage is not GuardrailStage.PRE_TOOL:
        raise ValueError("sandbox obligations are legal only at pre_tool")


@runtime_checkable
class Guardrail(Protocol):
    """Async evaluation contract implemented by all runtime guardrails."""

    id: str
    version: str
    stages: frozenset[GuardrailStage]

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome: ...


def _as_mapping(value: object, label: str) -> _FrozenMapping:
    normalized = normalize_payload(value)
    if not isinstance(normalized, _FrozenMapping):
        raise TypeError(f"{label} must be a mapping")
    return normalized
