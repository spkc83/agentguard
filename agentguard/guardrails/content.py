"""Evidence redaction and deterministic content guardrails."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, field_serializer, field_validator

from .contracts import (
    DecisionPayload,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailPayload,
    GuardrailStage,
    MessagePayload,
    ToolCallPayload,
    ToolResultPayload,
    validate_transformation,
)
from .normalization import (
    FrozenValue,
    _FrozenMapping,
    canonical_json_bytes,
    normalize_payload,
    thaw_payload,
)
from .reason_codes import (
    OUTPUT_SCHEMA_INVALID,
    PII_EGRESS_DENIED,
    PII_INPUT_REDACTED,
    SECRET_EGRESS_DENIED,
)

# Token-level boundaries (not digit-only): a 9-digit run *inside* a longer
# alphanumeric token — e.g. a sha256 hex digest or a UUID group — is not an
# SSN, and matching one there corrupts opaque reference digests that the audit
# and fairness-monitor evidence join on.
_SSN = re.compile(r"(?<![0-9A-Za-z])(\d{3})-?(\d{2})-?(\d{4})(?![0-9A-Za-z])")
_EMAIL = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_FORMATTED = re.compile(
    r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]\d{4}(?!\w)"
)
_PHONE_BARE = re.compile(r"(?<!\d)\d{10}(?!\d)")
_DOB = re.compile(
    r"(?<!\d)(?:\d{1,2}[/-]\d{1,2}[/-](?:\d{2}|\d{4})|\d{4}[/-]\d{1,2}[/-]\d{1,2})(?!\d)"
)
_ROUTING_LABELED = re.compile(r"(?i)\brouting(?:\s+number)?\D{0,8}(\d{9})\b")
_ACCOUNT_LABELED = re.compile(r"(?i)\b(?:account|acct)(?:\s+number|\s*#)?\D{0,8}(\d{8,17})\b")
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/-]{16,}"),
    re.compile(r"\b(?:sk|pk|ghp|github_pat)_[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
_SECRET_KEY = re.compile(
    r"(?i)(?:^|[_\-.])(?:api[_-]?key|secret|token|password|passwd|authorization)(?:$|[_\-.])"
)


@dataclass(frozen=True, slots=True)
class PiiMatch:
    """Location and category only; raw matched values are deliberately excluded."""

    pii_type: str
    path: tuple[str | int, ...]
    start: int
    end: int


class EvidenceSnapshot(BaseModel):
    """Redacted evidence plus a digest of the unredacted canonical value."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    value: object
    digest: str

    @field_validator("value", mode="before")
    @classmethod
    def _freeze_value(cls, value: object) -> FrozenValue:
        return normalize_payload(value)

    @field_serializer("value", when_used="json")
    def _serialize_value(self, value: object) -> object:
        return thaw_payload(value)  # type: ignore[arg-type]

    @classmethod
    def capture(cls, value: object) -> EvidenceSnapshot:
        """Capture bounded evidence without retaining or logging the raw value."""

        normalized = normalize_payload(value)
        digest = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
        redacted = _redact_secrets(mask_pii(normalized))
        return cls(value=redacted, digest=digest)

    @classmethod
    def capture_redacted(cls, value: object, redacted_value: object) -> EvidenceSnapshot:
        """Digest the full value while retaining only an explicit safe projection."""

        normalized = normalize_payload(value)
        digest = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
        safe = normalize_payload(redacted_value)
        redacted = _redact_secrets(mask_pii(safe))
        return cls(value=redacted, digest=digest)


def detect_pii(value: object) -> tuple[PiiMatch, ...]:
    """Detect PII recursively without returning raw matched text."""

    normalized = normalize_payload(value)
    matches: list[PiiMatch] = []
    _walk_detect(normalized, (), matches)
    return tuple(matches)


def mask_pii(value: object) -> FrozenValue:
    """Return a recursively masked, immutable JSON value."""

    normalized = normalize_payload(value)
    return normalize_payload(_walk_mask(normalized, ()))


def mask_pii_match(source: str, match: PiiMatch) -> str:
    """Return the masked replacement for one match in ``source``."""

    return _mask_for(match.pii_type, source[match.start : match.end])


def redact_evidence(value: object) -> object:
    """Return a plain JSON value with PII and secret material redacted."""

    normalized = normalize_payload(value)
    redacted = normalize_payload(_redact_secrets(mask_pii(normalized)))
    return thaw_payload(redacted)


class PiiInputGuardrail:
    id = "pii-input"
    version = "1"
    resume_fingerprint = "agentguard.guardrails.content:PiiInputGuardrail:1"
    stages = frozenset({GuardrailStage.INPUT})

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not detect_pii(_payload_value(context.payload)):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        replacement = _replace_payload(context.payload, mask_pii(_payload_value(context.payload)))
        validate_transformation(context.stage, GuardrailEffect.TRANSFORM, replacement)
        return GuardrailOutcome(
            effect=GuardrailEffect.TRANSFORM,
            reason_codes=(PII_INPUT_REDACTED,),
            replacement_payload=replacement,
        )


class PiiEgressGuardrail:
    id = "pii-egress"
    version = "1"
    resume_fingerprint = "agentguard.guardrails.content:PiiEgressGuardrail:1"
    stages = frozenset({GuardrailStage.POST_TOOL, GuardrailStage.POST_MESSAGE})

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if detect_pii(_payload_value(context.payload)):
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(PII_EGRESS_DENIED,),
            )
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class SecretEgressGuardrail:
    id = "secret-egress"
    version = "1"
    resume_fingerprint = "agentguard.guardrails.content:SecretEgressGuardrail:1"
    stages = frozenset({GuardrailStage.POST_TOOL, GuardrailStage.POST_MESSAGE})

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if _contains_secret(_payload_value(context.payload)):
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(SECRET_EGRESS_DENIED,),
            )
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class OutputSchemaGuardrail:
    id = "output-schema"
    version = "1"
    stages = frozenset({GuardrailStage.POST_TOOL, GuardrailStage.POST_MESSAGE})

    def __init__(
        self,
        validator: Callable[[object], object] | type[BaseModel] | None = None,
    ) -> None:
        self._validator = validator

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if self._validator is None:
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        value = thaw_payload(_payload_value(context.payload))
        try:
            if isinstance(self._validator, type) and issubclass(self._validator, BaseModel):
                self._validator.model_validate(value)
                valid = True
            else:
                validate = cast("Callable[[object], object]", self._validator)
                valid = validate(value) is not False
        except (TypeError, ValueError):
            valid = False
        if not valid:
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(OUTPUT_SCHEMA_INVALID,),
            )
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


def _walk_detect(
    value: FrozenValue,
    path: tuple[str | int, ...],
    matches: list[PiiMatch],
) -> None:
    if isinstance(value, _FrozenMapping):
        for key, item in value.items():
            _walk_detect(item, (*path, key), matches)
    elif isinstance(value, tuple):
        for index, item in enumerate(value):
            _walk_detect(item, (*path, index), matches)
    elif isinstance(value, str):
        matches.extend(_detect_text(value, path))
    elif isinstance(value, int) and not isinstance(value, bool):
        numeric = _numeric_pii(value, path)
        if numeric is not None:
            kind, text = numeric
            matches.append(PiiMatch(kind, path, 0, len(text)))


def _walk_mask(value: FrozenValue, path: tuple[str | int, ...]) -> object:
    if isinstance(value, _FrozenMapping):
        return {key: _walk_mask(item, (*path, key)) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_walk_mask(item, (*path, index)) for index, item in enumerate(value)]
    if isinstance(value, int) and not isinstance(value, bool):
        numeric = _numeric_pii(value, path)
        if numeric is not None:
            kind, text = numeric
            return _mask_for(kind, text)
    if not isinstance(value, str):
        return value
    result = value
    for match in reversed(_detect_text(value, path)):
        replacement = _mask_for(match.pii_type, result[match.start : match.end])
        result = result[: match.start] + replacement + result[match.end :]
    return result


def _detect_text(text: str, path: tuple[str | int, ...]) -> list[PiiMatch]:
    candidates: list[tuple[int, int, str]] = []
    for match in _SSN.finditer(text):
        if _valid_ssn(match.group(1), match.group(2), match.group(3)):
            candidates.append((match.start(), match.end(), "ssn"))
    candidates.extend((m.start(), m.end(), "email") for m in _EMAIL.finditer(text))
    candidates.extend((m.start(), m.end(), "phone") for m in _PHONE_FORMATTED.finditer(text))
    candidates.extend((m.start(), m.end(), "dob") for m in _DOB.finditer(text))

    hint = str(path[-1]).casefold() if path else ""
    if any(label in hint for label in ("phone", "mobile", "telephone")):
        candidates.extend((m.start(), m.end(), "phone") for m in _PHONE_BARE.finditer(text))
    for match in _ROUTING_LABELED.finditer(text):
        start, end = match.span(1)
        if _valid_routing(text[start:end]):
            candidates.append((start, end, "routing_number"))
    if "routing" in hint:
        for match in re.finditer(r"(?<!\d)\d{9}(?!\d)", text):
            if _valid_routing(match.group()):
                candidates.append((match.start(), match.end(), "routing_number"))
    for match in _ACCOUNT_LABELED.finditer(text):
        candidates.append((*match.span(1), "account_number"))
    if any(label in hint for label in ("account", "acct")):
        candidates.extend(
            (m.start(), m.end(), "account_number")
            for m in re.finditer(r"(?<!\d)\d{8,17}(?!\d)", text)
        )

    selected: list[tuple[int, int, str]] = []
    priority = {"routing_number": 0, "account_number": 0, "ssn": 1}
    for candidate in sorted(
        candidates,
        key=lambda item: (item[0], priority.get(item[2], 2), -(item[1] - item[0])),
    ):
        start, end, _ = candidate
        overlaps = any(
            start < prior_end and end > prior_start for prior_start, prior_end, _ in selected
        )
        if not overlaps:
            selected.append(candidate)
    return [PiiMatch(kind, path, start, end) for start, end, kind in selected]


def _valid_ssn(area: str, group: str, serial: str) -> bool:
    return (
        area not in {"000", "666"}
        and not area.startswith("9")
        and group != "00"
        and serial != "0000"
    )


def _valid_routing(value: str) -> bool:
    digits = [int(character) for character in value]
    checksum = 3 * sum(digits[0::3]) + 7 * sum(digits[1::3]) + sum(digits[2::3])
    return checksum % 10 == 0


def _numeric_pii(
    value: int,
    path: tuple[str | int, ...],
) -> tuple[str, str] | None:
    hint = str(path[-1]).casefold() if path else ""
    digits = str(value)
    if "routing" in hint and len(digits) <= 9:
        routing = digits.zfill(9)
        if _valid_routing(routing):
            return "routing_number", routing
    if any(label in hint for label in ("account", "acct")) and 8 <= len(digits) <= 17:
        return "account_number", digits
    if "ssn" in hint and len(digits) <= 9:
        ssn = digits.zfill(9)
        if _valid_ssn(ssn[:3], ssn[3:5], ssn[5:]):
            return "ssn", ssn
    if any(label in hint for label in ("phone", "mobile", "telephone")) and len(digits) == 10:
        return "phone", digits
    return None


def _mask_for(kind: str, original: str) -> str:
    if kind == "ssn":
        return ("XXX-XX-" if "-" in original else "XXXXX") + original[-4:]
    if kind == "account_number":
        return "X" * (len(original) - 4) + original[-4:]
    if kind == "routing_number":
        return "X" * len(original)
    if kind == "email":
        local, domain = original.split("@", 1)
        return (local[:1] + "***" if local else "***") + "@" + domain
    if kind == "phone":
        return "XXX-XXX-" + re.sub(r"\D", "", original)[-4:]
    return "XX/XX/XXXX"


def _payload_value(payload: GuardrailPayload) -> FrozenValue:
    if isinstance(payload, ToolCallPayload):
        return payload.arguments
    if isinstance(payload, ToolResultPayload):
        return cast("FrozenValue", payload.result)
    if isinstance(payload, DecisionPayload):
        return payload.body
    return cast("FrozenValue", payload.message)


def _replace_payload(
    payload: GuardrailPayload,
    value: FrozenValue,
) -> GuardrailPayload:
    if isinstance(payload, ToolCallPayload):
        if not isinstance(value, _FrozenMapping):
            raise TypeError("tool-call replacements must be mappings")
        return ToolCallPayload(arguments=value)
    if isinstance(payload, ToolResultPayload):
        return ToolResultPayload(result=value)
    if isinstance(payload, DecisionPayload):
        if not isinstance(value, _FrozenMapping):
            raise TypeError("decision replacements must be mappings")
        return DecisionPayload(
            domain=payload.domain,
            decision_id=payload.decision_id,
            outcome=payload.outcome,
            body=value,
        )
    return MessagePayload(target=payload.target, message=value)


def _contains_secret(value: FrozenValue) -> bool:
    if isinstance(value, _FrozenMapping):
        return any(_SECRET_KEY.search(key) or _contains_secret(item) for key, item in value.items())
    if isinstance(value, tuple):
        return any(_contains_secret(item) for item in value)
    return isinstance(value, str) and any(
        pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS
    )


def _redact_secrets(value: FrozenValue) -> object:
    if isinstance(value, _FrozenMapping):
        return {
            key: "[REDACTED]" if _SECRET_KEY.search(key) else _redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_redact_secrets(item) for item in value]
    if isinstance(value, str):
        result = value
        for pattern in _SECRET_VALUE_PATTERNS:
            result = pattern.sub("[REDACTED]", result)
        return result
    return value
