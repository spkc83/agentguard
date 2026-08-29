"""Trusted model-governance evidence consumed by live credit decisions."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime  # noqa: TC003 - Pydantic runtime type
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.guardrails import (
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    canonical_json_bytes,
)
from agentguard.guardrails.reason_codes import (
    FAIR_CHECK_FAILED,
    MRM_MODEL_UNVALIDATED,
)

from .decision_guardrails import _invalid_payload, parse_credit_candidate
from .model_validation import (
    ModelValidationReport,
    ModelValidationReportStatus,
    require_valid_report_revision,
)

_ON_DECISION = frozenset({GuardrailStage.ON_DECISION})
_SIGNATURE_DOMAIN = b"agentguard:model-validation-report:hmac-sha256:v1\x00"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class ModelValidationStatus(StrEnum):
    VALIDATED = "validated"
    UNVALIDATED = "unvalidated"


class ModelFairnessStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INSUFFICIENT_DATA = "insufficient_data"


def feature_schema_digest(feature_names: Iterable[str]) -> str:
    """Return a stable digest without exposing feature names in runtime evidence."""

    names = tuple(feature_names)
    return hashlib.sha256(canonical_json_bytes(names)).hexdigest()


class ModelGovernanceEvidence(BaseModel):
    """Trusted exact-version validation and fairness state for one model."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str
    model_version: str
    validation_status: ModelValidationStatus
    fairness_status: ModelFairnessStatus
    feature_schema_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    validation_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    fairness_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    validated_at: datetime
    expires_at: datetime

    @field_validator("model_id", "model_version")
    @classmethod
    def _validate_identifiers(cls, value: str) -> str:
        if not value or value != value.strip() or not value.isprintable():
            raise ValueError("model identifiers must be canonical printable text")
        return value

    @field_validator("validated_at", "expires_at")
    @classmethod
    def _normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("model evidence timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_window(self) -> ModelGovernanceEvidence:
        if self.expires_at <= self.validated_at:
            raise ValueError("model evidence expiry must follow validation")
        return self


class ModelGovernanceEvidenceProvider(Protocol):
    """Trusted lookup boundary; caller-supplied decision attributes are ignored."""

    provider_id: str
    version: str

    def get(self, model_id: str, model_version: str) -> Awaitable[ModelGovernanceEvidence | None]:
        """Return evidence for one exact model identity."""


class StaticModelGovernanceEvidenceProvider:
    """Immutable in-process provider for tests and explicitly pinned deployments."""

    provider_id = "static-model-governance"
    version = "1"

    def __init__(self, evidence: Iterable[ModelGovernanceEvidence]) -> None:
        indexed: dict[tuple[str, str], ModelGovernanceEvidence] = {}
        for item in evidence:
            key = (item.model_id, item.model_version)
            if key in indexed:
                raise ValueError("duplicate model governance evidence")
            indexed[key] = item.model_copy(deep=True)
        self._evidence = MappingProxyType(indexed)

    async def get(
        self,
        model_id: str,
        model_version: str,
    ) -> ModelGovernanceEvidence | None:
        evidence = self._evidence.get((model_id, model_version))
        return evidence.model_copy(deep=True) if evidence is not None else None


class SignedModelValidationEnvelope(BaseModel):
    """A domain-separated integrity envelope for one complete report revision."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    signature_schema_version: Literal["1"] = "1"
    key_id: str
    algorithm: Literal["HMAC-SHA256"] = "HMAC-SHA256"
    report_ref: str = Field(pattern=_SHA256_PATTERN)
    report: ModelValidationReport
    signature: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("key_id")
    @classmethod
    def _validate_key_id(cls, value: str) -> str:
        if not value or value != value.strip() or not value.isprintable():
            raise ValueError("key_id must be canonical printable text")
        return value


def _unsigned_envelope_bytes(
    *,
    signature_schema_version: str,
    key_id: str,
    algorithm: str,
    report_ref: str,
    report: ModelValidationReport,
) -> bytes:
    return _SIGNATURE_DOMAIN + canonical_json_bytes(
        {
            "algorithm": algorithm,
            "key_id": key_id,
            "report": report.model_dump(mode="json"),
            "report_ref": report_ref,
            "signature_schema_version": signature_schema_version,
        }
    )


class ModelValidationSigner:
    """Create HMAC-SHA256 report envelopes inside one trust domain."""

    def __init__(self, key_id: str, key: bytes) -> None:
        if not key_id or key_id != key_id.strip() or not key_id.isprintable():
            raise ValueError("key_id must be canonical printable text")
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("model-validation HMAC key must be at least 32 bytes")
        self._key_id = key_id
        self._key = bytes(key)

    def sign(self, report: ModelValidationReport) -> SignedModelValidationEnvelope:
        """Sign the exact full report; incomplete compatibility reports are rejected."""

        report = ModelValidationReport.model_validate(report.model_dump(mode="python"))
        if not report.is_strict:
            raise ValueError("only complete strict model-validation reports can be signed")
        report_ref = report.report_ref
        signature = hmac.new(
            self._key,
            _unsigned_envelope_bytes(
                signature_schema_version="1",
                key_id=self._key_id,
                algorithm="HMAC-SHA256",
                report_ref=report_ref,
                report=report,
            ),
            hashlib.sha256,
        ).hexdigest()
        return SignedModelValidationEnvelope(
            key_id=self._key_id,
            report_ref=report_ref,
            report=report,
            signature=signature,
        )


class ModelValidationVerifier:
    """Verify canonical envelope bytes using pinned HMAC keys."""

    def __init__(self, keys: Mapping[str, bytes]) -> None:
        copied: dict[str, bytes] = {}
        for key_id, key in keys.items():
            if not key_id or key_id != key_id.strip() or not key_id.isprintable():
                raise ValueError("key IDs must be canonical printable text")
            if not isinstance(key, bytes) or len(key) < 32:
                raise ValueError("model-validation HMAC keys must be at least 32 bytes")
            copied[key_id] = bytes(key)
        if not copied:
            raise ValueError("at least one model-validation verification key is required")
        self._keys = MappingProxyType(copied)

    def verify(self, envelope: SignedModelValidationEnvelope) -> ModelValidationReport:
        """Return a detached report copy after exact reference/signature verification."""

        envelope = SignedModelValidationEnvelope.model_validate(envelope.model_dump(mode="python"))
        if envelope.report.report_ref != envelope.report_ref:
            raise ValueError("model-validation report reference mismatch")
        key = self._keys.get(envelope.key_id)
        if key is None:
            raise ValueError("unknown model-validation signing key")
        expected = hmac.new(
            key,
            _unsigned_envelope_bytes(
                signature_schema_version=envelope.signature_schema_version,
                key_id=envelope.key_id,
                algorithm=envelope.algorithm,
                report_ref=envelope.report_ref,
                report=envelope.report,
            ),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(envelope.signature, expected):
            raise ValueError("invalid model-validation report signature")
        return envelope.report.model_copy(deep=True)


class ModelValidationReportSource(Protocol):
    """Trusted exact-model source responsible for latest-revision guarantees."""

    source_id: str
    version: str

    async def get_latest(
        self, model_id: str, model_version: str
    ) -> SignedModelValidationEnvelope | None: ...

    async def get_revision(
        self, model_id: str, model_version: str, revision: int
    ) -> SignedModelValidationEnvelope | None: ...


class InMemoryModelValidationReportSource:
    """Process-local immutable source with contiguous rollback-resistant lineages."""

    def __init__(
        self,
        envelopes: Iterable[SignedModelValidationEnvelope],
        *,
        source_id: str = "in-memory-model-validation",
        version: str = "1",
    ) -> None:
        if not source_id or source_id != source_id.strip() or not source_id.isprintable():
            raise ValueError("source_id must be canonical printable text")
        if not version or version != version.strip() or not version.isprintable():
            raise ValueError("source version must be canonical printable text")
        indexed: dict[tuple[str, str, int], SignedModelValidationEnvelope] = {}
        by_model: dict[tuple[str, str], list[SignedModelValidationEnvelope]] = {}
        for item in envelopes:
            envelope = SignedModelValidationEnvelope.model_validate(
                item.model_dump(mode="python")
            ).model_copy(deep=True)
            report = envelope.report
            key = (report.model_id, report.model_version, report.revision)
            if key in indexed:
                raise ValueError("duplicate exact model-validation report revision")
            indexed[key] = envelope
            by_model.setdefault(key[:2], []).append(envelope)
        latest: dict[tuple[str, str], SignedModelValidationEnvelope] = {}
        for model_key, lineage in by_model.items():
            lineage.sort(key=lambda item: item.report.revision)
            if [item.report.revision for item in lineage] != list(range(1, len(lineage) + 1)):
                raise ValueError("model-validation revision lineage must be contiguous from one")
            report_id = lineage[0].report.report_id
            for previous, current in zip(lineage, lineage[1:], strict=False):
                if current.report.report_id != report_id:
                    raise ValueError("report revisions must retain one report_id")
                if current.report.supersedes_report_ref != previous.report_ref:
                    raise ValueError("report revision does not bind its exact predecessor")
                require_valid_report_revision(previous.report, current.report)
            latest[model_key] = lineage[-1]
        self.source_id = source_id
        self.version = version
        self._indexed = MappingProxyType(indexed)
        self._latest = MappingProxyType(latest)

    async def get_latest(
        self, model_id: str, model_version: str
    ) -> SignedModelValidationEnvelope | None:
        item = self._latest.get((model_id, model_version))
        return item.model_copy(deep=True) if item is not None else None

    async def get_revision(
        self, model_id: str, model_version: str, revision: int
    ) -> SignedModelValidationEnvelope | None:
        item = self._indexed.get((model_id, model_version, revision))
        return item.model_copy(deep=True) if item is not None else None


class SignedReportModelGovernanceEvidenceProvider:
    """Verify a latest signed report lineage and project live governance evidence."""

    provider_id = "signed-model-validation-report"
    version = "1"

    def __init__(
        self,
        source: ModelValidationReportSource,
        verifier: ModelValidationVerifier,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        source_id = getattr(source, "source_id", "")
        source_version = getattr(source, "version", "")
        if (
            not source_id
            or source_id != source_id.strip()
            or not source_id.isprintable()
            or not source_version
            or source_version != source_version.strip()
            or not source_version.isprintable()
        ):
            raise ValueError("model-validation report source requires canonical identity/version")
        self._source = source
        self._verifier = verifier
        self._clock = clock or (lambda: datetime.now(UTC))
        self._source_identity = (source_id, source_version)
        self.config = MappingProxyType({"source_id": source_id, "source_version": source_version})

    async def get(self, model_id: str, model_version: str) -> ModelGovernanceEvidence | None:
        try:
            if (
                not model_id
                or model_id != model_id.strip()
                or not model_version
                or model_version != model_version.strip()
            ):
                return None
            if (
                getattr(self._source, "source_id", ""),
                getattr(self._source, "version", ""),
            ) != self._source_identity:
                return None
            latest = await self._source.get_latest(model_id, model_version)
            if latest is None:
                return None
            report = self._verifier.verify(latest)
            if (
                report.model_id != model_id
                or report.model_version != model_version
                or not report.is_strict
            ):
                return None
            current = report
            while current.revision > 1:
                previous_envelope = await self._source.get_revision(
                    model_id, model_version, current.revision - 1
                )
                if previous_envelope is None:
                    return None
                previous = self._verifier.verify(previous_envelope)
                if (
                    previous.report_id != report.report_id
                    or previous.model_id != model_id
                    or previous.model_version != model_version
                    or current.supersedes_report_ref != previous.report_ref
                ):
                    return None
                require_valid_report_revision(previous, current)
                current = previous
            if current.revision != 1 or current.supersedes_report_ref is not None:
                return None
            now = self._clock()
            if now.tzinfo is None or now.utcoffset() is None or report.expires_at is None:
                return None
            now = now.astimezone(UTC)
            if (
                report.derived_expires_at != report.expires_at
                or now < report.validation_date
                or now >= report.expires_at
            ):
                return None
            fairness = report.fairness
            if fairness is None:
                return None
            fairness_status = ModelFairnessStatus(fairness.status)
            validation_status = (
                ModelValidationStatus.VALIDATED
                if report.status is ModelValidationReportStatus.VALIDATED
                else ModelValidationStatus.UNVALIDATED
            )
            return ModelGovernanceEvidence(
                model_id=model_id,
                model_version=model_version,
                validation_status=validation_status,
                fairness_status=fairness_status,
                feature_schema_digest=report.feature_schema_digest,
                validation_ref=report.report_ref,
                fairness_ref=fairness.monitor_report_digest,
                validated_at=report.validation_date,
                expires_at=report.expires_at,
            )
        except Exception:  # every verifier/source failure is non-authorizing
            return None


class ModelProvenanceGuardrail:
    """Fail closed unless trusted validation and fairness evidence is current."""

    id = "credit-model-provenance"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.model_governance:ModelProvenanceGuardrail:1"
    )
    stages = _ON_DECISION

    def __init__(
        self,
        provider: ModelGovernanceEvidenceProvider,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        provider_id = getattr(provider, "provider_id", "")
        provider_version = getattr(provider, "version", "")
        if (
            not provider_id
            or provider_id != provider_id.strip()
            or not provider_version
            or provider_version != provider_version.strip()
        ):
            raise ValueError("model evidence provider requires canonical identity and version")
        self._provider = provider
        self._clock = clock or (lambda: datetime.now(UTC))
        self.config = {
            "provider_id": provider_id,
            "provider_version": provider_version,
        }

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not context.action.startswith("decision:"):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        candidate = parse_credit_candidate(context)
        if candidate is None:
            return _invalid_payload()
        attribution = candidate.attribution
        if (
            attribution is None
            or attribution.model_id != candidate.model_id
            or attribution.model_version != candidate.model_version
        ):
            return self._unvalidated()
        try:
            evidence = await self._provider.get(candidate.model_id, candidate.model_version)
            now = self._clock()
        except Exception:
            return self._unvalidated()
        if now.tzinfo is None or now.utcoffset() is None:
            return self._unvalidated()
        if (
            evidence is None
            or evidence.model_id != candidate.model_id
            or evidence.model_version != candidate.model_version
            or now.astimezone(UTC) < evidence.validated_at
            or now.astimezone(UTC) >= evidence.expires_at
            or evidence.feature_schema_digest != feature_schema_digest(attribution.feature_names)
        ):
            return self._unvalidated()
        if evidence.fairness_status is ModelFairnessStatus.FAILED:
            # The signed fairness binding is aggregate-only: it records THAT
            # the fairness analysis failed, not WHICH metric (disparate
            # impact, equalized odds, or calibration) failed. Emitting a
            # metric-specific code here would state a cause the evidence
            # cannot support, so the code stays generic until the binding
            # carries per-metric verdicts.
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(FAIR_CHECK_FAILED,),
            )
        if (
            evidence.validation_status is not ModelValidationStatus.VALIDATED
            or evidence.fairness_status is ModelFairnessStatus.INSUFFICIENT_DATA
        ):
            return self._unvalidated()
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)

    @staticmethod
    def _unvalidated() -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.DENY,
            reason_codes=(MRM_MODEL_UNVALIDATED,),
        )
