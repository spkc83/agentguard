"""Framework-independent immutable guardrail contracts and content controls."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentguard.core.sandbox import SandboxObligation

from .chain import (
    ChainCursor,
    ChainDescriptor,
    ChainMode,
    ChainResult,
    EvaluatedDecision,
    GuardrailChain,
    GuardrailDescriptor,
)
from .config import (
    BUILTIN_GUARDRAIL_REGISTRY,
    GuardrailChainConfig,
    GuardrailEntryConfig,
    GuardrailFactory,
    GuardrailFactoryRegistration,
    GuardrailRegistry,
    dump_guardrail_config,
    load_guardrail_config,
)
from .content import (
    EvidenceSnapshot,
    OutputSchemaGuardrail,
    PiiEgressGuardrail,
    PiiInputGuardrail,
    PiiMatch,
    SecretEgressGuardrail,
    detect_pii,
    mask_pii,
    mask_pii_match,
    redact_evidence,
)
from .contracts import (
    Decision,
    DecisionPayload,
    Guardrail,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailPayload,
    GuardrailStage,
    IdentitySnapshot,
    MessagePayload,
    ToolCallPayload,
    ToolResultPayload,
    validate_transformation,
)
from .executors import (
    ExecutorRef,
    ExecutorRefMismatchError,
    ExecutorResolver,
    RegisteredExecutor,
    StaticExecutorRegistry,
    TrustedExecutor,
    UnknownExecutorError,
)
from .normalization import (
    FrozenValue,
    canonical_json_bytes,
    normalize_payload,
    thaw_payload,
)
from .reason_codes import RUNTIME_REASON_CODES, is_valid_reason_code

if TYPE_CHECKING:
    from .kernel import (
        AdapterRegisteredToolCall,
        AdapterToolCall,
        GovernanceKernel,
        GovernedAdapterCaller,
        ReconciliationAssessment,
    )


def __getattr__(name: str) -> Any:
    """Load the kernel lazily to keep continuation contracts cycle-free."""

    if name in {
        "AdapterRegisteredToolCall",
        "AdapterToolCall",
        "GovernanceKernel",
        "GovernedAdapterCaller",
        "ReconciliationAssessment",
    }:
        from .kernel import (
            AdapterRegisteredToolCall,
            AdapterToolCall,
            GovernanceKernel,
            GovernedAdapterCaller,
            ReconciliationAssessment,
        )

        return {
            "AdapterRegisteredToolCall": AdapterRegisteredToolCall,
            "AdapterToolCall": AdapterToolCall,
            "GovernanceKernel": GovernanceKernel,
            "GovernedAdapterCaller": GovernedAdapterCaller,
            "ReconciliationAssessment": ReconciliationAssessment,
        }[name]
    raise AttributeError(name)


__all__ = [
    "AdapterRegisteredToolCall",
    "AdapterToolCall",
    "BUILTIN_GUARDRAIL_REGISTRY",
    "ChainCursor",
    "ChainDescriptor",
    "ChainMode",
    "ChainResult",
    "Decision",
    "DecisionPayload",
    "EvaluatedDecision",
    "EvidenceSnapshot",
    "ExecutorRef",
    "ExecutorRefMismatchError",
    "ExecutorResolver",
    "FrozenValue",
    "Guardrail",
    "GuardrailChain",
    "GuardrailChainConfig",
    "GuardrailDescriptor",
    "GuardrailEntryConfig",
    "GuardrailFactory",
    "GuardrailFactoryRegistration",
    "GuardrailRegistry",
    "GuardrailContext",
    "GuardrailEffect",
    "GuardrailOutcome",
    "GuardrailPayload",
    "GuardrailStage",
    "GovernanceKernel",
    "GovernedAdapterCaller",
    "IdentitySnapshot",
    "MessagePayload",
    "OutputSchemaGuardrail",
    "PiiEgressGuardrail",
    "PiiInputGuardrail",
    "PiiMatch",
    "RUNTIME_REASON_CODES",
    "RegisteredExecutor",
    "ReconciliationAssessment",
    "SecretEgressGuardrail",
    "SandboxObligation",
    "ToolCallPayload",
    "ToolResultPayload",
    "StaticExecutorRegistry",
    "TrustedExecutor",
    "UnknownExecutorError",
    "canonical_json_bytes",
    "detect_pii",
    "dump_guardrail_config",
    "is_valid_reason_code",
    "mask_pii",
    "mask_pii_match",
    "load_guardrail_config",
    "normalize_payload",
    "redact_evidence",
    "thaw_payload",
    "validate_transformation",
]
