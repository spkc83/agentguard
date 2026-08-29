"""AgentGuard compliance engine — policy evaluation, HITL, reporting.

Public API:
    from agentguard.compliance import PolicyEngine, PolicyRule, PolicySet
    from agentguard.compliance import HitlManager, HitlEscalation, ApprovalDecision
    from agentguard.compliance import ComplianceReporter, ComplianceReport
    from agentguard.compliance import FormalVerifier, VerificationResult
"""

from agentguard.compliance.continuation import (
    ApprovalDisposition,
    ApproverAuthenticator,
    ApproverCapability,
    ApproverPrincipal,
    ContinuationProtector,
    PostExecutionContinuation,
    PreExecutionContinuation,
    ProtectedContinuation,
    SealedContinuation,
    WorkloadAuthenticationBinding,
    canonical_continuation_aad,
    parse_protected_continuation,
)
from agentguard.compliance.continuation import (
    ContinuationKind as ProtectedContinuationKind,
)
from agentguard.compliance.engine import (
    PolicyBundle,
    PolicyBundleSnapshot,
    PolicyEngine,
    PolicyReloadResult,
    PolicyRule,
    PolicySet,
)
from agentguard.compliance.escalation_store import (
    ApprovedEscalation,
    ContinuationKind,
    CreatedEscalation,
    DecisionDisposition,
    EscalationAlreadyExistsError,
    EscalationConflictError,
    EscalationExpiredError,
    EscalationNotFoundError,
    EscalationRecord,
    EscalationStateError,
    EscalationStatus,
    EscalationStore,
    EscalationStoreError,
    EscalationTamperError,
    PostDeliveryEscalation,
    PreparedDecision,
)
from agentguard.compliance.execution_journal import (
    ExecutionJournal,
    ExecutionJournalAlreadyExistsError,
    ExecutionJournalConflictError,
    ExecutionJournalError,
    ExecutionJournalNotFoundError,
    ExecutionJournalRecord,
    ExecutionJournalStateError,
    ExecutionJournalStatus,
    ExecutionJournalTamperError,
    InDoubtClassification,
    ProtectedExecutionOutcome,
    canonical_execution_outcome_aad,
)
from agentguard.compliance.formal_verifier import FormalVerifier, VerificationResult
from agentguard.compliance.hitl import ApprovalDecision, HitlEscalation, HitlManager
from agentguard.compliance.reporter import ComplianceReport, ComplianceReporter, RuleSummary

__all__ = [
    "ApprovalDecision",
    "ApprovedEscalation",
    "ApprovalDisposition",
    "ApproverCapability",
    "ApproverAuthenticator",
    "ApproverPrincipal",
    "ComplianceReport",
    "ComplianceReporter",
    "ContinuationProtector",
    "ContinuationKind",
    "CreatedEscalation",
    "DecisionDisposition",
    "EscalationAlreadyExistsError",
    "EscalationConflictError",
    "EscalationExpiredError",
    "EscalationNotFoundError",
    "EscalationRecord",
    "EscalationStateError",
    "EscalationStatus",
    "EscalationStore",
    "EscalationStoreError",
    "EscalationTamperError",
    "ExecutionJournal",
    "ExecutionJournalAlreadyExistsError",
    "ExecutionJournalConflictError",
    "ExecutionJournalError",
    "ExecutionJournalNotFoundError",
    "ExecutionJournalRecord",
    "ExecutionJournalStateError",
    "ExecutionJournalStatus",
    "ExecutionJournalTamperError",
    "FormalVerifier",
    "HitlEscalation",
    "HitlManager",
    "InDoubtClassification",
    "PolicyEngine",
    "PolicyBundle",
    "PolicyBundleSnapshot",
    "PolicyReloadResult",
    "PolicyRule",
    "PolicySet",
    "PreparedDecision",
    "PostDeliveryEscalation",
    "PostExecutionContinuation",
    "PreExecutionContinuation",
    "ProtectedContinuation",
    "ProtectedContinuationKind",
    "ProtectedExecutionOutcome",
    "RuleSummary",
    "SealedContinuation",
    "VerificationResult",
    "WorkloadAuthenticationBinding",
    "canonical_continuation_aad",
    "canonical_execution_outcome_aad",
    "parse_protected_continuation",
]
