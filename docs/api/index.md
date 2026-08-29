# API Overview

AgentGuard's public surface is organized by layer. Each module is importable
directly; there is no hidden private surface beyond underscore-prefixed names.

## Runtime vs. offline

`agentguard.guardrails.GovernanceKernel` is the public governed-call boundary.
It owns immutable input transforms, derived action/resource resolution, RBAC,
staged policy and content guardrails, optional rate limiting, circuit breaking,
lifecycle audit evidence, and OpenTelemetry spans/metrics. Every adapter calls
the kernel. `agentguard.integrations._pipeline.run_governed` remains as a
deprecated compatibility shim and delegates to a newly constructed kernel.

Formal verification and finance reporting/model-analysis utilities remain offline. Hardened Docker
sandbox obligations can run on the governed PRE_TOOL path when configured; credit scoring, decision emission, review escalation, override emission, and completed
notice recording can run through the live kernel via `GovernedCreditAgent`.
`GovernanceKernel` supports authenticated restart-safe PRE_TOOL/PRE_MESSAGE resume for trusted
registered executors, protected guardrail-triggered POST_TOOL/POST_MESSAGE/ON_DECISION delivery,
and optional
signed-marker recovery plus checkpoint-attested unknown-window classification through an injected
`ExecutionJournal`. Protected-result recovery and POST resume never resolve or invoke an executor.
Sandbox obligations execute the authorized transformed `list[str]` command through the hardened
Docker backend; host subprocess backends are rejected.

Phase 3.5c adds explicit secure `GovernanceKernel` construction with an authenticator and
authoritative registry. Secure calls reject caller-supplied IDs, authenticate before request
observation, derive roles from one registry snapshot, and persist schema-v2 protected continuations
with an exact signed authentication/registry binding. First-party adapters now bind a fresh
per-call credential provider through the kernel. Optional `agentguard[auth]` supplies a concrete
offline RS256 verifier with pinned local keys, strict claims, replay protection, and revocation.
Explicitly legacy kernels retain the compatibility registry path.

The registry and Phase 4.2 credit imports below were executed during documentation verification;
the public surface is also exercised by the focused domain, core, and packaging tests.

## Layer 1 — Security runtime (`agentguard.core`)

The table marks which APIs participate in the current governed path.

```python
from agentguard.core.audit import (
    AppendOnlyAuditLog,
    AuditBackend,
    ChainVerificationResult,
    FileAuditBackend,
)
from agentguard.core.authentication import (
    AgentAuthenticator,
    AgentCredentialProvider,
    AuthenticatedAgentPrincipal,
)
from agentguard.core.authentication import ControlPlaneAuthenticator, ControlPlanePrincipal
from agentguard.core.jwt_authentication import (
    CredentialUseStore,
    InMemoryCredentialUseStore,
    InMemoryJwtKeySetProvider,
    JwtAgentAuthenticator,
    JwtKeySetProvider,
    JwtKeySetSnapshot,
    JwtTrustPolicy,
)
from agentguard.core.identity import AgentRegistry, FileBackedRegistry
from agentguard.core.registry import (
    AgentIdentityResolver,
    AgentRegistryRecord,
    AgentRegistrySnapshot,
    AgentStatus,
    AuthoritativeAgentRegistry,
)
from agentguard.core.registry_control_plane import AgentRegistryControlPlane, RoleGrantPolicy
from agentguard.core.registry_state import (
    InMemoryAuthoritativeAgentRegistry,
    RegisterAgentCommand,
    RegistryMutationCommand,
    RegistryOperation,
    RegistryOperationState,
    ReplaceAgentRolesCommand,
    RevokeAgentCommand,
    RotateAgentCredentialsCommand,
    SignedAuditReference,
)
from agentguard.core.registry_store import SignedFileAuthoritativeAgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.core.circuit_breaker import CircuitBreaker, CircuitState, TokenBucketRateLimiter
from agentguard.core.sandbox import (
    DockerSandboxBackend,
    NoOpSandboxBackend,
    SandboxBackend,
    SandboxConfig,
)
```

| Module | Purpose | On governed path? |
|--------|---------|-------------------|
| `core.audit` | Local versioned HMAC chain/checkpoints through `AppendOnlyAuditLog`, plus the `AuditLog` application protocol used by local and collector clients. Schema v5 signs typed HITL evidence, schema v6 signs typed `ReconciliationEvidence`, schema v7 signs typed `AuthenticationEvidence`, and schema v8 signs typed `RegistryMutationEvidence`; historical v1-v7 records retain their exact signed forms. | Yes |
| `core.authentication` | Mechanism-neutral async protocols and frozen credential-derived principals. Agent principals contain identity and validity facts but no roles/capabilities; the control-plane principal is a distinct type. | Yes, in secure kernel mode |
| `core.jwt_authentication` | Optional offline RS256 verifier, immutable pinned key snapshots, pluggable key/replay state, atomic one-use token IDs, bounded key overlap, and emergency revocation. It performs no OIDC discovery or network key lookup. | Yes, when supplied to a secure kernel |
| `core.registry` | Read-only protocols and deeply immutable active/revoked records. Roles, record revision, and credential epoch are registry-owned authorization state. | Yes, in secure kernel mode |
| `core.registry_state` | Typed register/replace-role/rotate/revoke commands, monotonic in-memory state, and the immutable `PREPARED` → `AUDITED` → `COMMITTED`/`CONFLICTED` operation ledger. | No |
| `core.registry_control_plane` | Distinct control-plane authentication, exact action and per-role capability checks, signed audit-first mutation, idempotent retry, and cancellation convergence. | No |
| `core.registry_store` | `SignedFileAuthoritativeAgentRegistry`: canonical HMAC-signed local POSIX state with verified audit cross-binding and restart recovery. | No |
| `core.identity` | Legacy compatibility-only in-memory or unsigned file registry. It accepts self-asserted registration and is used only by explicitly legacy kernels. | Legacy only |
| `core.rbac` | Deny-override RBAC with `fnmatch` wildcard matching | Yes |
| `core.circuit_breaker` | Optional `TokenBucketRateLimiter` plus atomic CLOSED/OPEN/HALF_OPEN `CircuitBreaker` admission | Yes, when configured |
| `core.sandbox` | Hardened Docker sandbox backend and immutable PRE_TOOL obligations; host subprocess backend remains test/development-only and is rejected by the kernel. | Yes, when configured |

Shared Pydantic models and the exception hierarchy:

```python
from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    AuthenticationEvidence,
    GuardrailEvaluation,
    PermissionContext,
    PolicyResult,
    ReconciliationEvidence,
    RegistryMutationEvidence,
    SandboxResult,
)
from agentguard.exceptions import (
    AgentGuardError,
    AuthenticationError,
    AuthenticationFailure,
    AuditError,
    AuditKeyMissingError,
    AuditTamperDetectedError,
)
from agentguard.exceptions import CircuitOpenError, DuplicateAgentError, IdentityNotFoundError
from agentguard.exceptions import (
    PermissionDeniedError,
    PolicyViolationError,
    RateLimitExceededError,
    RegistryError,
    RegistryFailure,
    SandboxError,
)
```

`AuthenticationFailure` is the canonical source for the reserved `AUTH.*` failure codes.
`AuthenticationError` exposes only that safe classification. `AuthenticationEvidence` is frozen
and secret-free: verified records can contain credential-derived identity and validity metadata;
rejected records cannot contain claimed/trusted identity, credential timestamps, registry
revision, roles, provider diagnostics, or raw credentials. Rejected-event producers reserve
`__unauthenticated__` as the outer audit actor. The evidence is valid only on
`authentication_succeeded` or `authentication_rejected` lifecycle events.

`RegistryMutationEvidence` is the schema-v8 authorized/rejected decision record for registry
administration. Authorized evidence binds the authenticated control-plane principal and capability
digest, canonical request digest, base/target registry revisions, before/after record digests,
credential epochs, and preparation time. Rejected evidence carries only the applicable canonical
`REGISTRY.*` failure facts; revision conflicts additionally bind distinct requested and observed
revisions.

`AgentRegistryControlPlane` accepts opaque credentials on every mutation method. It authenticates
before reading registry state, requires an exact capability for the mutation plus exact configured
grant/revoke capabilities for each changed role, writes and verifies the authorized audit event,
then commits the proposed revision. Operation IDs make compatible retries idempotent; reuse with a
different request or principal is rejected.

`InMemoryAuthoritativeAgentRegistry(..., audit_log=...)` requires the audit sink it will verify
independently before every commit. `SignedFileAuthoritativeAgentRegistry.open(...)` additionally
requires a registry ID, a registry signing key of at least 32 bytes, a canonical key ID, a
checkpoint-capable `AuditLog`, and `trusted_checkpoint_path` outside the registry directory. The
trusted path should reside in a separately retained failure domain. It accepts only owner-controlled
0700 directories and owner-only 0600 regular state/checkpoint/lock files with one hard link. Reads use `O_NOFOLLOW`;
writes use `flock`, a unique temporary file, file `fsync`, atomic replacement, and directory
`fsync`; blocking file transactions are offloaded from the event loop. The canonical JSON envelope
has a registry-specific HMAC domain and stores the operation ledger, latest committed audit
reference, and verified audit head. A chained local checkpoint handles crash consistency, while the
trusted checkpoint supplies restart freshness. Opening recovers one-step state/checkpoint and
`PREPARED`/`AUDITED` crash windows, and rejects inconsistent or older valid registry/audit state
when its trusted counterpart remains newer. This is a local POSIX boundary, not a multi-host
coordinator. Coordinated rollback of the trusted checkpoint's failure domain too remains outside
the guarantee.

## Layer 2 — Compliance engine (`agentguard.compliance`)

`PolicyEngine` evaluates schema-v2 runtime stages inside `GovernanceKernel` and
attestation stages through the reporting surface. The formal verifier,
`HitlManager`, and reporter remain offline libraries.

```python
from agentguard.compliance.engine import (
    PolicyBundle,
    PolicyBundleSnapshot,
    PolicyEngine,
    PolicyReloadResult,
    PolicyRule,
    PolicySet,
)
from agentguard.compliance import (
    ApprovalDisposition,
    ApproverAuthenticator,
    ApproverPrincipal,
    ContinuationProtector,
    EscalationStore,
    ExecutionJournal,
    ExecutionJournalRecord,
    ExecutionJournalStatus,
    InDoubtClassification,
    PostExecutionContinuation,
    PreExecutionContinuation,
)
from agentguard.compliance.formal_verifier import FormalVerifier, VerificationResult
from agentguard.compliance.hitl import ApprovalDecision, HitlEscalation, HitlManager
from agentguard.compliance.reporter import ComplianceReport, ComplianceReporter, RuleSummary
from agentguard.compliance.z3_models import (
    encode_policy_consistency,
    encode_rbac_permissions,
    encode_workflow_reachability,
)
```

| Module | Purpose |
|--------|---------|
| `compliance.engine` | Staged YAML policy evaluator. Runtime stages inspect transformed inputs or actual results; attestation rules remain offline. `snapshot()` returns an immutable `PolicyBundle`; `await reload()` validates and atomically publishes a new content-addressed generation, returning `PolicyReloadResult`. Unknown check types and duplicate rule IDs raise `PolicyLoadError`; custom check types are registered via `PolicyEngine(extra_check_handlers={...})`. |
| `compliance.formal_verifier` | Z3-backed RBAC reachability and policy-consistency checks. `verify_workflow_safety` is a breadth-first graph search, not Z3 (ADR-016). |
| `compliance.hitl` | Callback-based escalation types. `HitlManager` has no call sites in the runtime — it is a library you drive yourself. |
| `compliance.continuation` | Injected approver-authentication and continuation-protection protocols plus exact frozen PRE-execution and POST-delivery continuation schemas. The POST schema contains no executor reference. No plaintext/default protector ships. |
| `compliance.escalation_store` | POSIX file-backed, HMAC-authenticated control state with verifier-only tokens, opaque protected envelopes, prepare→audit→commit decisions/expiry, disjoint execution/delivery claims, and mutually exclusive delivery terminals. |
| `compliance.execution_journal` | Optional process-safe, signed claim journal with AEAD-protected exact outcomes. It records claimed, admitted, protected, completed, post-processing, `IN_DOUBT`, and terminal states without storing an executor reference or raw result. Executor exception, cancellation, and invalid-output paths commit durable `DELIVERY_DENIED`. |
| `compliance.reporter` | JSON / Markdown attestation reports over a verified audit snapshot; shadow findings are separate from policy pass/failure metrics |

Built-in policy bundles (35 rules total): `compliance/policies/owasp_agentic.yaml`
(10), `finos_aigf_v2.yaml` (15), `eu_ai_act.yaml` (10). See
[`docs/compliance/index.md`](../compliance/index.md) for what each bundle
actually checks.

## Layer 3 — Domain toolkit (`agentguard.domains.finance`)

This layer contains both runtime credit controls and offline producers/report generators. The
finance compatibility PII surface delegates to the framework-independent content controls used by
the kernel. `GovernedCreditAgent` and the action-scoped credit guardrails participate in governed
score, decision, override, and completed-notice calls; validation reports, fairness reports, and
synthetic generators remain offline.

```python
from agentguard.domains.finance.pii import PiiDetector, PiiMasker, PiiMatch
from agentguard.domains.finance.credit_risk import (
    CreditDecisionCandidate,
    CreditDecisionOutcome,
    CreditDecisionPolicy,
    CreditDecisionPolicyConfig,
)
from agentguard.domains.finance.credit_risk import (
    CreditModelScore,
    DecisionAuditEvidence,
    GovernedCreditAgent,
    ModelScoreAuditEvidence,
)
from agentguard.domains.finance.credit_risk import (
    AttributionIntegrityGuardrail,
    DecisionBandGuardrail,
    DecisionEvidenceGuardrail,
    PolicyReasonIntegrityGuardrail,
    ProtectedAttributeGuardrail,
    ReasonCodeGuardrail,
    ReviewReasonIntegrityGuardrail,
)
from agentguard.domains.finance.credit_risk import (
    CreditPolicyBundle,
    CreditPolicyRule,
    JudgmentalReason,
    PolicyComparison,
    PolicyDenialSelection,
    PolicyFact,
    PolicyRuleFinding,
    ReviewJudgment,
)
from agentguard.domains.finance.credit_risk import (
    ModelFairnessStatus,
    ModelGovernanceEvidence,
    ModelGovernanceEvidenceProvider,
    ModelProvenanceGuardrail,
    ModelValidationStatus,
    StaticModelGovernanceEvidenceProvider,
    feature_schema_digest,
)
from agentguard.domains.finance.credit_risk import (
    BacktestEvidence,
    ChallengerEvidence,
    FairnessValidationEvidence,
    ModelValidationReport,
    ModelValidationSigner,
    ModelValidationVerifier,
    ModelValidator,
    PerformanceMetrics,
    SignedModelValidationEnvelope,
    SignedReportModelGovernanceEvidenceProvider,
    ValidationFinding,
    ValidationPolicy,
)
from agentguard.domains.finance.credit_risk import (
    InMemoryPreparedNoticeProvider,
    NoticeCompletenessGuardrail,
    NoticeIssueEvidence,
    PreparedNoticeProvider,
    PreparedNoticeRecord,
)
from agentguard.domains.finance.credit_risk import (
    AuditLogProtocol,
    UnresolvedDeclineFinding,
    find_unresolved_declines,
)
from agentguard.domains.finance.credit_risk import (
    ReviewEscalationVerifier,
    ReviewLineageValidator,
    VerifiedReviewEscalation,
)
from agentguard.domains.finance.credit_risk import (
    ApprovalRateTest,
    CalibrationBin,
    FairnessAnalyzer,
    FairnessObservation,
    FairnessReport,
    FairnessVerdict,
    GroupMetrics,
)
from agentguard.domains.finance.credit_risk import (
    FairnessMonitor,
    FairnessMonitoringReport,
    FairnessObservationProvider,
    PrivateFairnessAttributes,
)
from agentguard.domains.finance.credit_risk.adverse_action import (
    DeniedApplicationNotice,
    IncompleteApplicationNotice,
    StandaloneCounterofferNotice,
    CombinedCounterofferAdverseActionNotice,
    CounterofferAcceptanceInstructions,
    CounterofferNonAcceptanceNotice,
    WithdrawalRecord,
    PrincipalReasonSelection,
    DecisionComponentOrigin,
    HumanReviewBinding,
    ModelReasonOrigin,
    PolicyRuleBinding,
    ConsumerReportSource,
    NonCraThirdPartyDisclosure,
    AffiliateDisclosure,
    WrittenInformationRequest,
)
from agentguard.domains.finance.credit_risk.attribution import (
    AdverseContribution,
    AttributionMethod,
    AttributionResult,
    CoefficientAttributor,
    ModelAttributor,
    OutputDirection,
    ScoreDirection,
    ScorecardAttributor,
)
from agentguard.domains.finance.credit_risk.notice_renderer import (
    NoticeProfile,
    NoticeRenderer,
    RenderedNotice,
)
from agentguard.domains.finance.credit_risk.reason_codes import (
    BureauFactorCode,
    BureauFactorRegistry,
    BureauFactorSelection,
    MappedBureauFactor,
    MappedReason,
    ReasonCode,
    ReasonCodeMapper,
    ReasonCodeRegistry,
    ReasonCodeSelection,
)
from agentguard.testing import (
    CreditApplicationSchema,
    SyntheticCreditGenerator,
    is_synthetic_approval,
)
from agentguard.testing.wgan_gp import StandardScaler, WganGpConfig, WganGpTrainer
```

| Module | Purpose |
|--------|---------|
| `pii` | Finance/FCRA/GLBA compatibility presets over the generic runtime PII detector and masker |
| `credit_risk.agent_templates` | Pure versioned `CreditDecisionPolicy` and immutable approve/review/decline candidate contracts; deprecated legacy wrappers are not the public runtime |
| `credit_risk.governed_agent` | Thin `GovernedCreditAgent` orchestration for fixed, independently authorizable score/decision/override/notice actions and allowlisted audit projections |
| `credit_risk.decision_guardrails` | Action-scoped typed decision, protected-feature, review-band, reason-code, attribution-integrity, policy-reason-integrity, and review-reason-binding controls at `ON_DECISION` |
| `credit_risk.decision_reasons` | Versioned hard credit-policy bundles recomputed from a declared fact schema, and reviewer judgments bound to a completed escalation; both supply non-model principal reasons that cannot be asserted as text |
| `credit_risk.model_governance` | Domain-separated signed report envelope, exact-model revision source/verifier/provider, static provider, and fail-closed live provenance control |
| `credit_risk.notice_governance` | Trusted prepared-notice validation and PII-free metadata for recording an already-completed written notification |
| `credit_risk.review_governance` | Checkpoint-attested validation of exact delivered review lineage before a final override may reference its escalation |
| `credit_risk.audit_correlation` | Checkpoint-attested correlation of delivered declines and later exactly linked delivered notices; unresolved results use `AA.UNRESOLVED_DECLINE` |
| `credit_risk.attribution` | Direction-aware scorecard points-lost and coefficient-delta attribution; only strictly positive adverse contributions are retained |
| `credit_risk.reason_codes` | Independent, versioned ECOA principal-reason and FCRA bureau-factor registries with exact model-feature bindings and attribution provenance |
| `credit_risk.adverse_action` | Immutable typed denial, counteroffer, incomplete-application, withdrawal, ECOA, and FCRA artifacts with actual-notification timing |
| `credit_risk.notice_renderer` | Deterministic source-grounded C-1/C-3/C-4/C-6 and standalone-counteroffer text profiles with exact SHA-256 digests |
| `credit_risk.model_validation` | Strict immutable backtest, challenger, private-monitor fairness, finding-lifecycle, policy, and revisioned report evidence; historical SR 11-7 structure is provenance, not an attestation |
| `credit_risk.fairness` | Immutable decision-level observations; named-direction disparate impact with z/Fisher evidence and Katz interval; denominator-aware equalized odds; fixed-decile ECE; tri-state verdicts |
| `credit_risk.fairness_monitor` | Exact-model, checkpoint-attested rolling selection of final decision evidence, private protected/outcome joins, aggregate-only provenance, and `ModelFairnessStatus` output |
| `testing.synthetic` | Deterministic causal statistical synthetic credit benchmark data and fixed approval predicate; artificial group bias is for fairness evaluation only |
| `testing.wgan_gp` | Optional deterministic PyTorch-backed benchmark generator and immutable scaler (`pip install agentguard[finance]`); `torch` is imported lazily |
| `domains.finance.synthetic.*` | Pre-1.0 identity-preserving compatibility re-exports of the `agentguard.testing` benchmark helpers |

## Layer 4 — Integrations and observability

```python
from agentguard.guardrails import (
    ChainMode,
    DecisionPayload,
    GovernanceKernel,
    GuardrailChain,
    GuardrailStage,
    ReconciliationAssessment,
    ToolCallPayload,
)
from agentguard.integrations import (
    GovernedA2AClient,
    GovernedAdkTool,
    GovernedCrewAITool,
    GovernedLangGraphToolNode,
    GovernedMcpClient,
)
from agentguard.observability.tracer import AgentTracer
from agentguard.observability.replay import ReplayDebugger, ReplayEntry, ShadowEvaluationView
from agentguard.observability.dashboard import (
    AgentMetrics,
    DashboardMetrics,
    MetricsDashboard,
    PolicyViolationTrend,
    ShadowGuardrailSummary,
)
```

| Module | Purpose | On governed path? |
|--------|---------|-------------------|
| `guardrails.kernel` | Public `GovernanceKernel` runtime: transform → derive → RBAC/policy/guardrails → limits/breaker → lifecycle audit → delivery. `ChainMode.SHADOW` observes every content guardrail without blocking or applying transforms; all non-chain governance remains enforced. | Yes |
| `guardrails.chain` | Ordered enforce/shadow/off guardrail execution with fail-closed timeouts and exact payload-kind transform safety | Yes |
| `guardrails.content` | Generic PII input masking plus PII/secret output denial and optional output-schema validation | Yes |
| `integrations._pipeline` | Deprecated private compatibility shim for legacy `run_governed` calls and adapter constructor assembly | Delegates only |
| `integrations.mcp_middleware` | `GovernedMcpClient` — wraps a session's `call_tool` | Yes |
| `integrations.langgraph` | `GovernedLangGraphToolNode` | Yes |
| `integrations.crewai` | `GovernedCrewAITool` | Yes |
| `integrations.google_adk` | `GovernedAdkTool` | Yes |
| `integrations.a2a_middleware` | `GovernedA2AClient` — governs `send_message` | Yes |
| `observability.tracer` | `AgentTracer`, OpenTelemetry with NoOp fallback (ADR-018) | Root/child spans plus outcome and duration instruments |
| `observability.replay` | Audit filtering + timeline reconstruction, including signed shadow guardrail/version/stage/effect/reason data | No (offline) |
| `observability.dashboard` | Invocation-aware aggregate metrics plus deduplicated shadow summaries and conflict detection | No (offline) |

### Governed credit boundary

`GovernedCreditAgent` delegates to `GovernanceKernel.guarded_tool_call`; it does not own identity,
RBAC, policy, audit, or HITL state. Its action vocabulary is closed:

| Method | Governed action | Result contract |
|--------|-----------------|-----------------|
| `score(...)` | `model:score` | `CreditModelScore`; signed evidence retains only opaque application/model references |
| `decide(...)` | `decision:approve`, `decision:review`, or `decision:decline` | `CreditDecisionCandidate` emitted as a `DecisionPayload` and evaluated at `ON_DECISION` |
| `override(...)` | `decision:override` | Final approve/decline candidate whose parent review lifecycle and exact decision/application/model/policy lineage are verified inside the admitted executor |
| `issue_notice(...)` | `notice:issue` | `NoticeIssueEvidence` for an already-completed written notification; it rerenders for validation but does not send the notice or treat rendering as delivery |

The mixed chain can contain all credit controls because each control is action-scoped. Decision
controls ignore `notice:issue`; `NoticeCompletenessGuardrail` ignores decision actions. A
`DecisionBandGuardrail` escalation protects the completed review result. Approving that escalation
only authorizes its delivery and does not convert it into a credit approval. The underwriter must
submit a final approve or decline candidate through the separately authorized `override(...)`
method. Configure a trusted `ReviewLineageValidator`, normally
`ReviewEscalationVerifier(audit_log)`; the final candidate reuses the reviewed decision identifier,
and a caller-provided escalation string alone has no authority.

`ModelProvenanceGuardrail` accepts current validation/fairness evidence only from its configured
`ModelGovernanceEvidenceProvider`; caller-supplied decision attributes cannot satisfy it. The
bundled static provider is appropriate for tests and explicitly pinned deployments. The signed
path is `ModelValidator.validate_evidence(...)` → `ModelValidationSigner` → exact-model
`ModelValidationReportSource` → `SignedReportModelGovernanceEvidenceProvider`. The bundled source
is immutable but process-local; durable storage, key custody/rotation, independent validation
workflow, and retention remain deployment responsibilities. HMAC proves integrity inside one
trust domain and is not public non-repudiation or a regulatory attestation.

The current governed `issue_notice(...)` path accepts a final decline candidate paired with either
`DeniedApplicationNotice` or `CounterofferNonAcceptanceNotice`. Other Phase 4.3 artifact types can
still be constructed and rendered, but they are not accepted by this Phase 4.2 recording boundary.
Its notification timestamp must not be later than the configured trusted clock, and the private
prepared-notice provider is populated only from inside the admitted executor.

The full decision remains available to in-process controls and, when escalation is configured, in
the encrypted protected continuation. Signed audit payload evidence is a separate allowlisted
projection: domain-separated opaque references and the minimum outcome/notice metadata. It excludes
raw applicant identifiers, applicant fields, PD values, feature names/values, contributions,
reason text, and notice bodies. Linked protected continuations use schema v3 for this evidence
metadata while preserving exact schema-v1/v2 serialization.

`find_unresolved_declines(audit_log)` calls `read_verified(require_checkpoint=True)` and refuses a
clean result when the chain is invalid or not attestable. It resolves a delivered decline only when
a later `notice:issue` delivery has matching opaque decision and application references, valid
timely `NoticeIssueEvidence`, and one exact enforced notice-completeness allow evaluation. Final
decline overrides are included; missing or malformed decline linkage produces an unresolved
integrity finding. Denied, late, unvalidated, malformed, or mismatched notice attempts do not
resolve the finding.

When `GovernanceKernel` receives both `execution_journal=` and the existing durable HITL
dependencies, it exposes three authenticated reconciliation methods:

| Method | Contract |
|--------|----------|
| `assess_execution(escalation_id, *, credential)` | Requires `hitl:reconcile`. Reads authenticated escalation/journal state and a verified audit snapshot with `require_checkpoint=True`. A protected result remains recoverable; otherwise the method records one of `claimed_without_terminal`, `admission_without_completion`, or `completion_without_protected_result` as `IN_DOUBT`. Stable claim/delivery markers repair compatible signed journal rollback or reject conflicts before classification. |
| `reconcile_known_outcome(escalation_id, *, credential, reconciliation_id, reason="")` | Requires `hitl:reconcile`. Opens the exact sealed result, revalidates policy, chain, identity, and RBAC, atomically persists `POST_PROCESSING_CLAIMED`, writes `execution_reconciliation_resumed`, then runs POST callbacks without resolving or invoking an executor. Positive stable-marker checks read verified signed history without requiring an external checkpoint; they do not infer anything from absence. |
| `deny_in_doubt(escalation_id, *, credential, reconciliation_id, reason="")` | Requires `hitl:reconcile`. Applies the sole generic resolution for unknown execution or already-claimed POST delivery: one authenticated reconciliation event and a stable delivery denial. |

These methods accept no caller-supplied result, payload, executor, executor ID, or disposition.
They cover claimed protected PRE/POST continuations only. Legacy caller-supplied executors,
policy-only escalations, INPUT escalations, and general exactly-once replay remain excluded.
For the normal journaled PRE path, the equivalent stable pre-callback marker is
`execution_post_processing_claimed` with event ID
`invocation:{id}:post-processing-claimed`. No POST policy or guardrail callback starts before the
journal claim and its marker commit. Executor exception, repeated cancellation, or invalid output
instead drains one stable `invocation:{id}:delivery` denial and durable `DELIVERY_DENIED` terminal.

The adapters define structural Protocols for the objects they wrap
(`McpSession`, `LangChainTool`, `CrewAIToolProtocol`, `AdkToolProtocol`,
`A2ATransport`) and retain optional native entry points. CI extras tests execute
LangGraph `StateGraph`, CrewAI `BaseTool`/`Agent`, ADK `FunctionTool`, and MCP
in-memory `ClientSession` boundaries; local environments may skip those optional packages.

Each adapter accepts either `kernel=GovernanceKernel(...)` or the legacy
`registry=`, `rbac_engine=`, and `audit_log=` dependencies. Supplying both
configuration styles is rejected, so one kernel owns each governed call.
Legacy adapter construction also accepts `chain_mode="shadow"`; when a kernel is
supplied its mode is already fixed and a second adapter-level mode is rejected.

## CLI (`agentguard.cli`)

The complete command surface:

```
agentguard audit show|verify|replay
agentguard policy validate|report
agentguard verify rbac|policy
agentguard observe dashboard|replay|summary
```

`agentguard policy validate` takes `--policy-dir`, not `--file`. There is no
`agentguard sandbox` command group.

See the top-level [`README.md`](../../README.md#cli) for flags and examples.
