# API Overview

AgentGuard's public surface is organized by layer. Each module is importable
directly; there is no hidden private surface beyond underscore-prefixed names.

## Runtime vs. offline

Only a subset of this API is on the governed call path. Today the runtime
pipeline (`agentguard.integrations._pipeline.run_governed`, used by every
adapter) performs exactly: identity resolution → RBAC check → audit write →
circuit breaker → execute. That means **identity, RBAC, audit, and the circuit
breaker are the only enforcement points**. Everything else on this page —
the policy engine, the formal verifier, HITL, PII detection, the sandbox
backends, the rate limiter, and the whole finance domain toolkit — is invoked
offline by the CLI, the reporter, or your own code, and cannot block a tool
call. Bringing those onto the hot path is tracked in
[`docs/plans/guardrails-realignment.md`](../plans/guardrails-realignment.md)
(Phase 1 onward).

Every symbol below is verified to exist by `tests/unit/test_docs_symbols.py`.

## Layer 1 — Security runtime (`agentguard.core`)

**On the governed path.**

```python
from agentguard.core.audit import AppendOnlyAuditLog, AuditBackend, ChainVerificationResult, FileAuditBackend
from agentguard.core.identity import AgentRegistry, FileBackedRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.core.circuit_breaker import CircuitBreaker, CircuitState, TokenBucketRateLimiter
from agentguard.core.sandbox import DockerSandboxBackend, NoOpSandboxBackend, SandboxBackend, SandboxConfig
```

| Module | Purpose | On governed path? |
|--------|---------|-------------------|
| `core.audit` | HMAC-chained, append-only audit log. `AuditBackend` is a Protocol; `FileAuditBackend` is the only shipped implementation. | Yes |
| `core.identity` | Agent identity registry, in-memory or file-backed | Yes |
| `core.rbac` | Deny-override RBAC with `fnmatch` wildcard matching | Yes |
| `core.circuit_breaker` | `CircuitBreaker` is wired into the pipeline; `TokenBucketRateLimiter` is not yet called by it | Breaker only |
| `core.sandbox` | Sandboxed *subprocess* execution backends. Not reachable from `run_governed`, which executes an in-process callable. | No |

Shared Pydantic models and the exception hierarchy:

```python
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext, PolicyResult, SandboxResult
from agentguard.exceptions import AgentGuardError, AuditError, AuditKeyMissingError, AuditTamperDetectedError
from agentguard.exceptions import CircuitOpenError, DuplicateAgentError, IdentityNotFoundError
from agentguard.exceptions import PermissionDeniedError, PolicyViolationError, RateLimitExceededError, SandboxError
```

## Layer 2 — Compliance engine (`agentguard.compliance`)

**Offline.** Nothing in this package is called by `run_governed`; the policy
engine is driven by the CLI (`agentguard policy validate|report`,
`agentguard verify rbac|policy`) and by `ComplianceReporter`.

```python
from agentguard.compliance.engine import PolicyEngine, PolicyRule, PolicySet
from agentguard.compliance.formal_verifier import FormalVerifier, VerificationResult
from agentguard.compliance.hitl import ApprovalDecision, HitlEscalation, HitlManager
from agentguard.compliance.reporter import ComplianceReport, ComplianceReporter, RuleSummary
from agentguard.compliance.z3_models import encode_policy_consistency, encode_rbac_permissions, encode_workflow_reachability
```

| Module | Purpose |
|--------|---------|
| `compliance.engine` | YAML policy evaluator over `AuditEvent` records. Six check types: `action_blocklist`, `resource_pattern`, `content_scan`, `permission_required`, `result_required`, `metadata_required`. Unknown check types raise `PolicyLoadError` at load time (ADR-022); custom check types are registered via `PolicyEngine(extra_check_handlers={...})` with handlers taking `(rule, event)`. |
| `compliance.formal_verifier` | Z3-backed RBAC reachability and policy-consistency checks. `verify_workflow_safety` is a breadth-first graph search, not Z3 (ADR-016). |
| `compliance.hitl` | Callback-based escalation types. `HitlManager` has no call sites in the runtime — it is a library you drive yourself. |
| `compliance.reporter` | JSON / Markdown attestation reports over an audit log |

Built-in policy bundles (35 rules total): `compliance/policies/owasp_agentic.yaml`
(10), `finos_aigf_v2.yaml` (15), `eu_ai_act.yaml` (10). See
[`docs/compliance/index.md`](../compliance/index.md) for what each bundle
actually checks.

## Layer 3 — Domain toolkit (`agentguard.domains.finance`)

**Offline.** These are libraries and report generators; none of them is
consulted before a tool call.

```python
from agentguard.domains.finance.pii import PiiDetector, PiiMasker, PiiMatch
from agentguard.domains.finance.credit_risk.agent_templates import CreditDecision, CreditDecisionConfig, CreditDecisioningAgent
from agentguard.domains.finance.credit_risk.adverse_action import AdverseActionGenerator, AdverseActionNotice
from agentguard.domains.finance.credit_risk.model_validation import ModelValidationReport, ModelValidator, PerformanceMetrics, ValidationFinding
from agentguard.domains.finance.credit_risk.fairness import FairnessAnalyzer, FairnessReport, GroupMetrics
from agentguard.domains.finance.synthetic.generators import CreditApplicationSchema, SyntheticCreditGenerator
from agentguard.domains.finance.synthetic.wgan_gp import WganGpConfig, WganGpTrainer
```

| Module | Purpose |
|--------|---------|
| `pii` | SSN / account / phone / email / DOB detection and masking. Not wired into logging or the pipeline. |
| `credit_risk.agent_templates` | Threshold-based decision banding (auto / review / decline) |
| `credit_risk.adverse_action` | ECOA / Regulation B notice construction |
| `credit_risk.model_validation` | SR 11-7 aligned validation checks over caller-supplied metrics |
| `credit_risk.fairness` | Disparate impact, equalized odds, calibration |
| `synthetic.generators` | Statistical synthetic credit data |
| `synthetic.wgan_gp` | PyTorch-backed generator (`pip install agentguard[finance]`); `torch` is imported lazily |

## Layer 4 — Integrations and observability

```python
from agentguard.integrations import GovernedA2AClient, GovernedAdkTool, GovernedCrewAITool, GovernedLangGraphToolNode, GovernedMcpClient
from agentguard.integrations._pipeline import run_governed
from agentguard.observability.tracer import AgentTracer
from agentguard.observability.replay import ReplayDebugger, ReplayEntry
from agentguard.observability.dashboard import AgentMetrics, DashboardMetrics, MetricsDashboard, PolicyViolationTrend
```

| Module | Purpose | On governed path? |
|--------|---------|-------------------|
| `integrations._pipeline` | Shared identity → RBAC → audit → breaker → execute pipeline (ADR-020). Private helper; the adapters are the public surface. | Yes |
| `integrations.mcp_middleware` | `GovernedMcpClient` — wraps a session's `call_tool` | Yes |
| `integrations.langgraph` | `GovernedLangGraphToolNode` | Yes |
| `integrations.crewai` | `GovernedCrewAITool` | Yes |
| `integrations.google_adk` | `GovernedAdkTool` | Yes |
| `integrations.a2a_middleware` | `GovernedA2AClient` — governs `send_message` | Yes |
| `observability.tracer` | `AgentTracer`, OpenTelemetry with NoOp fallback (ADR-018) | Emits one span per call |
| `observability.replay` | Audit log filtering + timeline reconstruction | No (offline) |
| `observability.dashboard` | Aggregate metrics + Markdown output | No (offline) |

The adapters define structural Protocols for the objects they wrap
(`McpSession`, `LangChainTool`, `CrewAIToolProtocol`, `AdkToolProtocol`,
`A2ATransport`) — no framework package is imported, so the adapters have not
yet been validated against real LangGraph / CrewAI / ADK / MCP objects.

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
