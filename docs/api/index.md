# API Overview

AgentGuard's public surface is organized by layer. Each module is importable
directly; there is no hidden private surface beyond underscore-prefixed names.

## Layer 1 — Security runtime (`agentguard.core`)

| Module | Exports | Purpose |
|--------|---------|---------|
| `core.audit` | `AppendOnlyAuditLog`, `FileAuditBackend`, `InMemoryAuditBackend` | HMAC-chained, append-only audit log |
| `core.identity` | `AgentRegistry`, `FileBackedRegistry`, `Agent` | Agent identity + file persistence |
| `core.rbac` | `RBACEngine`, `Role`, `Permission` | Deny-override RBAC with wildcard matching |
| `core.circuit_breaker` | `CircuitBreaker`, `TokenBucketRateLimiter` | Failure isolation + per-agent rate limits |
| `core.sandbox` | `DockerSandbox`, `NoOpSandbox` | Sandboxed tool execution backends |

## Layer 2 — Compliance engine (`agentguard.compliance`)

| Module | Exports | Purpose |
|--------|---------|---------|
| `compliance.engine` | `PolicyEngine`, `PolicyRule`, `PolicyResult` | YAML policy evaluator (6 check types) |
| `compliance.formal_verifier` | `FormalVerifier`, `VerificationResult` | Z3-based RBAC / policy / workflow verification |
| `compliance.hitl` | `HITLEscalation`, `HITLDecision` | Callback-based human-in-the-loop |
| `compliance.reporter` | `ComplianceReporter` | JSON / Markdown attestation reports |

Built-in policy bundles: `compliance/policies/owasp_agentic.yaml`,
`finos_aigf_v2.yaml`, `eu_ai_act.yaml`.

## Layer 3 — Domain toolkit (`agentguard.domains.finance`)

| Module | Exports | Purpose |
|--------|---------|---------|
| `credit_risk.agent_templates` | `CreditDecisioningAgent`, `CreditDecisionConfig`, `CreditDecision` | Decision banding with auto/review/decline |
| `credit_risk.adverse_action` | `AdverseActionGenerator`, `AdverseActionNotice` | ECOA / Regulation B notices |
| `credit_risk.model_validation` | `ModelValidator`, `ModelValidationReport`, `ValidationFinding` | SR 11-7 aligned validation |
| `credit_risk.fairness` | `FairnessAnalyzer`, `FairnessReport`, `GroupMetrics` | Disparate impact, equalized odds, calibration |
| `synthetic.generators` | `SyntheticCreditGenerator`, `CreditApplicationSchema` | Statistical synthetic credit data |
| `synthetic.wgan_gp` | `WGANGPCreditGenerator` | PyTorch-backed higher-fidelity generator (optional) |
| `pii` | `PiiDetector`, `PiiMasker`, `PiiMatch` | SSN / account / phone / email / DOB masking |

## Layer 4 — Integrations and observability

| Module | Exports | Purpose |
|--------|---------|---------|
| `integrations._pipeline` | `run_governed` | Shared identity→RBAC→audit→execute pipeline (ADR-020) |
| `integrations.mcp_middleware` | `GovernedMcpClient` | MCP tool-call wrapper |
| `integrations.langgraph` | `GovernedLangGraphToolNode` | LangGraph tool node wrapper |
| `integrations.crewai` | `GovernedCrewAITool` | CrewAI tool wrapper |
| `integrations.google_adk` | `GovernedAdkTool` | Google ADK tool wrapper |
| `integrations.a2a_middleware` | `GovernedA2AClient` | Agent-to-agent messaging wrapper |
| `observability.tracer` | `AgentTracer` | OpenTelemetry tracer with NoOp fallback (ADR-018) |
| `observability.replay` | `ReplayDebugger`, `ReplayEntry` | Audit log filtering + timeline |
| `observability.dashboard` | `MetricsDashboard`, `DashboardMetrics` | Aggregate metrics + Markdown output |

## CLI (`agentguard.cli`)

```
agentguard audit show|verify|replay
agentguard policy validate|report
agentguard verify policy|rbac
agentguard observe dashboard|replay|summary
```

See the top-level [`README.md`](../../README.md#cli) for flags and examples.
