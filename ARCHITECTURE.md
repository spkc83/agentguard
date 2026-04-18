# AgentGuard — Architecture Reference

## System Overview

AgentGuard is a **governance middleware** — it does not orchestrate agents; it governs them. Every agent action (tool call, inter-agent message, external API call) passes through AgentGuard's runtime before execution. The architecture is a four-layer stack that can be adopted incrementally: a team can start with Layer 1 (security) alone and add compliance, domain toolkits, and observability over time.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Agent Application                    │
│          (LangGraph / CrewAI / Google ADK / Raw Python)         │
└───────────────────────────┬─────────────────────────────────────┘
                            │  tool calls / agent messages
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AgentGuard Runtime Middleware                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Security Runtime                                │   │
│  │  RBAC → Identity → Sandbox → Circuit Breaker → Audit     │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 2: Compliance Engine                               │   │
│  │  Policy Evaluator → HITL Escalation → Report Generator   │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 3: Domain Toolkit (Finance / Healthcare / Gov)     │   │
│  │  Credit Risk → Adverse Action → Synthetic Data → PII     │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 4: Observability                                   │   │
│  │  OTel Traces → Replay Debugger → Cost/Metrics Dashboard  │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────────┘
                            │  governed execution
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│               Tools / Services / External APIs                   │
│        (databases, file systems, web, internal APIs)             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Security Runtime

The security runtime is the load-bearing foundation. Every other layer depends on it. It is designed around the principle: **log first, act second, fail closed**.

### Execution Flow

```
Agent calls tool
       │
       ▼
1. resolve_identity(agent_id)        → AgentIdentity
       │
       ▼
2. check_permission(identity, action, resource)  → PermissionContext
       │
       ├── DENIED → write AuditEvent(result="denied") → raise PermissionDeniedError
       │
       ▼
3. evaluate_policies(permission_ctx) → list[PolicyResult]
       │
       ├── CRITICAL violation → write AuditEvent(result="denied") → raise PolicyViolationError
       ├── HITL required → write AuditEvent(result="escalated") → await human_approval()
       │
       ▼
4. write AuditEvent(result="allowed", policy_results=...)   ← LOG BEFORE EXECUTION
       │
       ▼
5. execute_in_sandbox(tool, args)    → SandboxResult
       │
       ├── Sandbox error → write AuditEvent(result="error") → raise SandboxError
       │
       ▼
6. return SandboxResult to agent
```

### RBAC Model

```
Role
 ├── name: str
 ├── permissions: list[Permission]
 └── inherited_roles: list[Role]     # role hierarchy

Permission
 ├── action: str                      # "tool:*", "tool:web_search", "data:read:pii"
 ├── resource_pattern: str            # glob or regex
 ├── conditions: list[Condition]      # time-based, context-based
 └── effect: Literal["allow", "deny"]

AgentIdentity
 ├── agent_id: str                    # stable UUID assigned at registration
 ├── name: str
 ├── roles: list[Role]
 └── metadata: dict                   # framework, version, owner, environment
```

Permission resolution uses **deny-override**: if any matching permission has `effect="deny"`, the action is denied regardless of other permissions. This mirrors AWS IAM's explicit-deny model.

### Sandbox Design

Two execution backends (pluggable via `SandboxBackend` protocol):

**Docker backend (default):**
- Each tool execution runs in a fresh container based on a minimal image
- Network access is opt-in per tool definition
- File system access is restricted to a mount-per-call temporary volume
- CPU and memory limits enforced via Docker resource constraints
- Execution timeout: configurable per tool, default 30 seconds

**Wasm backend (lightweight, optional):**
- Uses `wasmtime-py` for near-native sandboxing without Docker overhead
- Suitable for pure-Python tools with no system call requirements
- Faster cold start; lower isolation guarantee than Docker

### Audit Log

Append-only, tamper-evident log using HMAC chain:

```
AuditEvent N:  { ...event data..., prev_hash: HMAC(event N-1), hash: HMAC(event N) }
```

Storage backends (pluggable):
- **File** (default): JSONL file, rotated daily, compressed
- **S3/GCS**: for production deployments
- **PostgreSQL**: optional, via `agentguard[postgres]` install

The audit log is never the first place a write fails. If the log write fails, the action is blocked.

---

## Layer 2: Compliance Engine

The compliance engine evaluates a set of YAML-defined policy rules against every `AuditEvent`. It is separate from RBAC (which is about *who can do what*) — compliance is about *whether what was done meets regulatory standards*.

### Policy Rule Schema

```yaml
# Example: OWASP Agentic AI - Prompt Injection check
- id: OWASP-AGENT-01
  name: Prompt Injection Detection
  severity: critical
  description: >
    Detects user-supplied content being injected into system prompts
    or tool arguments that could override agent instructions.
  check:
    type: content_scan
    targets: [tool_args, agent_messages]
    patterns:
      - "ignore previous instructions"
      - "disregard your system prompt"
      - "you are now"
  remediation: >
    Sanitize user inputs before interpolation into prompts.
    Use structured tool schemas with strict validation.
  references:
    - https://owasp.org/www-project-top-10-for-large-language-model-applications/
```

### Built-in Policy Sets

**OWASP Top 10 for Agentic AI** (`policies/owasp_agentic.yaml`):
- OWASP-AGENT-01: Prompt Injection
- OWASP-AGENT-02: Sensitive Data Exposure
- OWASP-AGENT-03: Supply Chain Attacks (tool poisoning)
- OWASP-AGENT-04: Privilege Escalation
- OWASP-AGENT-05: Excessive Agency (scope creep)
- OWASP-AGENT-06: Overreliance / Hallucination in Action
- OWASP-AGENT-07: Data Poisoning
- OWASP-AGENT-08: Insecure Plugins / Tools
- OWASP-AGENT-09: Insecure Output Handling
- OWASP-AGENT-10: Model Denial of Service

**FINOS AIGF v2.0** (`policies/finos_aigf_v2.yaml`):
- 46 risks mapped across: Governance, Risk Management, Technology, Operations
- Key risk IDs: FINOS-AIGF-001 (Model Risk) through FINOS-AIGF-046 (Vendor Concentration)
- Maps to SR 11-7 (Fed model risk management guidance) requirements

**EU AI Act** (`policies/eu_ai_act.yaml`):
- Annex III High-Risk AI: credit scoring (Article 6)
- Article 9: Risk management system requirements
- Article 10: Data governance requirements
- Article 13: Transparency and information provision
- Article 14: Human oversight requirements
- Article 17: Quality management system

### Human-in-the-Loop Escalation

HITL is triggered when:
1. A policy rule has `requires_human_approval: true`
2. A circuit breaker threshold is approaching (warning zone)
3. An action is in an agent's `escalation_required` scope

HITL implementation is **callback-based** — AgentGuard provides the escalation event; the caller provides the approval handler:

```python
async def my_approval_handler(escalation: HitlEscalation) -> ApprovalDecision:
    # Send to Slack, PagerDuty, internal workflow system
    # Return ApprovalDecision(approved=True/False, approver_id="...", reason="...")
    ...

guard = AgentGuard(hitl_handler=my_approval_handler)
```

### Formal Policy Verification (Z3 SMT Solver)

The formal verifier runs as a **static analysis tool** — it does not sit in the hot path of agent execution. It answers questions that runtime checks cannot: not "was this action allowed?" but "is it *possible* for any agent to reach this forbidden state given these policies?"

The Z3 SMT solver (Microsoft Research, pure Python via `z3-solver`) encodes AgentGuard concepts as logical formulas and checks satisfiability:

**Property 1 — RBAC Privilege Escalation:**
```
Prove: ∀ agent a, ∀ role sequence R₁...Rₙ:
  assigned_roles(a) = {R₁...Rₙ} ∧ none_explicitly_granted(a, P)
  → ¬reachable(a, permission P)
```
Encoded as bitvector arithmetic. If Z3 returns SAT, the counterexample is a concrete role sequence that achieves escalation.

**Property 2 — Policy Consistency:**
```
Prove: ∀ rules r₁, r₂ ∈ policy_set:
  ¬(conditions(r₁) ∧ conditions(r₂) → effect(r₁) = ALLOW ∧ effect(r₂) = DENY)
```
Detects contradictions and redundant rules before deployment.

**Property 3 — Workflow Safety (µZ fixed-point engine):**
```
Prove: ∀ execution paths P in agent graph G:
  (node_with_role(X) ∈ P) ∧ (tool_requiring(Y) ∈ P)
  → ∃ hitl_node ∈ P between them
```
Uses Z3's Datalog/µZ engine for reachability queries on directed graphs.

**Property 4 — Credit Model Monotonicity (for credit risk domain):**
```
Prove: ∀ input pairs (x₁, x₂) where x₁.income > x₂.income ∧ all_else_equal:
  credit_score(x₁) ≥ credit_score(x₂)
```
Encodes model decision boundaries as piecewise-linear Z3 arithmetic formulas.

**Property 5 — Adverse Action Determinism:**
```
Prove: ∀ applicant profiles p where p₁ = p₂:
  adverse_action_reasons(p₁) = adverse_action_reasons(p₂) (same set, same order)
```

All verification results produce a `VerificationResult` with status `sat | unsat | timeout | unknown`. When SAT (property violated), Z3's counterexample is translated back to human-readable AgentGuard terms. Verification timeout defaults to 10 seconds.

```bash
# CLI usage
agentguard verify rbac --config rbac_config.yaml
agentguard verify workflow --graph agent_graph.json --property no-pii-without-hitl
agentguard verify policy --file policies/finos_aigf_v2.yaml --check consistency
agentguard verify model --module credit_scorer --property monotonicity --feature income
```

---

## Layer 3: Credit Risk Domain Toolkit

### Credit Decisioning Agent Template

A pre-built, AgentGuard-wrapped agent graph for automated credit decisioning workflows:

```
Application Received
      │
      ▼
[bureau_pull_tool]           ← sandboxed, RBAC: requires "credit:read:bureau"
      │
      ▼
[income_verification_tool]   ← sandboxed, RBAC: requires "credit:read:income"
      │
      ▼
[pd_model_tool]              ← sandboxed, model inference (PD score)
      │
      ├── PD < 5%:  AUTO_APPROVE
      ├── PD 5–20%: ANALYST_REVIEW (HITL escalation) → underwriter decision
      └── PD > 20%: AUTO_DECLINE → [adverse_action_tool]
                                        │
                                        ▼
                               [adverse_action_generator]
                               ECOA/Reg B compliant notice
                               with deterministic reason ordering
```

**Formal verification hook:** Before deployment, `agentguard verify workflow` proves that:
- No application can be auto-declined without the adverse action generator running
- No PII leaves the sandboxed bureau pull without being masked in the audit log
- The decision boundary is monotone with respect to FICO score and DTI ratio

### Adverse Action Notice Generator

ECOA and Regulation B require that when credit is denied (or offered on less favorable terms), the applicant receives a notice stating the specific principal reasons. The `AdverseActionGenerator`:

- Accepts the PD model's feature importance output
- Ranks adverse factors by contribution magnitude
- Maps model features to consumer-readable reason codes (FCRA-standardized where applicable)
- Ensures deterministic ordering (verified by Z3 property 5)
- Produces `AdverseActionNotice` Pydantic model with: applicant_id, decision, reasons (ordered list), creditor_info, disclosure_text

### SR 11-7 Model Validation Agent

Federal Reserve / OCC SR 11-7 guidance requires banks to independently validate AI/ML credit models. The validation agent automates parts of this workflow:

```
Model Validation Request
      │
      ├── [conceptual_soundness_tool]   — methodology review checklist
      ├── [data_quality_tool]           — training/validation data analysis
      ├── [performance_metrics_tool]    — Gini, KS, AUC, PSI, vintage analysis
      ├── [fairness_analysis_tool]      — disparate impact (4/5ths rule), equalized odds
      └── [documentation_review_tool]  — model documentation completeness
                    │
                    ▼
           ModelValidationReport
           (SR 11-7 section mapping)
```

### WGAN-GP Synthetic Credit Data Generator

Architecture for tabular credit application data generation:

```
Generator G:  noise(z) ⊕ condition(label) → [FC → BN → LeakyReLU] × 3 → synthetic_application
Critic D:     real/fake_application → [FC → LayerNorm → LeakyReLU] × 3 → scalar

Training:
  - Gradient penalty λ=10 (Gulrajani et al. 2017)
  - Optimizer: Adam(lr=1e-4, β1=0.5, β2=0.9)
  - Critic steps per generator step: 5
  - Conditional generation: condition on default label for controlled class distribution
  - Mode collapse detection: MMD metric between real and synthetic marginal distributions
```

Output schema for `synthetic_credit_applications_v1` dataset:
```
application_id, fico_score, dti_ratio, ltv_ratio, annual_income,
employment_status, loan_purpose, loan_amount, term_months,
delinquency_24m, months_employed, credit_utilization,
num_open_accounts, synthetic_demographic_proxy [for fairness testing only],
is_default [label]
```

### Fairness Analysis Tools

- **Disparate impact test (4/5ths rule):** `approval_rate(protected_group) / approval_rate(majority_group) ≥ 0.8`
- **Equalized odds:** True positive and false positive rates equal across demographic groups
- **Calibration:** Predicted PD matches observed default rate within confidence intervals across score bands
- **Counterfactual fairness:** Verify decision does not change when protected attributes are swapped, all else equal

All fairness computations use synthetic demographic proxies from the dataset — never infer real demographics from applicant data.

### PII Detection and Masking

Pattern library covers:
- SSN: `\d{3}-\d{2}-\d{4}` and variants → masked as `XXX-XX-####` in logs
- Account numbers: 8–17 digit sequences in financial context → last 4 digits only
- Routing numbers: 9-digit ABA format → fully masked
- DOB: multiple date format patterns → masked
- Full name + address combination → combination triggers masking even if individual fields do not

FCRA-regulated data (credit report contents, tradeline details) is treated as Category 1 PII regardless of format.

---

## Layer 4: Observability

Layer 4 provides three complementary surfaces that all read from the same
audit log so there is no second source of truth:

1. **`AgentTracer`** — OpenTelemetry spans emitted during the governance
   pipeline (live, real-time).
2. **`ReplayDebugger`** — filter and reconstruct historical audit events
   into decision timelines (post-hoc, offline).
3. **`MetricsDashboard`** — aggregate KPIs (denial rate, latency
   percentiles, per-agent activity, policy violation trends).

### OpenTelemetry Semantic Conventions

AgentGuard defines custom span attributes under the `agentguard.*` namespace:

```
agentguard.agent.id              string   UUID of the acting agent
agentguard.agent.name            string   Human-readable name
agentguard.action                string   The tool/action invoked
agentguard.resource              string   Target resource
agentguard.permission.granted    bool
agentguard.permission.reason     string
agentguard.policy.violations     int      Count of policy violations
agentguard.policy.critical       bool     Any critical violations
agentguard.sandbox.backend       string   "docker" | "wasm" | "none"
agentguard.sandbox.duration_ms   float
agentguard.cost.tokens           int      Total LLM tokens in this trace
agentguard.cost.usd              float    Estimated cost
agentguard.hitl.required         bool
agentguard.hitl.approved         bool
```

`AgentTracer` is lazily imported — if `opentelemetry-sdk` is not installed,
all spans become no-ops and the governance pipeline runs with zero
observability overhead. Integration adapters accept an optional `tracer`
parameter and automatically wrap the full pipeline (identity → RBAC →
audit → execute) in a single span named `agentguard.tool_call`.

### Audit Replay

The replay debugger takes audit log events and produces a filtered decision
timeline:

```bash
agentguard observe replay --log-dir ./audit-logs --agent-id <uuid> --result denied
agentguard observe replay --log-dir ./audit-logs --start-time 2026-04-10T00:00:00+00:00
```

Each timeline entry reports the agent, action, resource, governance
decision, and warning flags (`denied`, `error`, `escalated`,
`policy_violation`). Events are sorted by timestamp and linked back to the
original `AuditEvent` for full inspection.

### Metrics Dashboard

`MetricsDashboard.compute(events)` aggregates KPIs over any slice of the
audit log. Output is available as a structured `DashboardMetrics` model,
JSON (via `to_json`), or Markdown table (via `to_markdown`):

```bash
agentguard observe dashboard --log-dir ./audit-logs --output-format markdown
agentguard observe summary --log-dir ./audit-logs
```

Latency percentiles (p50/p95/p99) are computed only for events with a
positive `duration_ms` — integration adapters currently emit that field
only on error events (per ADR-004), so production latency metrics should
be sourced from OTel spans rather than pre-event audit records.

---

## Protocol Integration Design

All framework adapters route tool calls through a **shared governance
pipeline** (`agentguard.integrations._pipeline.run_governed`) so behavior
is identical across MCP, LangGraph, CrewAI, Google ADK, and A2A:

```
resolve identity -> RBAC check -> audit (allowed, pre)
                 -> circuit breaker -> executor
                 -> audit (error, on failure)  (ADR-004)
```

Adapters are thin — they build the executor callable for their framework
and delegate everything else to the shared pipeline. New frameworks can be
supported by writing a ~30-line adapter that constructs an executor lambda.

### MCP Middleware (`GovernedMcpClient`)

Wraps an MCP `ClientSession` at the `call_tool` boundary:

```python
from agentguard.integrations import GovernedMcpClient

client = GovernedMcpClient(
    session=mcp_session,
    agent_id=agent.agent_id,
    registry=registry, rbac_engine=engine, audit_log=audit,
)
result = await client.call_tool("web_search", {"query": "..."})
```

### LangGraph Integration (`GovernedLangGraphToolNode`)

Drop-in replacement for LangGraph's `ToolNode`. Exposes `ainvoke(tool_name,
input, resource)` and routes through the governance pipeline.

### CrewAI Integration (`GovernedCrewAITool`)

Wraps a CrewAI tool (sync `_run` method) so invocations go through the
governance pipeline. The wrapper exposes an async `run(*args, **kwargs)`;
callers can override the RBAC resource per-call via `_resource=...`.

### Google ADK Integration (`GovernedAdkTool`)

Wraps an ADK tool's `run_async(args, tool_context)` method. Resource
pattern can be set per-instance or overridden per-call.

### A2A Middleware (`GovernedA2AClient`)

Agent-to-agent messages are governed at the `send_message` boundary.
Actions are encoded as `a2a:send:<target_agent>` with resource
`agent/<target_agent>` so RBAC can allow/deny specific agent-to-agent
relationships.

---

## Security Threat Model

Primary threats and mitigations:

| Threat | Vector | Mitigation |
|--------|--------|------------|
| Prompt injection | User input → agent prompt → tool args | Content scanning policy (OWASP-AGENT-01) |
| Privilege escalation | Agent requests higher-permission tool | RBAC deny-override; no self-grant |
| Sandbox escape | Tool binary escapes Docker/Wasm | Minimal base images; seccomp profiles; read-only FS |
| Audit log tampering | Attacker modifies past events | HMAC chain; append-only storage |
| HITL bypass | Agent retries without waiting for approval | Circuit breaker blocks retries during pending approval |
| Data exfiltration | Agent leaks PII via tool calls | PII detection policy; network egress control in sandbox |
| Tool poisoning | Malicious tool definition injected | Tool registry with signature verification |
| Credential theft | Agent accesses secrets it shouldn't | Vault integration; short-lived tokens per sandbox |

---

## Deployment Patterns

**Pattern 1 — Library (embedded):**
AgentGuard runs in-process with the agent application. Simplest deployment; suitable for single-machine agent systems.

**Pattern 2 — Sidecar:**
AgentGuard runs as a sidecar container alongside the agent application. Tool calls are proxied through AgentGuard's local HTTP endpoint. Suitable for containerized deployments.

**Pattern 3 — Gateway:**
AgentGuard runs as a standalone governance gateway. All agent applications in an organization route tool calls through it. Enables centralized audit, compliance reporting, and policy management. Suitable for enterprise deployments with multiple agent teams.

---

## Versioning and Stability Contract

- **`agentguard.core.*`**: Stable API — breaking changes require major version bump and deprecation notice
- **`agentguard.compliance.*`**: Stable API — policy schema changes are backward-compatible within minor versions
- **`agentguard.domains.*`**: Beta — may change in minor versions; domain modules are versioned independently
- **`agentguard.integrations.*`**: Stable in v1.0 — public adapter classes and constructor signatures are frozen. The ``_pipeline`` helper is private.
- **`agentguard.observability.*`**: Stable in v1.0 — `AgentTracer`, `ReplayDebugger`, and `MetricsDashboard` APIs are frozen.
