# AgentGuard — Architecture Reference

## System Overview

AgentGuard is a **governance middleware** — it does not orchestrate agents; it governs them. Every agent action (tool call, inter-agent message, external API call) routed through an AgentGuard adapter passes through its runtime before execution. The architecture is a four-layer stack that can be adopted incrementally: a team can start with Layer 1 (security) alone and add compliance, domain toolkits, and observability over time.

> **Read this first.** This document describes both what is implemented and what the
> architecture is designed to support. Only Layer 1's identity, RBAC, audit, and
> circuit breaker are on the governed call path today; Layers 2–4 are offline tools
> driven by the CLI, the reporter, or your own code. Items that do not exist yet are
> collected in [Roadmap — not yet implemented](#roadmap--not-yet-implemented) and
> flagged inline as **(roadmap)**. The gap analysis behind those flags is
> [`docs/plans/guardrails-realignment.md`](docs/plans/guardrails-realignment.md).

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

Steps marked **(roadmap)** are part of the target design but are *not* performed by
`agentguard.integrations._pipeline.run_governed` today.

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
3. evaluate_policies(permission_ctx) → list[PolicyResult]        (roadmap)
       │
       ├── CRITICAL violation → write AuditEvent(result="denied") → raise PolicyViolationError
       ├── HITL required → write AuditEvent(result="escalated") → await human_approval()
       │
       ▼
4. write AuditEvent(result="allowed", policy_results=...)   ← LOG BEFORE EXECUTION
       │
       ▼
5. circuit_breaker.call(executor)    → result
       │
       ├── Executor error → write AuditEvent(result="error") → re-raise
       │
       ▼
6. return result to agent
```

**Step 3 is planned — Phase 1.3.** `PolicyEngine` is not called by `run_governed`;
events written by the pipeline always carry `policy_results: []`, and no code path
emits `result="escalated"`. Policy evaluation happens after the fact, when the CLI or
`ComplianceReporter` replays the audit log.

**Step 5 executes an in-process callable**, not a sandbox. The sandbox backends in
`core/sandbox.py` run a `list[str]` command as a subprocess or container and are not
reachable from the governed path (roadmap — see Phase 5.3).

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

Two execution backends, pluggable via the `SandboxBackend` protocol. Both take a
`list[str]` command and return a `SandboxResult`. **Neither is reachable from
`run_governed`** — the governed path executes an in-process callable, so "sandboxed
execution" is available as a standalone utility only (roadmap — Phase 5.3).

**`DockerSandboxBackend`:**
- Each execution runs in a fresh container from a caller-supplied image
- Applies `network_disabled` and `mem_limit` from `SandboxConfig`
- Execution timeout, default 30 seconds
- Hardening flags (`read_only`, non-root `user`, `cap_drop=ALL`, `no-new-privileges`,
  `pids_limit`, CPU quota) and per-call volume mounts are **roadmap**

**`NoOpSandboxBackend`:**
- Direct `asyncio.create_subprocess_exec` with timeout enforcement, no isolation
- Development and testing only; never `shell=True`

### Audit Log

Append-only, tamper-evident log using HMAC chain:

```
AuditEvent N:  { ...event data..., prev_hash: HMAC(event N-1), hash: HMAC(event N) }
```

Storage backends are pluggable via the `AuditBackend` protocol. **`FileAuditBackend`
(daily-rotated JSONL) is the only implementation that ships.** Remote and database
backends are roadmap items; there is no `agentguard[postgres]` extra.

The audit log is never the first place a write fails. If the log write fails, the action is blocked.

Two integrity limitations are known and tracked (Phase 2): `verify_chain()` does not
detect truncation of the tail (no sequence numbers or signed head), and the HMAC
signing key is held by the audited process itself.

---

## Layer 2: Compliance Engine

The compliance engine evaluates a set of YAML-defined policy rules against `AuditEvent`
records. It is separate from RBAC (which is about *who can do what*) — compliance is
about *whether what was done meets regulatory standards*.

**It runs offline, over a written log — not before execution.** `PolicyEngine` is
invoked by `agentguard policy validate|report`, by the `verify` commands, and by
`ComplianceReporter`; it is not called by `run_governed`, and `PolicyResult` has no
`deny` vocabulary, only `passed: bool`. Putting the engine on the hot path with an
`allow | deny | escalate | warn` effect is planned — Phase 1.3. Until then a failing
rule is a finding in a report, not a blocked action.

The bundles are also uneven in what they can actually detect: of the 35 shipped rules,
9 match patterns against the real action/resource strings, 10 check only that a key is
present in caller-supplied identity metadata (values are never read), and 16 evaluate
the event's `result`/`granted` fields. See
[`docs/compliance/index.md`](docs/compliance/index.md) for the per-bundle breakdown.

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

**FINOS AIGF v2.0-aligned controls** (`policies/finos_aigf_v2.yaml`):
- 15 controls informed by FINOS AIGF v2.0, spanning Governance, Risk Management,
  Technology, and Operations themes
- Rule IDs are AgentGuard-local (`AG-FINOS-NNN`); this is **not** an official mapping
  to the FINOS risk registry (`AIR-*` IDs). An official mapping requires domain review.
- Several controls reference SR 11-7 (Fed model risk management guidance) themes

**EU AI Act** (`policies/eu_ai_act.yaml`):
- Annex III High-Risk AI: credit scoring (Article 6)
- Article 9: Risk management system requirements
- Article 10: Data governance requirements
- Article 13: Transparency and information provision
- Article 14: Human oversight requirements
- Article 17: Quality management system

### Human-in-the-Loop Escalation

HITL implementation is **callback-based** — `HitlManager` builds a `HitlEscalation` and
hands it to a handler you supply, which returns an `ApprovalDecision`:

```python
from agentguard.compliance.hitl import ApprovalDecision, HitlEscalation, HitlManager


async def my_approval_handler(escalation: HitlEscalation) -> ApprovalDecision:
    # Send to Slack, PagerDuty, internal workflow system
    return ApprovalDecision(approved=True, approver_id="...", reason="...")


manager = HitlManager(handler=my_approval_handler)
```

**Nothing in AgentGuard calls `HitlManager` (roadmap — Phase 3.4.)** There is no
`AgentGuard` facade class, no automatic escalation trigger, no pending-approval state,
no timeout, and no persistence across a restart; no code path writes an
`result="escalated"` audit event, so the dashboard's escalation counter is always zero.
Escalation triggers on policy `requires_human_approval`, on circuit-breaker warning
zones, and on a per-agent `escalation_required` scope are all part of the target
design, not the current one.

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

**Property 3 — Workflow Safety:**
```
Check: ∀ execution paths P in agent graph G:
  (node_with_role(X) ∈ P) ∧ (tool_requiring(Y) ∈ P)
  → ∃ hitl_node ∈ P between them
```
`verify_workflow_safety` implements this as a **breadth-first search over the directed
graph** — it contains no Z3 at all (ADR-016). It is a graph check, not a proof, and it
is exposed through the Python API only; there is no `verify` CLI subcommand for it.

Properties 4 (credit model monotonicity) and 5 (adverse action determinism) are
**roadmap** — no monotonicity or determinism encoding exists in `agentguard/`.

All verification results produce a `VerificationResult` with status `sat | unsat | timeout | unknown`. When SAT (property violated), Z3's counterexample is translated back to human-readable AgentGuard terms. Verification timeout defaults to 10 seconds.

```bash
# CLI usage — these two subcommands are the whole `verify` group
agentguard verify rbac --config rbac_config.yaml
agentguard verify policy --policy-dir agentguard/compliance/policies
```

Two soundness caveats apply to what ships today, both tracked in Phase 5.2: the RBAC
encoding indexes exact `(action, resource)` pairs rather than modelling `fnmatch`
subsumption and role inheritance, so a `tool:*` grant the runtime expands is invisible
to it; and the policy-consistency encoding treats rule conditions as unconstrained
strings, which makes the satisfiability question close to vacuous. Treat both as
lint-grade signals, not as proofs, until that PR lands.

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

**Roadmap — formal verification hook.** The target design gates deployment on proofs
that no application can be auto-declined without the adverse action generator running,
that no PII leaves the bureau pull unmasked, and that the decision boundary is monotone
in FICO score and DTI ratio. None of these checks exists; the graph above is also a
design sketch — `CreditDecisioningAgent` is a synchronous threshold function that holds
no governance references and issues no HITL escalation.

### Adverse Action Notice Generator

ECOA and Regulation B require that when credit is denied (or offered on less favorable terms), the applicant receives a notice stating the specific principal reasons. The `AdverseActionGenerator`:

- Accepts the PD model's feature importance output
- Ranks adverse factors by contribution magnitude
- Maps model features to consumer-readable reason codes (FCRA-standardized where applicable)
- Ensures deterministic ordering via an explicit tie-break (not formally verified)
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

AgentGuard defines custom span attributes under the `agentguard.*` namespace.

**Emitted today.** A governed call produces exactly **one** span,
`agentguard.tool_call`, with four attributes:

```
agentguard.agent_id              string   The acting agent's id
agentguard.action                string   The tool/action invoked
agentguard.resource              string   Target resource (caller-asserted)
agentguard.trace_id              string   Correlation id minted per call
```

**Roadmap — planned attributes and child spans.** The naming below is the target
convention (dotted sub-namespaces, e.g. `agent.id` rather than `agent_id`), and none
of it is emitted yet. Planned child spans: `agentguard.rbac_check`,
`agentguard.policy_eval`, `agentguard.audit_write`.

```
agentguard.agent.name            string   Human-readable name
agentguard.permission.granted    bool
agentguard.permission.reason     string
agentguard.policy.violations     int      Count of policy violations
agentguard.policy.critical       bool     Any critical violations
agentguard.sandbox.backend       string   "docker" | "none"
agentguard.sandbox.duration_ms   float
agentguard.cost.tokens           int      Total LLM tokens in this trace
agentguard.cost.usd              float    Estimated cost
agentguard.hitl.required         bool
agentguard.hitl.approved         bool
```

`AgentTracer.trace_rbac_check`, `trace_policy_evaluation`, and `trace_tool_call` exist
but have no callers; the pipeline builds its span directly. They are slated for
deletion or wiring in Phase 2.4.

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

Primary threats and the mitigation each one is *designed* to have. The status column is
the honest part: only one row is fully mitigated on the governed path today.

| Threat | Vector | Intended mitigation | Status |
|--------|--------|---------------------|--------|
| Privilege escalation | Agent requests higher-permission tool | RBAC deny-override; no self-grant | **Partial** — enforced, but the `resource` is asserted by the caller and defaults to `*`, so a deny rule fires only when the caller volunteers the incriminating label (Phase 1.1) |
| Audit log tampering | Attacker modifies past events | HMAC chain; append-only storage | **Partial** — mid-chain edits are detected; tail truncation is not, and the signing key lives in the audited process (Phase 2.1–2.2) |
| Prompt injection | User input → agent prompt → tool args | Content scanning policy (OWASP-AGENT-01) | **Not mitigated** — the policy engine is offline and tool args never reach it (Phase 1.3) |
| Data exfiltration | Agent leaks PII via tool calls | PII detection; sandbox egress control | **Not mitigated** — `pii.py` has no call sites in `agentguard/`; results are returned verbatim (Phase 1.4) |
| Sandbox escape | Tool escapes the container | Minimal base images; seccomp profiles; read-only FS | **Not mitigated** — the sandbox is off the governed path, and seccomp / read-only FS are roadmap (Phase 5.3) |
| HITL bypass | Agent retries without waiting for approval | Breaker blocks retries during pending approval | **Not mitigated** — no escalation is ever raised (Phase 3.4) |
| Agent impersonation | Caller asserts another agent's id | Verified short-lived workload credentials | **Not mitigated** — `resolve()` is a dict lookup on a self-asserted string (Phase 3.5) |
| Tool poisoning | Malicious tool definition injected | Tool registry with signature verification | **Roadmap** — no tool registry or signing exists |
| Credential theft | Agent accesses secrets it shouldn't | Vault integration; short-lived per-sandbox tokens | **Roadmap** — no secrets-manager integration exists |

Two further caveats that are properties of the design rather than of any one threat:
the adapters wrap a callable the caller still holds, so calling the raw tool bypasses
governance entirely; and a guardrail bypass is only as strong as the boundary the
application chooses to route through.

---

## Deployment Patterns

**Pattern 1 — Library (embedded).** *The only supported pattern.*
AgentGuard runs in-process with the agent application. Suitable for single-machine
agent systems. Note that in-process governance is advisory with respect to the
application itself: the audited process holds the audit signing key, and code in that
process can call the wrapped tool directly.

**Patterns 2 and 3 — sidecar and gateway — are roadmap.** No HTTP surface, proxy,
server, or control plane ships in this package; there is nothing to deploy as a
sidecar or gateway today. They are described in the Roadmap section below.

---

## Versioning and Stability Contract

- **`agentguard.core.*`**: Stable API — breaking changes require major version bump and deprecation notice
- **`agentguard.compliance.*`**: Stable API — policy schema changes are backward-compatible within minor versions
- **`agentguard.domains.*`**: Beta — may change in minor versions; domain modules are versioned independently
- **`agentguard.integrations.*`**: Stable in v1.0 — public adapter classes and constructor signatures are frozen. The ``_pipeline`` helper is private.
- **`agentguard.observability.*`**: Stable in v1.0 — `AgentTracer`, `ReplayDebugger`, and `MetricsDashboard` APIs are frozen.

---

## Roadmap — not yet implemented

Everything in this table is described elsewhere in this document as part of the target
architecture and **does not exist in the shipped package**. Phase numbers refer to
[`docs/plans/guardrails-realignment.md`](docs/plans/guardrails-realignment.md) §6.

### Layer 1 — Security runtime

| Item | Status | Phase |
|---|---|---|
| Wasm sandbox backend (`wasmtime-py`) | Not started. No `wasmtime` import exists anywhere in the package. | — |
| Sandbox on the governed path | `run_governed` executes an in-process callable; the sandbox backends take a `list[str]` command. The two APIs are disjoint. | 5.3 |
| Docker hardening (`read_only`, non-root `user`, `cap_drop=ALL`, `no-new-privileges`, `pids_limit`, CPU quota, seccomp profile) | Not started. The backend sets only `network_disabled` and `mem_limit`. | 5.3 |
| Per-call temporary volume mounts and per-tool network opt-in | Not started. | 5.3 |
| S3 / GCS audit backends | Not started. `FileAuditBackend` is the only implementation. | — |
| PostgreSQL audit backend and an `agentguard[postgres]` extra | Not started. No such extra exists, and a core DB dependency is explicitly out of scope per CLAUDE.md. | — |
| Truncation-resistant audit chain (monotonic sequence numbers, signed head checkpoint, `flock` + `fsync`) | Not started. Deleting the tail of the log still verifies clean. | 2.1 |
| Out-of-process signing (`SigningAuditBackend`, KMS/collector) | Not started. The audited process holds the HMAC key. | 2.2 |
| Rate limiting on the governed path | `TokenBucketRateLimiter` exists and is tested but has no caller. | 1.5 |
| Agent authentication (signed short-lived workload credentials) | Not started. `agent_id` is self-asserted. | 3.5 |
| Derived, non-caller-asserted RBAC resources (`ResourceResolver`) | Not started. | 1.1 |

### Layer 2 — Compliance

| Item | Status | Phase |
|---|---|---|
| `AgentGuard` facade class with `hitl_handler=` | **No such class exists.** Adapters are constructed with explicit dependencies. | 5.4 |
| Policy evaluation on the hot path, with `allow \| deny \| escalate \| warn` effects | Not started. `PolicyResult` has only `passed: bool`; pipeline events carry `policy_results: []`. | 1.3 |
| HITL wiring: escalation triggers, pending state, timeouts, persistence, `escalated` audit events | Not started. `HitlManager` has zero call sites. | 3.4 |
| Property 4 — credit model monotonicity proof | Not started. No monotonicity encoding exists. | — |
| Property 5 — adverse action ordering proof | Not started. Ordering is enforced by a sort tie-break, not proven. | — |
| Z3 Datalog/µZ workflow reachability | Not planned. `verify_workflow_safety` is a BFS and stays one (ADR-016). | — |
| Sound RBAC encoding (fnmatch subsumption, role inheritance) and a differential test against `RBACEngine` | Not started. The current encoding indexes exact `(action, resource)` pairs. | 5.2 |
| Official FINOS AIR-\* risk mapping | Not started. Rule IDs are AgentGuard-local `AG-FINOS-NNN`. | 4/5 |
| Reporter verifying the chain before attesting | Not started. `ComplianceReporter` never calls `verify_chain()`. | 2.3 |

### CLI

| Item | Status | Phase |
|---|---|---|
| `verify` subcommand for workflow safety | Not implemented. The `verify` group is `rbac` and `policy` only; workflow safety is Python-API only. | — |
| `verify` subcommand for model properties (monotonicity) | Not implemented; depends on Property 4. | — |
| `sandbox` command group | Not implemented. There is no `sandbox` group. | — |

### Layer 4 and operations

| Item | Status | Phase |
|---|---|---|
| Child spans (`rbac_check`, `policy_eval`, `audit_write`) and the full attribute set | Not started. One span, four attributes. | 2.4 |
| Real `duration_ms` on successful calls | Not started. Allowed events hard-code `0.0`, so latency percentiles reflect failures only. | 1.5 |
| Metrics endpoint (`/metrics`, Prometheus, OTel instruments) | Not started. | 2.4 |
| Replay as re-evaluation against a pinned policy bundle | Not started. `ReplayDebugger` filters and prints. | — |
| Sidecar deployment (HTTP proxy endpoint) | Not started. No HTTP surface ships. | — |
| Gateway deployment (standalone governance service, central policy management) | Not started. | — |
| Tool registry with signature verification | Not started. | — |
| Vault / secrets-manager integration, short-lived per-sandbox tokens | Not started. | — |

### Adapters

| Item | Status | Phase |
|---|---|---|
| Validation against the real LangGraph / CrewAI / Google ADK / MCP packages | Not started. The adapters import no framework and are tested against mocks; signatures do not yet match the frameworks' native tool interfaces. | 5.1 |
