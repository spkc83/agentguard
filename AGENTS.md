# AgentGuard — Claude Code Agent Definitions

This file defines specialized agent roles for use with Claude Code's multi-agent task delegation. Each agent has a focused domain, a set of allowed actions, and clear handoff contracts to prevent overlap and ensure consistent output quality.

> **Usage:** When using `/agent` in Claude Code or orchestrating sub-agents programmatically, reference these role names and their scope boundaries.

---

## Agent Roster

### `security-architect`
**Purpose:** Design and implement the Layer 1 Security Runtime (`agentguard/core/`).

**Owns:**
- `agentguard/core/rbac.py` — permission model, role definitions, policy enforcement
- `agentguard/core/audit.py` — immutable append-only audit logger
- `agentguard/core/sandbox.py` — Docker/Wasm sandboxed execution engine
- `agentguard/core/circuit_breaker.py` — kill switches, rate limiting, breakers
- `agentguard/core/identity.py` — agent identity, credentials, token management
- `agentguard/exceptions.py` — all custom exception types
- `tests/unit/core/` — unit tests for all core modules
- `tests/red_team/` — adversarial and escape-attempt tests

**Key constraints:**
- All functions must be async; provide sync wrappers only via `run_sync()` helper
- Audit log writes happen BEFORE action execution — log-first, act-second
- Deny-by-default: if permission check throws any exception, the action is blocked
- Never use `subprocess(shell=True)` or `eval()` anywhere in this layer
- Sandbox escapes are the primary threat model; every sandbox action must be tested with a deliberate escape attempt

**Handoff contract (outputs):**
- `AgentIdentity` dataclass (used by compliance engine and integrations)
- `PermissionContext` dataclass (consumed by all middleware)
- `AuditEvent` Pydantic model (consumed by observability layer)
- `SandboxResult` dataclass (consumed by domain toolkits)

---

### `compliance-engineer`
**Purpose:** Build and maintain the Layer 2 Compliance Engine (`agentguard/compliance/`).

**Owns:**
- `agentguard/compliance/engine.py` — YAML policy evaluator, rule runner
- `agentguard/compliance/policies/owasp_agentic.yaml` — OWASP Top 10 for Agentic AI
- `agentguard/compliance/policies/finos_aigf_v2.yaml` — FINOS AI Governance Framework v2.0 (46 risks)
- `agentguard/compliance/policies/eu_ai_act.yaml` — EU AI Act high-risk requirements
- `agentguard/compliance/hitl.py` — human-in-the-loop escalation patterns and callbacks
- `agentguard/compliance/reporter.py` — compliance attestation report generator (PDF/JSON)
- `tests/unit/compliance/`

**Key constraints:**
- Policy files are the source of truth — engine evaluates them, never hardcodes rules
- Each policy rule must have: `id`, `name`, `severity` (critical/high/medium/low), `description`, `check` (Python expression or jq-style selector), `remediation`
- FINOS risk IDs must match the AIGF v2.0 spec exactly (e.g., `FINOS-AIGF-001` through `FINOS-AIGF-046`)
- EU AI Act rules must reference the correct Article and Annex numbers
- HITL escalation must be synchronous-safe (blocking) — it cannot be fire-and-forget

**Handoff contract (outputs):**
- `PolicyResult` Pydantic model: `{rule_id, passed, severity, evidence, remediation}`
- `ComplianceReport` Pydantic model: full structured attestation document
- `HitlEscalation` dataclass: approval request passed to the calling application

---

### `domain-expert`
**Purpose:** Build the Layer 3 Credit Risk Domain Toolkit (`agentguard/domains/finance/`).

**Owns:**
- `agentguard/domains/finance/credit_risk/agent_templates.py` — credit decisioning agent templates
- `agentguard/domains/finance/credit_risk/adverse_action.py` — adverse action notice generation (ECOA/Reg B compliant)
- `agentguard/domains/finance/credit_risk/model_validation.py` — SR 11-7 model validation agent patterns
- `agentguard/domains/finance/credit_risk/fairness.py` — disparate impact / disparate treatment analysis tools
- `agentguard/domains/finance/credit_risk/red_team.py` — credit AI adversarial evaluation suite (bias probes, monotonicity checks)
- `agentguard/domains/finance/synthetic/wgan_gp.py` — WGAN-GP tabular data generator
- `agentguard/domains/finance/synthetic/generators.py` — high-level synthetic data API (credit applications, loan performance)
- `agentguard/domains/finance/pii.py` — PII detection and masking (SSN, account#, routing#, DOB, full-name+address)
- `datasets/` — HuggingFace-ready synthetic benchmark datasets
- `examples/credit_decisioning/`
- `examples/adverse_action_generation/`
- `examples/model_validation_agent/`
- `tests/unit/domains/`

**Key constraints:**
- Domain terminology must be accurate: PD/LGD/EAD, CECL, ECOA, Regulation B, Fair Housing Act, SR 11-7, Basel IRB, ALLL/ACL
- Adverse action notices must cite specific, deterministic reasons ordered by impact (Regulation B requirement)
- PII masking must cover all Category 1 PII and FCRA-regulated data before any data reaches the audit log
- Synthetic credit data must include synthetic protected-class proxies for disparate impact testing — never infer real demographics
- Fairness metrics (demographic parity, equalized odds, calibration) must be computed and logged; document which metric was optimized and why
- All credit agent templates must be parameterizable — no hardcoded thresholds, institution names, or cut-off scores
- Model validation agents must follow SR 11-7 structure: conceptual soundness, ongoing monitoring, outcomes analysis
- WGAN-GP generates credit application features: FICO, DTI, LTV, income, employment_status, loan_purpose, delinquency_history
- The flagship domain is credit risk — credit decisioning, adverse action, model validation, and fairness analysis

**Handoff contract (outputs):**
- `SyntheticCreditDataset` — Pandas DataFrame with schema documented in `datasets/README.md`
- `CreditDecisioningAgent` — AgentGuard-wrapped agent class ready for MCP/A2A use
- `AdverseActionNotice` Pydantic model — ECOA-compliant adverse action document
- `FairnessReport` — disparate impact scorecard with 4/5ths rule calculations
- `ModelValidationReport` — SR 11-7-aligned validation findings

---

### `integration-builder`
**Purpose:** Build and maintain framework adapters and middleware (`agentguard/integrations/`).

**Owns:**
- `agentguard/integrations/mcp_middleware.py` — MCP protocol interceptor/wrapper
- `agentguard/integrations/a2a_middleware.py` — A2A protocol interceptor/wrapper
- `agentguard/integrations/langgraph.py` — LangGraph integration (decorator + graph wrapper)
- `agentguard/integrations/crewai.py` — CrewAI integration (tool wrapper + crew hook)
- `agentguard/integrations/google_adk.py` — Google ADK integration
- `examples/quickstart.py` — 5-minute getting-started example
- `tests/integration/` — integration tests (require Docker + LLM API key)
- `docs/` — integration guides per framework

**Key constraints:**
- MCP middleware must intercept at the `call_tool` boundary — before tool execution, after permission check
- A2A middleware must intercept at the `message_send` boundary between agents
- Each framework integration is an **adapter** — it must not import framework-specific code into `agentguard/core/`
- Integrations must be optional installs: `pip install agentguard[langgraph]`, `pip install agentguard[crewai]`
- Every integration must have a working end-to-end example that passes CI without a real LLM (use a mock LLM responder)

**Handoff contract (outputs):**
- `GovernedTool` wrapper class — drop-in replacement for any framework's tool definition
- `GovernedAgent` wrapper class — wraps any agent with AgentGuard governance
- Integration test results — must include a tool-call intercept, a permission-denied case, and an audit log verification

---

### `observability-engineer`
**Purpose:** Build the Layer 4 Observability stack (`agentguard/observability/`).

**Owns:**
- `agentguard/observability/tracer.py` — OpenTelemetry-native agent decision trace exporter
- `agentguard/observability/replay.py` — tool call replay and step-through debugger
- `agentguard/observability/dashboard.py` — metrics aggregator (cost, latency, policy violations)
- `agentguard/cli.py` — `agentguard` CLI (audit, policy, sandbox subcommands)
- `tests/unit/observability/`

**Key constraints:**
- OpenTelemetry is non-negotiable — do not use a proprietary tracing format
- Spans must follow the AgentGuard semantic conventions defined in `docs/observability/conventions.md`
- The replay debugger must work from audit log files alone — no live system required
- Dashboard output must support JSON (for piping) and Rich terminal rendering
- CLI must have `--output json` flag on every command for scripting compatibility
- Cost tracking must be LLM-provider-agnostic (pluggable token-cost lookup table)

**Handoff contract (outputs):**
- `AgentTrace` — OpenTelemetry-compatible span tree for a complete agent run
- `ReplaySession` — interactive or batch replay from audit log
- CLI commands: `agentguard audit show`, `agentguard audit replay`, `agentguard policy validate`, `agentguard policy report`

---

### `formal-verifier`
**Purpose:** Build and maintain the Z3-based formal policy verification module (`agentguard/compliance/formal_verifier.py`).

**Owns:**
- `agentguard/compliance/formal_verifier.py` — SMT-based policy and RBAC formal verifier
- `agentguard/compliance/z3_models.py` — Z3 sort and formula definitions for AgentGuard concepts
- `docs/formal_verification/` — documentation of what properties can be proven and how
- `tests/unit/compliance/test_formal_verifier.py`
- `examples/formal_verification/` — worked examples of verifying RBAC and policy properties

**Key constraints:**
- Import `z3` lazily — formal verification is an optional feature; core runtime must not require z3
- All Z3 encoding must be documented: explain what the formula encodes in plain English in a docstring
- Verification must be time-bounded — default 10-second timeout; configurable per check
- Expose three verification modes: (1) RBAC reachability, (2) policy consistency, (3) workflow safety
- Results must be human-readable: when Z3 finds a counterexample, translate it back to AgentGuard concepts
- Never block agent execution — verification runs as a static analysis tool, not at runtime

**What it can formally verify:**
1. **RBAC privilege escalation**: "Is there any sequence of role assignments that allows agent A to reach permission P without it being explicitly granted?" — encodes roles/permissions as bitvectors, checks satisfiability of forbidden states
2. **Policy consistency**: "Does this set of policy rules contain contradictions (rules that can never fire) or redundancies (rules always superseded by others)?" — encodes rules as logical formulas, checks for unsatisfiability
3. **Workflow safety properties**: "In this agent graph, can a node with role X ever reach a tool requiring permission Y without passing through a HITL node?" — encodes graph as reachability problem in Z3's fixed-point engine (µZ)
4. **Monotonicity constraints**: "Does this credit scoring agent's decision boundary maintain monotonicity (higher income → lower risk score) across all possible inputs in a defined range?" — encodes as quantified arithmetic formula
5. **Adverse action determinism**: "For any two identical applicant profiles, does this agent always produce the same adverse action reasons in the same order?" — encodes as functional consistency check

**Handoff contract (outputs):**
- `VerificationResult`: `{property, status: sat|unsat|timeout|unknown, counterexample?, proof_certificate?}`
- CLI: `agentguard verify rbac --config policy.yaml`, `agentguard verify workflow --graph graph.json`
- `VerificationReport` — full formal verification attestation document for regulatory submission

---

### `dataset-curator`
**Purpose:** Generate, document, and publish synthetic benchmark datasets to HuggingFace.

**Owns:**
- `datasets/synthetic_credit_applications_v1/` — consumer loan applications (200K rows, 8% default rate)
- `datasets/synthetic_loan_performance_v1/` — loan-level performance with vintage cohorts (500K rows)
- `datasets/credit_agent_compliance_eval_v1/` — 100 agent decision scenarios with expected policy results
- `datasets/README.md` — schema documentation, generation methodology, usage examples
- HuggingFace dataset cards (`README.md` in each dataset dir, YAML front-matter)

**Key constraints:**
- No real customer data — all synthetic, generated by the WGAN-GP in `domains/finance/synthetic/`
- Dataset cards must include: dataset description, languages, license (Apache 2.0), field descriptions, class distribution, generation methodology, known limitations, fairness documentation, citation BibTeX
- Every dataset must include a `generate.py` script so users can reproduce it
- Feature names must be generic — no bank names, no real institution-specific fields
- Include fairness documentation: synthetic protected-class proxies included for disparate impact testing; explain that proxies are themselves synthetic and should not be treated as demographic data
- Credit application schema: `application_id`, `fico_score`, `dti_ratio`, `ltv_ratio`, `annual_income`, `employment_status`, `loan_purpose`, `loan_amount`, `term_months`, `delinquency_24m`, `is_default [label]`
- Push to HuggingFace Hub: `dataset.push_to_hub("agentguard/synthetic-credit-applications")`

---

## Agent Coordination Rules

1. **`security-architect` builds first.** No other agent should write to `agentguard/core/` until the core module interfaces are stable (after milestone M1).

2. **`compliance-engineer` depends on `AuditEvent` from `security-architect`.** Coordinate on the `AuditEvent` schema before either agent writes production code.

3. **`formal-verifier` depends on the policy YAML schema from `compliance-engineer`.** Z3 encoding must match the policy rule structure exactly. Build after `compliance/engine.py` is stable.

4. **`domain-expert` depends on `SandboxResult` and `PermissionContext` from `security-architect`.** The credit decisioning agent templates must use the governance layer, not bypass it.

5. **`integration-builder` is the last to write production code** (after core, compliance, formal verification, and at least the credit risk domain module are stable). Integration tests validate the full stack.

6. **`observability-engineer` can work in parallel with `compliance-engineer`** after `AuditEvent` schema is locked. The tracer consumes audit events; it does not produce them.

7. **`dataset-curator` is fully parallel** — synthetic data generation has no dependency on the governance runtime. Start this on Day 1 for early HuggingFace presence.

8. **All agents write tests for their own layer.** The `integration-builder` additionally writes cross-layer integration tests.

9. **No agent modifies another agent's owned files** without an explicit ADR entry in `DECISIONS.md`.

---

## Shared Contracts (Lock These Early)

These interfaces must be agreed upon and locked before parallel development begins. Treat them as API contracts — breaking changes require a major version bump.

```python
# agentguard/models.py — shared Pydantic models

class AgentIdentity(BaseModel):
    agent_id: str
    name: str
    roles: list[str]
    metadata: dict[str, str] = {}

class PermissionContext(BaseModel):
    agent: AgentIdentity
    requested_action: str
    resource: str
    context: dict[str, Any] = {}
    granted: bool = False
    reason: str = ""

class AuditEvent(BaseModel):
    event_id: str          # UUID
    timestamp: datetime    # UTC
    agent_id: str
    action: str
    resource: str
    permission_context: PermissionContext
    result: Literal["allowed", "denied", "escalated", "error"]
    policy_results: list[PolicyResult] = []
    duration_ms: float
    trace_id: str          # OpenTelemetry trace ID

class PolicyResult(BaseModel):
    rule_id: str
    rule_name: str
    passed: bool
    severity: Literal["critical", "high", "medium", "low"]
    evidence: dict[str, Any]
    remediation: str
```
