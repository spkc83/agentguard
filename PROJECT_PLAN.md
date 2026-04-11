# AgentGuard — 12-Month Project Plan

**Commitment:** ~10 hours/week  
**Philosophy:** Ship early, iterate publicly. Each milestone is a releasable version. HuggingFace and GitHub presence starts at Month 1, not Month 12.

---

## Milestone Overview

| Milestone | Version | Target Month | Theme |
|-----------|---------|-------------|-------|
| M0 | — | Week 1 | Project scaffolding and first commit |
| M1 | v0.1.0 | Month 1 | Audit logger + RBAC MVP |
| M2 | v0.2.0 | Month 3 | Full security runtime + MCP middleware |
| M3 | v0.3.0 | Month 5 | Compliance engine + policy sets |
| M4 | v0.4.0 | Month 7 | Financial domain toolkit + synthetic data |
| M5 | v0.5.0 | Month 9 | Framework integrations (LangGraph, CrewAI, ADK) |
| M6 | v1.0.0 | Month 12 | Observability, stability, production-ready |

---

## M0 — Week 1: Project Scaffolding
**Goal:** First commit live on GitHub. Project is findable, professional, and cloneable.

### Tasks
- [ ] Create GitHub repository: `agentguard` (public, MIT license)
- [ ] Initialize Python package with `pyproject.toml` (using `hatchling` build backend)
- [ ] Set up `ruff`, `mypy`, `pytest` in dev dependencies
- [ ] Create GitHub Actions CI workflow (`ci.yml`): lint → type check → test
- [ ] Write initial `README.md` with: what it is, why it exists, roadmap badge, "coming soon" install section
- [ ] Add `CLAUDE.md`, `AGENTS.md`, `ARCHITECTURE.md`, `DECISIONS.md` to repo
- [ ] Create `agentguard/__init__.py` with version and `__all__`
- [ ] Create `agentguard/exceptions.py` with base exception hierarchy
- [ ] Add `.github/ISSUE_TEMPLATE/` (bug report, feature request, integration request)
- [ ] Add `CONTRIBUTING.md` with dev setup instructions
- [ ] Push `datasets/` directory stub with placeholder `README.md`

**HuggingFace action:** Create HuggingFace organization `agentguard`. Reserve namespace.

**Definition of done:** `pip install -e ".[dev]"` works. `pytest` runs (0 tests, 0 failures). CI passes. README renders correctly on GitHub.

---

## M1 — Month 1: Audit Logger + RBAC MVP (v0.1.0)
**Goal:** The two most fundamental components work end-to-end. A developer can register an agent identity, define roles, check permissions, and get a tamper-evident audit log.

### Tasks

**Week 2: Core models and audit logger**
- [ ] Define shared Pydantic models in `agentguard/models.py`: `AgentIdentity`, `PermissionContext`, `AuditEvent`, `PolicyResult`
- [ ] Implement `agentguard/core/audit.py`:
  - `AppendOnlyAuditLog` class with file backend
  - HMAC chain (SHA-256, key from env var `AGENTGUARD_AUDIT_KEY`)
  - `async def write(event: AuditEvent) -> None`
  - `async def verify_chain() -> ChainVerificationResult`
- [ ] Unit tests for audit logger: write events, verify chain, detect tampering
- [ ] `agentguard audit verify` CLI command stub

**Week 3: Identity and RBAC**
- [ ] Implement `agentguard/core/identity.py`:
  - `AgentRegistry` — in-memory registry for v0.1; file-backed in v0.2
  - `async def register(name, roles, metadata) -> AgentIdentity`
  - `async def resolve(agent_id) -> AgentIdentity`
- [ ] Implement `agentguard/core/rbac.py`:
  - `Permission` and `Role` models
  - `PermissionChecker` with deny-override resolution
  - `async def check(identity, action, resource) -> PermissionContext`
  - Built-in roles: `credit-analyst`, `credit-reviewer`, `system-agent`, `readonly`
- [ ] Unit tests: permission grant, permission deny, deny-override, role inheritance
- [ ] Integration test: register agent → check permission → write audit event

**Week 4: Polish and release**
- [ ] Update `README.md` with real code example (5 lines, working)
- [ ] Write `examples/quickstart.py` — register agent, check permission, show audit log
- [ ] Add `agentguard audit show --agent-id` CLI command
- [ ] Publish to PyPI: `pip install agentguard==0.1.0`
- [ ] Write HuggingFace blog post draft: "AgentGuard: Why AI agents need a security runtime"

**HuggingFace action (Month 1 end):**
- Push first synthetic dataset: `agentguard/synthetic-credit-applications-v1` (generate with simple SMOTE first; WGAN-GP in M4)
- Dataset card with full documentation
- Post to r/MachineLearning, r/LocalLLaMA — "I built a governance middleware for AI agents"

**Definition of done:** `pip install agentguard` works. Quickstart example runs in < 10 lines. 80%+ test coverage on `core/audit.py` and `core/rbac.py`. PyPI published.

---

## M2 — Month 3: Full Security Runtime + MCP Middleware (v0.2.0)
**Goal:** Complete Layer 1. A real MCP-based agent is governed end-to-end. Sandbox executes tools in Docker.

### Tasks

**Month 2, Week 1-2: Circuit breaker + sandbox**
- [ ] Implement `agentguard/core/circuit_breaker.py`:
  - `CircuitBreaker` with states: CLOSED, OPEN, HALF_OPEN
  - Configurable failure threshold, timeout, success threshold
  - `async def call(fn, *args) -> result | raise CircuitOpenError`
  - Rate limiter: token bucket per agent identity
- [ ] Implement `agentguard/core/sandbox.py`:
  - `SandboxBackend` protocol
  - `DockerSandboxBackend`: spawn container, mount temp volume, enforce timeout, collect result
  - `WasmSandboxBackend`: wasmtime-py execution
  - `SandboxResult` model with stdout, stderr, exit_code, duration_ms
- [ ] Red team tests: sandbox escape attempts (network access, file system escape, process spawn)

**Month 2, Week 3-4: MCP middleware + file-backed registry**
- [ ] Implement `agentguard/integrations/mcp_middleware.py`:
  - `GovernedMcpClient` wrapping `mcp.ClientSession`
  - Intercepts `call_tool` → identity resolve → RBAC → policy check → audit → sandbox → execute
  - Drop-in replacement: `async with GovernedMcpClient(session, agent_id="...") as client:`
- [ ] Upgrade `AgentRegistry` to file-backed (JSON file, atomically written)
- [ ] CLI: `agentguard audit replay --log <file>` (basic version)
- [ ] Integration test: real MCP server + governed client + permission denied scenario + audit log verification

**Month 3: Polish and release**
- [ ] Performance benchmark: measure governance overhead per tool call (target: < 20ms p99 excluding sandbox)
- [ ] Docker sandbox integration tests in CI (GH Actions with Docker)
- [ ] Update README with architecture diagram (ASCII or Mermaid)
- [ ] Publish v0.2.0 to PyPI
- [ ] Submit to `awesome-mcp-servers` list and similar community lists
- [ ] Write technical blog post: "How we built tamper-evident audit logging for AI agents"

**HuggingFace action:**
- Publish interactive Space (Gradio): paste an agent config, see permission analysis and policy violations
- Submit to HuggingFace `spaces` trending via social media

**Definition of done:** MCP middleware integration test passes with real Docker sandbox. Governance overhead < 20ms. 85%+ coverage on all `core/` modules.

---

## M3 — Month 5: Compliance Engine + Formal Verifier + Policy Sets (v0.3.0)
**Goal:** Complete Layer 2. Agents can be evaluated against OWASP Agentic AI, FINOS AIGF v2.0, and EU AI Act rules. Formal policy verification via Z3 proves safety properties statically. Compliance reports generated.

### Tasks

**Month 4:**
- [ ] Design and document policy YAML schema (JSON Schema validation)
- [ ] Implement `agentguard/compliance/engine.py`:
  - `PolicyEngine` loads YAML policy files at startup
  - `async def evaluate(audit_event: AuditEvent) -> list[PolicyResult]`
  - Plugin architecture: `check` field dispatches to typed check handlers
- [ ] Implement OWASP Top 10 Agentic AI policy file (10 rules, all check types exercised)
- [ ] Implement FINOS AIGF v2.0 policy file (46 risks, prioritize top 15 for v0.3)
- [ ] Implement `agentguard/compliance/z3_models.py` — Z3 sorts and formula helpers for AgentGuard concepts
- [ ] Unit tests for each policy rule type

**Month 5:**
- [ ] Implement `agentguard/compliance/formal_verifier.py`:
  - Property 1: RBAC privilege escalation absence (bitvector encoding)
  - Property 2: Policy set consistency (contradiction and dead-rule detection)
  - Property 3: Workflow safety — "no path to resource X without HITL" (µZ reachability)
  - `VerificationResult` model with counterexample translation to human-readable terms
  - 10-second timeout default; configurable
- [ ] Implement EU AI Act high-risk rules (Articles 9, 10, 13, 14, 17)
- [ ] Implement `agentguard/compliance/hitl.py`:
  - `HitlEscalation` model
  - `async def escalate(event, handler) -> ApprovalDecision`
  - Built-in handlers: `LogAndApproveHandler` (auto-approve + log, for dev), `SlackHandler` stub
- [ ] Implement `agentguard/compliance/reporter.py`:
  - `ComplianceReporter.generate_report(audit_log, time_range) -> ComplianceReport`
  - Output formats: JSON, Markdown
- [ ] CLI: `agentguard policy validate`, `agentguard policy report`, `agentguard verify rbac`, `agentguard verify policy`, `agentguard verify workflow`
- [ ] End-to-end test: agent performs 10 tool calls → compliance report → FINOS-AIGF rule evaluations → Z3 proves no privilege escalation path exists

**HuggingFace action:**
- Update Gradio Space to include compliance analysis + formal verification output
- Publish dataset: `agentguard/credit-agent-compliance-eval-v1` (100 agent decision scenarios with expected policy results)
- Write HuggingFace blog post: "Formal Verification of AI Agent Governance Policies Using Z3"

**Definition of done:** All 3 policy sets load without errors. Z3 verifier proves escalation-absence on the built-in role templates (unsat result). Compliance report generates from audit log. 85%+ coverage on `compliance/`.

---

## M4 — Month 7: Credit Risk Domain Toolkit + Synthetic Data (v0.4.0)
**Goal:** Complete Layer 3 for credit risk. Credit decisioning agent template works end-to-end with ECOA-compliant adverse action generation. WGAN-GP generates realistic synthetic credit application data. Z3 formally verifies monotonicity and adverse action determinism.

### Tasks

**Month 6:**
- [ ] Implement `agentguard/domains/finance/synthetic/wgan_gp.py`:
  - Generator and Critic networks (PyTorch, tabular architecture with embedding layers for categorical features)
  - Gradient penalty training loop (λ=10)
  - Conditional generation on default label
  - `fit(df, label_col, default_rate_target) -> trained_model`
  - `generate(n_samples, default_rate) -> pd.DataFrame`
- [ ] Generate and publish `agentguard/synthetic-credit-applications-v1` (WGAN-GP, 200K rows, 8% default rate)
- [ ] Implement `agentguard/domains/finance/pii.py`: detect and mask all Category 1 PII + FCRA-regulated data
- [ ] Implement `agentguard/domains/finance/credit_risk/fairness.py`:
  - Disparate impact test (4/5ths rule)
  - Equalized odds calculation
  - Score calibration by group
  - `FairnessReport` Pydantic model

**Month 7:**
- [ ] Implement `agentguard/domains/finance/credit_risk/agent_templates.py`:
  - `CreditDecisioningAgent`: AgentGuard-wrapped agent with bureau pull, income verify, PD model, decision tools
  - Configurable PD thresholds (auto-approve/review/decline cutoffs)
  - HITL trigger: review band
- [ ] Implement `agentguard/domains/finance/credit_risk/adverse_action.py`:
  - `AdverseActionGenerator`: feature importance → reason code mapping → ordered notice
  - `AdverseActionNotice` Pydantic model (ECOA/Reg B aligned)
  - Determinism: same input always produces same ordered reasons
- [ ] Implement `agentguard/domains/finance/credit_risk/model_validation.py`:
  - `ModelValidationAgent`: SR 11-7 structured validation workflow
  - Gini, KS, AUC, PSI, vintage analysis, fairness analysis sub-tools
  - `ModelValidationReport` with SR 11-7 section mapping
- [ ] Add Z3 properties 4 and 5 to `formal_verifier.py`: monotonicity check + adverse action determinism
- [ ] End-to-end demo: `examples/credit_decisioning/` — synthetic application, decision, adverse action notice, fairness report
- [ ] Publish `agentguard[finance]` to PyPI

**HuggingFace action:**
- Publish 2 synthetic datasets (credit applications, loan performance with vintage cohorts)
- Write HuggingFace blog post: "Synthetic Credit Data Generation with WGAN-GP for Fair Lending AI"

**Definition of done:** Full credit decisioning example runs end-to-end. Adverse action notice generates with deterministic reason ordering. Z3 proves monotonicity holds for the example PD model's decision boundary. WGAN-GP trains in < 30 minutes on CPU for 10K-row seed dataset.

---

## M5 — Month 9: Framework Integrations (v0.5.0)
**Goal:** LangGraph, CrewAI, and Google ADK have official AgentGuard integrations. Developers can add governance to existing agent code with minimal changes.

### Tasks

**Month 8:**
- [ ] Implement `agentguard/integrations/langgraph.py`:
  - `@governed_node` decorator for LangGraph nodes
  - `GovernedStateGraph` wrapper for full graph governance
  - Example: `examples/langgraph_credit_decisioning.py`
- [ ] Implement `agentguard/integrations/crewai.py`:
  - `GovernedTool` wrapper for CrewAI tools
  - `GovernedCrew` wrapper applying governance to all agents in a crew
  - Example: `examples/crewai_credit_crew.py`

**Month 9:**
- [ ] Implement `agentguard/integrations/google_adk.py`:
  - ADK `BaseTool` subclass with governance built in
  - ADK agent runner wrapper
  - Example: `examples/adk_credit_agent.py`
- [ ] Implement `agentguard/integrations/a2a_middleware.py`:
  - A2A `MessageSend` interceptor
  - Agent-to-agent trust graph enforcement
- [ ] Integration test matrix: LangGraph + CrewAI + ADK × Docker sandbox × FINOS compliance
- [ ] Submit to FINOS as a project under FINOS AI governance initiative

**HuggingFace action:**
- Update Gradio Space to demo all three framework integrations
- Publish `agentguard/agent-security-red-team-suite` dataset (adversarial scenarios for eval)

**Definition of done:** All three framework integrations have working examples. CI passes integration tests for each. FINOS submission made.

---

## M6 — Month 12: Observability + v1.0.0
**Goal:** Production-ready. Observability stack complete. Performance optimized. Documentation complete. Conference talk submitted.

### Tasks

**Month 10:**
- [ ] Implement `agentguard/observability/tracer.py`:
  - OpenTelemetry SDK integration
  - `agentguard.*` semantic attribute namespace
  - Auto-export to OTLP endpoint (configurable)
- [ ] Implement `agentguard/observability/replay.py`:
  - `agentguard audit replay` full interactive mode
  - Step-through with Rich terminal rendering
  - JSON output mode

**Month 11:**
- [ ] Implement `agentguard/observability/dashboard.py`:
  - `agentguard dashboard` — Rich terminal dashboard
  - Metrics: tool call volume, permission denials, policy violations, cost, latency
  - Configurable time windows
- [ ] Performance optimization pass: profile governance overhead; target < 10ms p99 for in-memory path
- [ ] Security audit: run `pip-audit`, review sandbox escape test suite, HMAC key rotation docs

**Month 12:**
- [ ] Complete documentation: all public APIs, all policy rules, all integration guides
- [ ] v1.0.0 stability review: deprecate any unstable APIs, finalize versioning contract
- [ ] Publish v1.0.0 to PyPI
- [ ] Submit conference talk to AI Engineer Summit: "Building a Governance Runtime for AI Agents in Regulated Industries"
- [ ] Write comprehensive HuggingFace blog post on v1.0.0 release
- [ ] Target: 3,000+ GitHub stars, 5+ external contributors, 1+ FINOS member bank as contributor

**Definition of done:** v1.0.0 on PyPI. All docs complete. Conference talk submitted. 90%+ coverage on `core/` and `compliance/`. Performance target met.

---

## Continuous Activities (Every Month)

**GitHub community:**
- Respond to issues within 48 hours
- Label `good first issue` for onboarding tasks
- Weekly release notes (even for patch releases)
- Maintain `CHANGELOG.md`

**Content and discovery:**
- Monthly blog post (HuggingFace blog or personal blog cross-posted)
- Weekly tweet/LinkedIn post on project progress, learnings, or financial AI governance topics
- Engage on r/MachineLearning, r/LocalLLaMA, and AI Engineer Discord

**HuggingFace:**
- Keep datasets updated with each major release
- Update Space demo with new features
- Monitor dataset download counts as adoption signal

---

## Success Metrics by Milestone

| Milestone | GitHub Stars | PyPI Downloads/month | HuggingFace Downloads |
|-----------|-------------|---------------------|----------------------|
| M1 (Month 1) | 50–200 | 100–500 | 500–2K (dataset) |
| M2 (Month 3) | 200–800 | 500–2K | 2K–10K |
| M3 (Month 5) | 500–1,500 | 1K–5K | 5K–20K |
| M4 (Month 7) | 1,000–2,500 | 2K–10K | 10K–50K |
| M5 (Month 9) | 2,000–4,000 | 5K–20K | 20K–100K |
| M6 (Month 12) | 3,000–8,000 | 10K–50K | 50K+ |

These are realistic ranges, not targets. A single HN or Reddit frontpage moment can 10x these numbers instantly. The goal is to consistently ship quality and let adoption follow.
