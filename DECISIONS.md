# AgentGuard — Architectural Decision Records (ADRs)

This document logs all significant architectural decisions made during AgentGuard's development. Every decision includes context, the options considered, the chosen option, and the consequences. When Claude Code agents make architectural choices, they must log them here.

**Format:** `ADR-NNN — Title`
**Status options:** `Proposed | Accepted | Deprecated | Superseded by ADR-NNN`

---

## ADR-001 — Python as the primary implementation language
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** AgentGuard needs to integrate with LangGraph, CrewAI, Google ADK, MCP, and A2A — all of which have Python SDKs as their primary interface. The target users are ML engineers and AI practitioners who overwhelmingly work in Python.

**Decision:** Python 3.11+ as the primary language. TypeScript/JavaScript bindings may be added in v1.1 via a thin wrapper, but the core is Python-only in v0.x.

**Consequences:**
- Positive: Native integration with all major agent frameworks; no FFI overhead
- Positive: `asyncio` ecosystem fits naturally with async agent patterns
- Negative: Node.js agent ecosystems (e.g., some MCP implementations) require a bridge
- Negative: Performance-critical sandbox code may need C extension later

---

## ADR-002 — Pydantic v2 for all data models
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** Data validation is critical for a security/compliance tool. Invalid data entering the audit log or compliance engine is a security risk.

**Decision:** All public-facing data models use Pydantic v2 BaseModel. Internal dataclasses are acceptable for purely internal structures not crossing API boundaries.

**Consequences:**
- Positive: Runtime type validation catches bad data at boundaries
- Positive: Automatic JSON serialization for audit logs and API responses
- Positive: JSON Schema generation for policy rule validation
- Negative: Pydantic v2 migration pain if users have Pydantic v1 dependencies (document clearly)

---

## ADR-003 — Deny-first RBAC with deny-override semantics
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** Access control for AI agents in regulated environments must default to restriction. The alternative (allow-first, deny-explicit) creates a growing attack surface as new tools are added.

**Options considered:**
1. Allow-first, deny-explicit (ACL model)
2. Deny-first, allow-explicit (zero-trust model) ← chosen
3. Capability-based (object capabilities)

**Decision:** Deny-first with deny-override. An agent has no permissions unless explicitly granted. If both an allow and a deny rule match, deny wins. This mirrors AWS IAM's explicit deny model.

**Consequences:**
- Positive: New tools are automatically restricted until granted
- Positive: Clear mental model for security practitioners
- Negative: Onboarding requires explicit permission grants; steeper initial configuration
- Mitigation: Provide well-documented role templates for common agent types

---

## ADR-004 — Audit log-first, act-second execution order
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** In regulated environments, the audit trail must be complete even if the system crashes mid-execution. If we log after execution, a crash between execution and logging creates an unaudited action.

**Decision:** Write the audit event (with `result="allowed"`) BEFORE executing the tool in the sandbox. If the sandbox execution fails, write a follow-up event with `result="error"`. If the log write fails, the action is blocked.

**Consequences:**
- Positive: Audit trail is complete even under failure conditions
- Positive: Regulators can reconstruct all attempted actions, not just successful ones
- Negative: Theoretical false-positive in audit log if log write succeeds but action fails before sandbox start (mitigated by follow-up error event)
- Negative: Adds ~1-5ms latency to every tool call for the log write

---

## ADR-005 — Policy rules stored as YAML files in version control
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** Compliance rules must be auditable, reviewable, and diffable. Database-stored rules are opaque to the development workflow.

**Options considered:**
1. YAML files in repository ← chosen
2. Database (PostgreSQL) with admin UI
3. Rego (OPA) — powerful but steep learning curve
4. Python code (functions)

**Decision:** YAML files with a defined schema. The compliance engine loads and validates them at startup. Custom organizational policies extend the built-in sets.

**Consequences:**
- Positive: Git history of policy changes; PR review process for compliance rule changes
- Positive: Easy to read and write for compliance officers (not just engineers)
- Positive: Can be audited by external regulators via repository access
- Negative: Less expressive than Rego for complex multi-condition rules
- Negative: No live rule updates (restart required) — acceptable for v0.x
- Future: Consider OPA integration in v1.x for organizations needing dynamic policy

---

## ADR-006 — Docker as the default sandbox backend
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** Sandboxed tool execution is the primary defense against runaway agents and privilege escalation. The sandbox must be strong enough for production regulated-industry use.

**Options considered:**
1. Docker (container isolation) ← chosen as default
2. Wasm (wasmtime-py) — lighter, less isolation
3. gVisor — stronger isolation, complex setup
4. Firecracker microVMs — strongest isolation, requires KVM, complex
5. No sandbox (subprocess with limited permissions)

**Decision:** Docker as the default backend, Wasm as a lightweight alternative for pure-Python tools. Provide a `SandboxBackend` protocol for organizations to plug in gVisor or Firecracker.

**Consequences:**
- Positive: Docker is available in virtually all deployment environments
- Positive: Strong isolation; well-understood security model
- Negative: Docker daemon dependency; cold start latency (~100-500ms per tool call)
- Negative: Not suitable for serverless/Lambda environments → document Wasm backend for those
- Mitigation: Container pool pre-warming for latency-sensitive deployments

---

## ADR-007 — HMAC chain for audit log tamper detection
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** A governance tool's own audit log is a high-value target for tampering. Simple append-only files can be modified. We need tamper-evidence without requiring a distributed ledger.

**Decision:** Each audit event includes a SHA-256 HMAC of the previous event plus the current event's content. Verification tool (`agentguard audit verify`) walks the chain and reports breaks.

**Consequences:**
- Positive: Tamper-evident without blockchain complexity
- Positive: Verification is fast and offline
- Negative: HMAC key management is a new operational concern (document key rotation)
- Negative: Chain break makes all subsequent events suspect (by design — this is the alert)

---

## ADR-008 — Financial services as flagship domain; regulated-industry pattern for others
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** We need domain depth for credibility and adoption, but want the core to be general-purpose. The project owner has 17 years of financial services expertise — this is the unique differentiator.

**Decision:** Build the financial services domain module (`agentguard/domains/finance/`) to production quality. Define a `DomainModule` protocol that healthcare, government, and energy can implement identically. Document the protocol clearly so external contributors can add domains.

**Consequences:**
- Positive: Financial services anchoring provides credibility with the most regulated domain
- Positive: Bank and financial institution contributors are likely early adopters
- Positive: FINOS affiliation is accessible — FINOS explicitly supports open-source financial AI tooling
- Negative: Perception risk: "this is a finance tool" — mitigate with general-purpose core framing
- Positive: Healthcare and government modules can be accepted as community contributions in v0.3+

---

## ADR-009 — OpenTelemetry as the observability standard
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** Observability tooling must integrate with existing enterprise monitoring stacks (Datadog, Jaeger, Grafana, Honeycomb). Building a proprietary tracing format creates integration burden.

**Decision:** All traces and spans use the OpenTelemetry SDK. Custom attributes follow the `agentguard.*` semantic convention namespace (documented in `docs/observability/conventions.md`). No proprietary trace format.

**Consequences:**
- Positive: Works out-of-box with any OTel-compatible backend
- Positive: Enterprise buyers can route to their existing observability platform
- Negative: OTel SDK adds ~10MB to install size
- Negative: OTel configuration (exporters, samplers) can be complex for new users — provide good defaults

---

## ADR-010 — MIT license
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** License choice affects commercial adoption, contributor willingness, and compatibility with downstream projects.

**Options considered:**
1. MIT ← chosen
2. Apache 2.0 — adds patent grant clause
3. AGPL — strong copyleft; would block many enterprise adopters
4. BSL (Business Source License) — delayed open source; harmful to community trust

**Decision:** MIT license. Maximum permissiveness to encourage adoption in regulated industries where legal review of dependencies is common and GPL-family licenses often fail.

**Consequences:**
- Positive: No barriers to commercial use; fastest enterprise legal approval
- Positive: Compatible with all major agent framework licenses (LangGraph: MIT, CrewAI: MIT, MCP SDK: MIT)
- Negative: No copyleft protection — commercial actors can fork without contributing back
- Mitigation: Strong community brand; contributor recognition; FINOS project affiliation

---

## ADR-011 — WGAN-GP (not CTGAN or vanilla GAN) for tabular synthetic data
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** Generating realistic synthetic financial transaction data requires a GAN architecture suited to highly imbalanced tabular data. Multiple architectures were considered.

**Options considered:**
1. CTGAN (SDV library) — most popular, but treats all columns uniformly
2. TVAE (SDV library) — VAE-based, faster training but lower fidelity
3. Vanilla GAN — training instability; mode collapse common
4. WGAN with weight clipping — better stability, but weight clipping limits network capacity
5. WGAN-GP (gradient penalty) ← chosen
6. TabDDPM (diffusion) — state of the art but requires significant compute

**Decision:** WGAN-GP with conditional generation. Gradient penalty provides stable training. Conditional generation (on the fraud label) allows controlled class imbalance in output. Architecture is a TabGAN variant with embedding layers for categorical features.

**Consequences:**
- Positive: Stable training on 4GB VRAM hardware (GTX 970) for typical fraud dataset sizes
- Positive: Well-understood architecture; reviewable implementation
- Positive: Conditional generation essential for fraud use case (1:500 class ratio)
- Negative: Not state-of-the-art fidelity vs. diffusion models
- Negative: Requires careful hyperparameter tuning per dataset
- Future: TabDDPM backend as optional `agentguard[diffusion]` install when GPU compute available

---

## ADR-012 — Optional extras install pattern for integrations
**Status:** Accepted  
**Date:** 2026-04-08

**Context:** AgentGuard integrates with multiple frameworks (LangGraph, CrewAI, ADK). Requiring all framework dependencies in the base install would create conflicts and bloat.

**Decision:**
```
pip install agentguard              # core only
pip install agentguard[langgraph]   # + LangGraph adapter
pip install agentguard[crewai]      # + CrewAI adapter  
pip install agentguard[adk]         # + Google ADK adapter
pip install agentguard[finance]     # + financial domain toolkit + WGAN-GP deps
pip install agentguard[observability]  # + OTel exporters + dashboard
pip install agentguard[all]         # everything
```

**Consequences:**
- Positive: Minimal install footprint for core use cases
- Positive: Avoids framework version conflicts
- Negative: More complex pyproject.toml; requires careful optional dependency management
- Negative: Integration test matrix grows (N frameworks × M Python versions)

---

---

## ADR-013 — Z3 SMT solver for formal policy and RBAC verification
**Status:** Accepted  
**Date:** 2026-04-10

**Context:** Runtime policy checks answer "was this action allowed?" but cannot answer "is it *possible* to reach a forbidden state given these policies?" — a question critical for regulated environments where exhaustive testing is insufficient for compliance attestation. Traditional testing cannot prove absence of privilege escalation paths.

**Options considered:**
1. No formal verification — rely solely on tests ← insufficient for regulated-industry claims
2. Alloy (relational model checker) — expressive but requires separate toolchain and non-Python DSL
3. TLA+ — powerful for distributed systems; steep learning curve; not Python-native
4. Dafny — verification-aware language; requires rewriting core logic
5. OPA/Rego with exhaustive evaluation — bounded, not a proof
6. Z3 SMT solver (Microsoft Research) ← chosen

**Decision:** Use Z3 via `z3-solver` (pure Python, no compilation, MIT license) as the formal verification backend. Z3 can encode RBAC permissions as bitvectors, policies as logical formulas, and agent graphs as reachability problems in its µZ fixed-point engine. Import lazily — `from agentguard.compliance.formal_verifier import verify` — so z3 is not a core dependency.

**Five provable properties:**
1. RBAC privilege escalation absence
2. Policy set consistency (no contradictions or dead rules)
3. Workflow safety (e.g., no path to PII without HITL)
4. Credit model monotonicity (regulatory requirement for explainability)
5. Adverse action determinism (Regulation B compliance)

**Consequences:**
- Positive: Unique differentiator — no other open-source agent framework offers formal verification
- Positive: Directly addresses regulators' demand for mathematical evidence of safety properties
- Positive: Publishable: "Formal Verification of AI Agent Governance Policies Using SMT Solving" is a credible workshop paper (NeurIPS Safe Generative AI, ICLR RE-Align)
- Positive: Pure Python, 10MB install, runs on CPU — compatible with GTX 970 constraint
- Negative: Z3 encoding complexity; requires expertise to write new property encodings
- Negative: Verification of large policy sets may hit 10-second timeout; document scope limitations
- Negative: Properties proven over *models* of agent behavior, not actual execution — soundness depends on encoding accuracy

---

## ADR-014 — Credit risk as flagship domain (replacing fraud detection)
**Status:** Accepted  
**Date:** 2026-04-10

**Context:** The project owner currently works at a bank leading AI initiatives in an area that includes fraud. Building fraud detection tooling as an open-source project creates potential conflict of interest and IP concerns with the current employer, even when using entirely synthetic data and general methodologies.

**Decision:** Replace all fraud detection, AML, SAR, and BSA-related use cases in the domain toolkit with credit risk use cases: credit decisioning agents, adverse action generation (ECOA/Reg B), SR 11-7 model validation workflows, and fairness analysis for credit models. The synthetic data generator targets credit application and loan performance data rather than transaction monitoring data.

**Why credit risk is equally strong or stronger:**
- Credit scoring is explicitly named as High-Risk AI in EU AI Act Annex III — regulatory stakes are identical
- ECOA/Regulation B adverse action requirements create concrete, verifiable compliance rules Z3 can formally prove
- SR 11-7 model validation is a well-defined regulatory obligation that maps cleanly to an agent workflow
- Credit model fairness (disparate impact under ECOA/FHA) is a major active regulatory enforcement area
- Synthetic credit data (applications, loan performance) is clearly non-proprietary and has no resemblance to employer data
- The AI4Finance Foundation (19K+ stars on FinGPT) has strong credit risk representation, providing community on-ramp

**Consequences:**
- Positive: No conflict of interest or IP concerns with current employer
- Positive: Credit risk domain has stronger formal verification opportunities (monotonicity, determinism)
- Positive: ECOA/FHA fairness requirements are more concrete and legible to regulators than AML rules
- Negative: Loses AML/SAR use case which has strong industry demand
- Negative: Credit decisioning has more established commercial tools (Zest AI, Upstart) — more competitive space
- Mitigation: AgentGuard governs the *agent* performing credit decisions, not the credit model itself — this is a different, less competitive layer

*When you (Claude Code) make a new architectural decision, append it here following the same format. Increment the ADR number sequentially.*
