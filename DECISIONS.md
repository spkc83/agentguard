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

**Decision:** WGAN-GP with conditional generation. Gradient penalty provides stable training. Conditional generation (on the default label) allows controlled class imbalance in output. Architecture is a TabGAN variant with embedding layers for categorical features.

**Consequences:**
- Positive: Stable training on 4GB VRAM hardware (GTX 970) for typical credit dataset sizes
- Positive: Well-understood architecture; reviewable implementation
- Positive: Conditional generation essential for credit risk use case (imbalanced default rates)
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

## ADR-014 — Credit risk as flagship financial services domain
**Status:** Accepted
**Date:** 2026-04-10

**Context:** The flagship domain module needs a well-defined regulatory environment with concrete compliance requirements that can be formally verified. Credit risk offers this: EU AI Act Annex III explicitly names credit scoring as High-Risk AI, ECOA/Regulation B mandate adverse action notices with deterministic reason ordering, and SR 11-7 requires structured model validation workflows.

**Decision:** Credit risk is the flagship financial services domain: credit decisioning agents, adverse action generation (ECOA/Reg B), SR 11-7 model validation workflows, and fairness analysis for credit models. The synthetic data generator targets credit application and loan performance data.

**Why credit risk:**
- Credit scoring is explicitly named as High-Risk AI in EU AI Act Annex III
- ECOA/Regulation B adverse action requirements create concrete, verifiable compliance rules Z3 can formally prove
- SR 11-7 model validation is a well-defined regulatory obligation that maps cleanly to an agent workflow
- Credit model fairness (disparate impact under ECOA/FHA) is a major active regulatory enforcement area
- Synthetic credit data (applications, loan performance) is clearly non-proprietary
- The AI4Finance Foundation (19K+ stars on FinGPT) has strong credit risk representation, providing community on-ramp

**Consequences:**
- Positive: Strong formal verification opportunities (monotonicity, adverse action determinism)
- Positive: ECOA/FHA fairness requirements are concrete and legible to regulators
- Positive: No IP concerns — credit risk tooling is a well-established open-source domain
- Negative: Credit decisioning has established commercial tools (Zest AI, Upstart) — competitive space
- Mitigation: AgentGuard governs the *agent* performing credit decisions, not the credit model itself — this is a different, less competitive layer

---

## ADR-015 — YAML policy-as-code with typed check handlers
**Status:** Accepted
**Date:** 2026-04-14

**Context:** The compliance engine needs to evaluate audit events against policy rules loaded from YAML files. Rules need different evaluation strategies: some check action patterns, others scan for content, others require metadata fields.

**Decision:** Policy rules define a `check.type` field that dispatches to typed handler methods in the PolicyEngine. Six check types implemented: `action_blocklist`, `resource_pattern`, `content_scan`, `permission_required`, `result_required`, `metadata_required`. New check types can be added by registering a handler in the `_check_handlers` dispatch table.

**Consequences:**
- Positive: YAML rules are readable by compliance officers, not just engineers
- Positive: New check types can be added without modifying existing rules
- Positive: Unknown check types pass safely (no silent failures, no crashes)
- Negative: Less expressive than a full rule engine (no cross-event correlation)
- Future: Consider OPA/Rego integration for organizations needing complex multi-condition rules

---

## ADR-016 — Graph reachability for workflow safety verification
**Status:** Accepted
**Date:** 2026-04-14

**Context:** The formal verifier needs to prove workflow safety properties: "can a target node be reached from a source without passing through a HITL node?" Z3's Fixedpoint engine (µZ Datalog) was initially considered but proved brittle with uninterpreted sorts across Z3 versions.

**Options considered:**
1. Z3 Fixedpoint engine (µZ Datalog) — theoretically elegant but API instability across Z3 versions
2. Z3 Solver with bounded unrolling — works but complex encoding for simple reachability
3. BFS reachability on pruned graph ← chosen

**Decision:** Remove HITL nodes from the graph, then run BFS from source to target. If target is reachable, the safety property is violated (SAT). Z3 is still used for RBAC bitvector encoding and policy consistency checks where it adds real value. The workflow safety check uses simple graph algorithms where they are more robust.

**Consequences:**
- Positive: Robust across all Z3 versions; no API compatibility issues
- Positive: Constant-time for typical agent workflow graphs (small node counts)
- Negative: Cannot express temporal properties or quantified path constraints
- Future: Re-evaluate µZ when agent workflow graphs become larger or need richer properties

---

## ADR-017 — Protocol-based framework adapters with governance pipeline
**Status:** Accepted
**Date:** 2026-04-16

**Context:** AgentGuard needs to integrate with LangGraph, CrewAI, Google ADK, and A2A without depending on any of these frameworks at runtime. Each framework has a different tool execution interface.

**Options considered:**
1. Abstract base class with framework-specific subclasses — requires import of framework
2. Protocol-based adapters with lazy imports ← chosen
3. Monkey-patching framework internals — fragile and version-dependent

**Decision:** Define minimal Protocol interfaces (`LangChainTool`, `CrewAIToolProtocol`, `AdkToolProtocol`, `A2ATransport`) that capture the essential method signature of each framework's tool/transport. Governed wrappers accept `Any` and duck-type against these protocols. No framework imports at module level — frameworks are only needed when the user instantiates a governed wrapper with a real tool.

**Consequences:**
- Positive: Zero import-time dependency on any framework
- Positive: Each adapter follows identical governance pipeline (identity→RBAC→breaker→audit→execute)
- Positive: Users can test with simple mock objects matching the protocol
- Negative: Protocol drift if frameworks change their tool interfaces — mitigated by protocol being minimal (1-2 methods)
- Negative: No static type checking against actual framework types — acceptable trade-off for decoupling

---

## ADR-018 — NoOp fallback for OpenTelemetry tracer
**Status:** Accepted
**Date:** 2026-04-16

**Context:** The observability layer uses OpenTelemetry for tracing, but `opentelemetry-sdk` is an optional dependency. The tracer must work gracefully when OTel is not installed.

**Decision:** `AgentTracer` lazily imports `opentelemetry` at init time. If the import fails, all span operations produce `_NoOpSpan` objects with zero overhead. The `is_active` property lets callers check availability. Convenience methods (`trace_rbac_check`, `trace_policy_evaluation`, `trace_tool_call`) encapsulate common governance span patterns.

**Consequences:**
- Positive: Core runtime works without OTel installed — no unnecessary dependency
- Positive: Drop-in activation: `pip install agentguard[observability]` enables real tracing
- Positive: All span attributes use `agentguard.*` namespace per OTel semantic conventions
- Negative: NoOp path means missing traces when OTel is not configured — document clearly

---

## ADR-019 — Audit-based observability (replay + dashboard from audit events)
**Status:** Accepted
**Date:** 2026-04-16

**Context:** The replay debugger and metrics dashboard need a data source. Options were: (1) separate event store, (2) OTel trace backend queries, (3) existing audit log.

**Decision:** Both `ReplayDebugger` and `MetricsDashboard` operate on `list[AuditEvent]` loaded from the existing `FileAuditBackend`. No additional data store is required. The audit log is the single source of truth for governance decisions — replay and metrics are views over it.

**Consequences:**
- Positive: No additional infrastructure; works offline from JSONL files
- Positive: Consistent with "audit log is the single source of truth" design principle
- Positive: Replay can filter by agent, action, result, time range — all fields already in AuditEvent
- Negative: Large audit logs may require pagination (not yet implemented — acceptable for v1.0)
- Future: Add streaming/pagination for audit logs exceeding 100K events

---

## ADR-020 — Shared governance pipeline for integration adapters
**Status:** Accepted
**Date:** 2026-04-17

**Context:** The first M5 implementation duplicated a ~60-line governance pipeline (identity → RBAC → audit → breaker → execute) across five adapters (MCP, LangGraph, CrewAI, Google ADK, A2A). During post-implementation review, two serious bugs surfaced in all five adapters:
1. **Missing error event logging:** when executor raised, no follow-up `result="error"` audit event was written, violating ADR-004.
2. **Missing duration tracking:** on failure, no timing information was captured, so the dashboard couldn't compute error-path latencies.

Fixing these in five places invited drift; future adapters (Autogen, Swarm, Atomic Agents) would inherit the same divergence risk.

**Decision:** Extract the governance pipeline into `agentguard/integrations/_pipeline.run_governed`. All adapters construct a zero-arg async `executor` callable and delegate the full pipeline (identity resolution, RBAC, pre-event, circuit breaker, execute, error event on exception, OTel span wrapping) to the shared helper. The module is underscore-prefixed (private) — not part of the public API contract.

**Consequences:**
- Positive: Error-event logging (ADR-004) is enforced in one place, tested once
- Positive: Adapters shrink from ~90 LOC to ~30 LOC each
- Positive: OTel tracer wiring lives in one place; adapters opt in via a `tracer=` constructor parameter
- Positive: New framework adapters become near-trivial
- Negative: Private module means users can't subclass the pipeline — acceptable, since governance flow should not be customizable per-adapter
- Negative: Slight indirection when reading a single adapter — mitigated by docstring in `_pipeline.py`

---

## ADR-021 — Library-mode OTel tracer: never mutate the global TracerProvider
**Status:** Accepted
**Date:** 2026-04-18

**Context:** The first M6 `AgentTracer` implementation installed a fresh
`TracerProvider` via `trace.set_tracer_provider()` when the current
provider was not a `TracerProvider` instance (the OTel default is a
`ProxyTracerProvider`). This is an aggressive move for a library: if the
host application configures its own provider later, spans end up
fragmented across two providers with different exporters.

**Decision:** `AgentTracer` only calls `trace.get_tracer(service_name)`
and never mutates the global provider. When the host application has not
configured OTel yet, the default `ProxyTracerProvider` produces no-op
spans, matching the behavior users already expect from library-level
OTel instrumentation. When the host configures OTel afterwards, the
tracer starts emitting real spans automatically.

**Consequences:**
- Positive: AgentGuard plays nicely with any host OTel setup (Datadog,
  Jaeger, Honeycomb, Grafana) without risk of double-provider state
- Positive: Aligns with OpenTelemetry's stated "library author" guidance
- Negative: Out-of-the-box spans are no-ops until the user configures a
  provider — documented in the tracer module docstring
- Note: This was flagged by the ADR-017/018/020 post-implementation
  review (ADR-018 promised NoOp fallback behavior but the first cut
  took a more intrusive path)

*When you (Claude Code) make a new architectural decision, append it here following the same format. Increment the ADR number sequentially.*
