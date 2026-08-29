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

**Current-guidance note (2026-08-27):** SR 26-2 superseded SR 11-7 on April 17, 2026,
and OCC Bulletin 2026-13 rescinded OCC Bulletin 2011-12. References below describe the historical
context for this decision, not the current supervisory status or a prescriptive requirement.

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
**Status:** Accepted — partially superseded by ADR-022 (unknown check types now fail at load; custom handlers register via `extra_check_handlers`)
**Date:** 2026-04-14

**Context:** The compliance engine needs to evaluate audit events against policy rules loaded from YAML files. Rules need different evaluation strategies: some check action patterns, others scan for content, others require metadata fields.

**Decision:** Policy rules define a `check.type` field that dispatches to typed handler methods in the PolicyEngine. Six check types implemented: `action_blocklist`, `resource_pattern`, `content_scan`, `permission_required`, `result_required`, `metadata_required`. New check types can be added by registering a handler in the `_check_handlers` dispatch table.

**Consequences:**
- Positive: YAML rules are readable by compliance officers, not just engineers
- Positive: New check types can be added without modifying existing rules
- ~~Positive: Unknown check types pass safely (no silent failures, no crashes)~~ — reversed by ADR-022: this was fail-open
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

**Decision:** `AgentTracer` lazily imports OpenTelemetry at initialization. If the SDK is absent or
the host has not installed a recording provider, span operations produce `_NoOpSpan` objects and
metrics are ignored. `is_active` reports configured trace recording, not package availability. The
shared governance pipeline owns the root/child span structure; unused convenience emitters were
removed.

**Consequences:**
- Positive: Core runtime works without OTel installed — no unnecessary dependency
- Positive: Installing the observability extra and configuring SDK providers enables real tracing
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
**Status:** Superseded in part by ADR-027; the single-path requirement remains accepted
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

The 2026-04-17 decision established the one-path invariant. ADR-027 moves ownership of that path
from the private integration helper to a public, framework-independent kernel; `_pipeline` now
preserves compatibility only.

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

**Decision:** `AgentTracer` never mutates a global provider. At construction it checks whether the
host installed SDK `TracerProvider` and `MeterProvider` instances and obtains instruments only from
those providers. The default `ProxyTracerProvider` and missing SDK remain explicit no-op mode, so
`is_active` means a recording SDK trace provider was configured rather than merely importable.
Hosts configure providers first and then construct the tracer.

**Consequences:**
- Positive: AgentGuard plays nicely with any host OTel setup (Datadog,
  Jaeger, Honeycomb, Grafana) without risk of double-provider state
- Positive: Aligns with OpenTelemetry's stated "library author" guidance
- Negative: Out-of-the-box spans are no-ops until the user configures providers; a tracer created
  before host configuration remains a no-op and should be reconstructed afterwards.
- Note: This was flagged by the ADR-017/018/020 post-implementation
  review (ADR-018 promised NoOp fallback behavior but the first cut
  took a more intrusive path)

---

## ADR-022 — Unknown policy check types fail at load time
**Status:** Accepted
**Date:** 2026-08-22

**Supersedes:** the "New check types can be added by registering a handler in the `_check_handlers` dispatch table" mechanism and the "Unknown check types pass safely" consequence in ADR-015 (ADR-015 otherwise stands: YAML policy-as-code with typed check handlers).

**Context:** `PolicyEngine._evaluate_rule` resolved `check.type` against a dispatch table and, on a miss, returned `PolicyResult(passed=True, evidence={"note": "Unknown check type: ..."})`. A single typo in a YAML file — `action_blocklsit` instead of `action_blocklist` — therefore turned a critical control into a rule that always passes, at runtime, with no error and only a note buried in the evidence dict. This directly contradicts design principle 5 (fail-safe over fail-open) and is exactly the failure mode a compliance engine exists to prevent: the policy set looks complete in `agentguard policy validate` while the control is inert. Additionally, the dispatch table was a class-level dict of *unbound* methods invoked as `handler(self, rule, event)`, so third-party handlers had to accept an engine instance as their first argument — an awkward, undocumented contract.

**Decision:**
1. Unknown check types are rejected at **load time**. `PolicyEngine._load_file` validates every rule's `check.type` against the handler table immediately after the `PolicyRule` is constructed, and raises `PolicyLoadError(file, rule_id, detail)` (new, in `agentguard/exceptions.py`) listing the known types. Construction of the engine fails; the process does not start with a silently degraded policy set.
2. Custom check types are registered through the constructor: `PolicyEngine(policy_dirs=..., extra_check_handlers={"my_check": handler})`, where `CheckHandler = Callable[[PolicyRule, AuditEvent], PolicyResult]`. The merged table is built in `__init__` *before* any policy file is read, so custom types load exactly like built-in ones. Built-in handlers are bound methods, so they share the `(rule, event)` signature — no engine argument leaks into the public contract.
3. The runtime "unknown check type" branch in `_evaluate_rule` remains only as a defensive `# pragma: no cover` guard that raises rather than passes, for the case where a rule is injected after construction.
4. The CLI (`policy validate`, `policy report`, `verify policy`) catches `PolicyLoadError`, prints the file, rule ID, and offending type, and exits 1.

**Consequences:**
- Positive: A misspelled or unimplemented check type is caught at startup and in CI, not discovered during an audit
- Positive: Custom handlers have a documented, engine-free signature and cannot be shadowed by a load-order accident
- Positive: `agentguard policy validate` becomes a real gate — it now fails on a policy set the engine could not fully evaluate
- Negative: Policy files that previously loaded with a bad check type now break the engine — this is intended, but it is a breaking change for any downstream policy set carrying such a rule
- Negative (stated limitation): CLI users cannot register custom check types. `extra_check_handlers` is a Python API only, so a YAML policy set using a custom type is loadable from library code but not from `agentguard policy validate`. Custom types remain a programmatic-integration feature; adding a plugin entry-point mechanism for the CLI is deferred until there is demand.

---

## ADR-023 — RBAC resource is derived by the integrator, never supplied by the agent
**Status:** Accepted
**Date:** 2026-08-22

**Context:** Every framework adapter accepted the RBAC `resource` as a free-form string at call time, defaulting to `"*"`. The resource is the *subject* of the permission decision, so the governed party was naming its own subject: with `allow tool:* on *` plus `deny tool:* on admin/*`, calling `admin_delete` with `resource="public/report"` — or with no resource at all — executed. The deny rule only fired when the caller volunteered an incriminating label. A second, related defect: `Permission.matches` used `fnmatch.fnmatch`, which applies `os.path.normcase`, so the same policy meant different things on Linux and Windows, and a case variant (`Admin/keys`) evaded `deny admin/*` on Linux.

**Decision:**
1. Adapters take resource **resolvers** at construction time and expose no resource argument at call time. `ResourceResolver = str | Callable[[Any], str | Awaitable[str]]` — a static string or a sync/async callable receiving the adapter-specific call input (LangGraph: `tool_input`; MCP: `arguments`; ADK: `args`; CrewAI: `{"args", "kwargs"}`). LangGraph and MCP take `resources: Mapping[tool_name, ResourceResolver]`, which doubles as an allowlist; CrewAI and ADK take a required `resource=`. A2A keeps deriving `agent/<target>`.
2. `run_governed` accepts `resource: str | None`. `None` — no resolver, resolver raised, resolver returned a non-string, or canonicalisation rejected the value — is a fail-closed denial: a `denied` audit event is written against the sentinel `<unresolved>` and `PermissionDeniedError` is raised **before** RBAC is consulted.
3. Every derived resource passes through `canonicalize_resource` before RBAC: reject empty, fnmatch metacharacters (`*?[]`), the sentinel characters `<>`, control characters, absolute paths and upward traversal; `posixpath.normpath`; `casefold()`.
4. `Permission.matches` uses `fnmatch.fnmatchcase`. Resources are matched with both pattern and subject case-folded; actions are matched case-sensitively (actions are chosen by the integrator, and folding them would silently widen policy).
5. Direct callers of `run_governed` (e.g. the credit-decisioning example) are inside the trust boundary by definition and own the derivation themselves; the docstring says so.

**Consequences:**
- Positive: the governed agent cannot choose its own RBAC subject; lying is a `TypeError` at the signature level, omission is an audited denial
- Positive: an unknown tool name is now an audited denial instead of a `KeyError` — exactly the event an audit trail should record
- Positive: policy semantics no longer depend on the host platform
- Negative: breaking API change for all adapters (`resources=`/`resource=` are required keyword arguments; `ainvoke`/`call_tool`/`run_async` lost their `resource` parameter; CrewAI `_resource=` raises `TypeError`)
- Negative: the honour system moves to whoever writes the resolver; the resolver author also writes the RBAC policy, which is the right trust level. Phase 1.2 makes the resolver consume the transformed typed payload, and Phase 1.4 adds argument-aware policy enforcement.
- Resolved by ADR-024 / PR 1.3: denial and escalation events gain machine-stable reason codes; the v0.x free-text `PermissionContext.reason` remains for compatibility.

---

## ADR-024 — Stable Phase 1 guardrail, payload, policy, and evidence contracts
**Status:** Accepted
**Date:** 2026-08-26

**Supersedes in part:** ADR-004's single pre-execution event shape, ADR-007's unversioned HMAC payload, ADR-019's event-by-event dashboard interpretation, ADR-020's pipeline ordering, and ADR-023's deferral of stable reason codes. Those ADRs otherwise stand.

**Context:** Phase 1 must put payload inspection and policy enforcement on the governed path without leaking secrets into evidence, authorizing one payload and executing another, invalidating historical audit hashes, or turning broad compliance prose into unsafe blocking rules. The initial plan deferred the audit envelope and lifecycle until Phase 2, even though post-execution denial, dashboard latency, escalation, and stable policy reason codes all depend on them. It also used shallow-frozen models, a generic payload union without a hard message/tool boundary, free-text reasons, and an event ordering that left a race between a circuit-breaker check, the pre-execution audit write, and execution.

**Decision:**

1. **Stable vocabulary.** Phase 1 uses guardrail decisions `allow`, `deny`, `transform`, `escalate`, and `warn`. `deny` and `escalate` require at least one machine-stable reason code; `transform` requires a replacement payload of the same discriminator; `warn` records and continues. Policy effects are `allow`, `deny`, `escalate`, and `warn`; policies do not transform payloads. A later guardrail cannot override an earlier deny. Runtime reason codes are registry-backed names such as `RESOURCE.UNRESOLVED`, `RBAC.PERMISSION_DENIED`, `GUARDRAIL.TIMEOUT`, `GUARDRAIL.INTERNAL_ERROR`, `RATE_LIMIT.EXCEEDED`, and `CIRCUIT_BREAKER.OPEN`. Shipped policy rule IDs are themselves stable policy reason codes.
2. **Deeply immutable, distinct payloads.** Runtime payload models are discriminated and recursively immutable, not merely `ConfigDict(frozen=True)` around mutable dict/list children. Tool calls, tool results, and inter-agent messages have different models (`ToolCallPayload`, `ToolResultPayload`, and `MessagePayload`) and cannot validate as one another. A transform returns a new same-kind model; it never mutates the caller's object.
3. **Transform before authorization.** The governed path constructs the typed input, applies fail-closed `input_transform` guardrails, and only then derives action/resource and runs RBAC/policy. The resolver and executor receive the same transformed payload. Sync resolvers run off the event loop in a dedicated executor with bounded workers and queue; sync and async resolution have explicit timeouts. Saturation, timeout, cancellation, exception, invalid type, or invalid canonical resource denies with `RESOURCE.UNRESOLVED` and evidence.
4. **Runtime/evidence separation.** The executor receives a runtime payload, which may contain sensitive values and is never serialized into an audit event. The evidence sink receives a distinct typed redacted payload plus a digest of the canonical runtime payload. Evidence models cannot be passed to an executor. If canonicalization, redaction, or evidence construction fails, execution is blocked before admission or delivery is denied after execution; raw payload fallback is forbidden.
5. **Lifecycle envelope in Phase 1.** Events correlate by `invocation_id`. An admitted call emits `admission` before the executor, `execution_completed` after every executor attempt, and exactly one delivery terminal: `delivery_completed`, `delivery_denied`, or `delivery_escalated`. A breaker/rate/policy rejection before admission emits `delivery_denied` without an admission. Dashboard/replay group by invocation. If malformed history has multiple delivery terminals, the conservative precedence is denied, then escalated, then completed. `execution_completed` without a delivery terminal means executed but not delivered; `admission` alone means admitted but execution is unknown. Neither counts as allowed.
6. **Atomic breaker/audit boundary.** Circuit-breaker admission reserves the sole HALF_OPEN probe under its lock, then invokes an async `before_execute` callback that writes `admission`, then calls the executor. If the callback fails, the executor is not called and the reservation is released back to OPEN backoff. Concurrent threshold failures emit one OPEN transition. Rate limits are keyed by `(agent_id, action)` and checked before breaker admission.
7. **Versioned HMAC compatibility.** Historical records without a hash schema marker are interpreted as v1 and verified using the exact legacy field set and serialization bytes. New records are written as v2, whose signed bytes include the Phase 1 lifecycle, reason-code, digest, and redacted-evidence fields. Existing records are never rewritten. A v2 record may follow a valid v1 record by referencing its hash. Phase 2 adds sequence numbers, key IDs, concurrent-writer locking, and signed head checkpoints on this envelope; it does not redesign the Phase 1 lifecycle.
8. **Policy-safe defaults and exact migration.** Policy schema v2 requires a known `stage`, `applies_to`, `effect`, and check type; missing/unknown fields, handler exceptions, and timeouts fail bundle load or deny evaluation. `attestation` rules cannot authorize a runtime call. Legacy v1 bundles remain detect-only `warn` so an upgrade does not unexpectedly block production. The shipped migration is fixed by `docs/plans/guardrails-realignment.md`: 35 rules total, staged 14 pre-tool / 1 post-tool / 20 attestation, with 3 deny / 3 escalate / 29 warn. Moving a shipped rule from warn to enforce is a reviewed policy-bundle change, not a severity-derived default.
9. **Generic guardrails and finance compatibility.** Framework-independent PII detection, redaction, and evidence transformation live under `agentguard/guardrails/` and do not import a domain package. `agentguard/domains/finance/pii.py` owns finance/FCRA/GLBA presets and remains as a compatibility import boundary for the v0.x line, delegating generic mechanics rather than duplicating them. Domain-specific protected data categories may tighten a generic guardrail but may not weaken its fail-closed behavior.

**Compatibility and breaking-change choices:**

- Historical v1 audit files remain readable and verifiable; no migration rewrites signed data. New v2 fields change signed bytes by design and therefore carry an explicit version.
- Legacy policy bundles preserve detect-only behavior. Enforcement begins only after explicit v2 migration, so severity never silently becomes a deny effect.
- Existing finance PII imports remain valid while the generic implementation moves. A removal or import-path break requires the next major version.
- Resolvers now observe the transformed payload, and bounded resolver capacity can reject overload. Both are intentional security behavior changes: the authorized subject must match executed data, and unbounded thread growth is not an acceptable fallback.
- Lifecycle-aware dashboard counts replace event counts. Legacy events remain visible as `legacy`, but they cannot be reinterpreted as proof of delivery.

**Consequences:**

- Positive: Phase 1 can enforce input and output controls without placing raw secrets in the audit chain.
- Positive: Authorization, evidence, execution, and delivery describe one immutable payload lineage.
- Positive: Historical HMAC evidence remains verifiable while new security-relevant fields are signed.
- Positive: Policy migration is reviewable rule-by-rule and cannot derive enforcement from severity or malformed defaults.
- Positive: The reusable guardrail package remains domain-neutral without breaking finance callers.
- Negative: Payload construction and serialization require recursive immutable JSON handling and explicit runtime/evidence conversion.
- Negative: Invocation lifecycle emits more events and requires consumers to aggregate by `invocation_id`.
- Negative: Timed-out sync resolver threads cannot be force-killed by Python; the dedicated bounded pool limits residual work, and saturation denies new calls until capacity returns.

---

## ADR-025 — Schema v3, atomic file append, and attestable evidence snapshots
**Status:** Accepted
**Date:** 2026-08-26

**Context:** Phase 2 adds sequence, key, subject, and checkpoint integrity. Adding those fields to
the live schema-v2 serializer would invalidate already-produced Phase 1 v2 hashes. Locking only
the final file write would also leave a race because predecessor selection and signing previously
happened before the backend saw the event. Finally, the compliance reporter accepted detached
event lists and could not prove that evidence was complete or untampered.

**Decision:**

1. Historical v1 and v2 signed shapes are represented by exact frozen serializers. New writes use
   schema v3 with domain-separated canonical JSON. Any future signed-envelope change requires a
   new schema version.
2. Sequence is the one-based physical chain position. A contiguous unsequenced v1/v2 prefix
   occupies its physical positions; the first v3 event receives `N+1`. Sequence, `key_id`,
   `chain_id`, lifecycle, redacted evidence, opaque subject references, links, chain mode, and the
   policy-bundle digest are signed. The sink rejects caller-supplied integrity fields.
3. `FileAuditBackend` uses one directory-wide `flock` transaction to read the authoritative
   checkpoint and durable tail, allocate and sign the next event, append with `O_APPEND`, `fsync`,
   and atomically replace a separately domain-signed head checkpoint. The first v3 migration
   append counts legacy history once; steady-state appends do not reparse it. Cached chain state
   is never authoritative.
4. A clean compliance attestation requires one lock-consistent `VerifiedAuditSnapshot`, a valid
   v3 local checkpoint, and a signed head checkpoint retained outside the log/checkpoint failure
   domain (or retained by the current writer process). A local checkpoint without that anchor is
   `verified_unanchored`: hash-valid but non-attestable. Legacy-only and two-method custom backends
   are likewise readable but non-attestable. Empty or broken evidence is refused, not reported as
   100% compliant.
5. Runtime policy results retain their emitted bundle digest. The reporter resolves that digest
   against an activated bundle generation retained by the engine and refuses unknown generations
   or rule IDs. Lifecycle-repeated runtime results are counted once per invocation and rule.
   Evidence references are opaque correlation identifiers and never authorization inputs.

**Consequences:**

- Positive: concurrent local writers cannot create sibling heads, tail truncation is detectable,
  and reports cannot silently attest detached or checkpoint-invalid evidence.
- Positive: v1 and v2 evidence remains byte-compatible while v3 has a stable future-proof signing
  contract.
- Negative: file append performs a locked tail/checkpoint read, and a crash between log `fsync`
  and checkpoint promotion leaves evidence safely non-attestable until recovered.
- Limitation: durable rollback detection depends on retaining the exported trusted checkpoint in
  a separate failure domain. Phase 2.2 must make that automatic through a collector that owns
  persistence, sequence, checkpoint state, and signing; a stateless remote signer is insufficient.

---

## ADR-026 — Stateful UDS audit collector with immutable key epochs

**Status:** Accepted (2026-08-26)

**Context:** A local HMAC chain still gives the audited agent process the signing key, and a local
log plus checkpoint can be rolled back as one unit. A stateless remote signer would hide the key
but would still sign forks or truncated branches chosen by its caller. The process boundary also
needs bounded transport, deterministic retries, key rotation, and crash recovery.

**Decision:** Keep `AppendOnlyAuditLog` as the local-trust implementation and introduce an
application-facing `AuditLog` protocol. `SigningAuditBackend` implements that protocol as a keyless
client of `AuditCollectorServer` over a length-prefixed Unix socket. The collector owns sequence
allocation, chain/checkpoint signing, file persistence, immutable sequence-bound key epochs, and a
signed external `CollectorState` containing key fingerprints and the accepted head.

The collector takes a lifetime non-blocking lock in the canonical log directory. Socket paths are
owner-only and reject symlinks, non-sockets, foreign ownership, and foreign peer UIDs. Requests,
connections, time, snapshots, pages, event counts, and bytes are bounded. `event_id` is the
idempotency key: an identical retry returns the committed event; a conflicting reuse is rejected.
Verified reads use immutable server snapshots rather than a moving log.

File commits prepare and `fsync` the prospective checkpoint before appending. Recovery discards a
valid prepare if its event is absent, promotes it if the exact event is durable, and refuses every
other state. The external anchor advances only after the local checkpoint. On restart, a verified
local head one or more events ahead of an older signed external state may roll that state forward;
an external head ahead of local history, a gap, conflict, corrupt state, or missing state for a
non-empty log fails closed unless explicit adoption was requested.

Rotation commits a new key ID, activation sequence, and SHA-256 key fingerprint to signed external
state before installing the immutable keyring. Historical verification resolves the exact expected
epoch; IDs cannot be rebound or removed, old keys cannot sign new epochs, duplicate pending
activations are rejected, and failed state persistence leaves the in-memory keyring unchanged.

**Consequences:**

- Positive: the agent process can audit and read attestable evidence without holding signing keys.
- Positive: one collector provides global ordering, timeout-safe idempotency, online rotation, and
  deterministic recovery across the event/checkpoint crash window.
- Negative: deployments must supervise the collector and retain all historical verification keys.
- Limitation: UDS peer credentials are OS identity, not application identity. A same-UID attacker
  that controls the collector socket and both storage domains remains outside this threat boundary.
- Limitation: symmetric HMAC proves possession and integrity, not semantic truth or public
  third-party verifiability; an asymmetric/KMS signer can implement a later boundary.

---

## ADR-027 — Public GovernanceKernel owns the governed runtime

**Status:** Accepted
**Date:** 2026-08-26

**Context:** ADR-020 removed duplicated enforcement from five adapters, but left the trusted
runtime inside the private integration module. As payload transforms, staged policy evaluation,
content guardrails, rate limiting, lifecycle audit evidence, and OTel instrumentation joined the
call path, `_pipeline.run_governed` became a framework-layer owner of framework-independent
security behavior. A façade that continued to execute orchestration in `_pipeline` would preserve
the wrong dependency direction. The earlier guardrail evaluator also duplicated chain semantics
and could obscure task cancellation.

**Decision:** `agentguard.guardrails.kernel.GovernanceKernel` is the public runtime boundary. A
kernel instance owns the identity registry, RBAC engine, audit log, optional policy engine,
`GuardrailChain`, rate limiter, circuit breaker, tracer, and resolver/guardrail timeouts. Its
`guarded_tool_call` method owns the root OTel context and the complete fail-closed lifecycle.

The kernel consumes immutable typed payloads and produces typed `PermissionContext`,
`PolicyResult`, guardrail decisions, and signed audit artifacts. It runs the shared
`GuardrailChain` for input, pre-tool/message, and post-tool/message stages; cancellation propagates
instead of becoming a guardrail failure. Transforms must preserve the exact payload discriminator.

The circuit breaker remains a kernel-owned execution boundary, not a precheck guardrail. The
kernel passes the admission audit write as `CircuitBreaker.call(..., before_execute=...)`, so a
CLOSED admission or the single HALF_OPEN probe is committed immediately before the executor
starts. Once admitted, the exact lifecycle is `admission` → `execution_completed` → exactly one
delivery terminal (`delivery_completed`, `delivery_denied`, or `delivery_escalated`). Pre-admission
denials, escalations, and rejections do not fabricate an admission event.

All five adapters accept either a preconfigured `kernel=` or the legacy registry/RBAC/audit and
optional governance arguments. Mixed ownership is rejected. The deprecated
`agentguard.integrations._pipeline.run_governed` function has the old signature, constructs a
kernel, and delegates; it no longer owns orchestration.

**Consequences:**

- Positive: Direct callers and every adapter share one framework-independent enforcement path.
- Positive: Guardrail ordering, timeout behavior, cancellation, OTel context, audit evidence, and
  breaker admission are owned and tested at one boundary.
- Positive: Existing adapter construction and direct `run_governed` calls retain a migration path.
- Negative: Supplying a kernel and legacy governance dependencies together now raises an error;
  callers must choose one owner explicitly.
- Negative: The compatibility module remains until a future major-version removal.
- Limitation: Durable/authenticated HITL approval, agent authentication, and sandbox execution are
  still outside the kernel and remain roadmap work.

---

## ADR-028 — Shadow mode uses signed schema-v4 guardrail evidence

**Status:** Accepted
**Date:** 2026-08-26

**Context:** Production adoption needs a non-enforcing observation period, but treating shadow
decisions as logs or unsigned metadata would make the rollout evidence mutable and
non-attestable. Reusing schema v3 would also change its frozen canonical bytes. Shadow transforms
must not create an authorization/execution mismatch, and shadow content checks must not be
mistaken for disabling RBAC, policy, rate limiting, circuit breaking, or audit.

**Decision:** `ChainMode` controls only `GuardrailChain`. In `shadow`, every configured guardrail
runs through every applicable stage, but deny, escalate, timeout, internal-error, and transform
decisions do not block execution or replace the resolver, executor, result, or caller payload. In
`off`, content guardrails do not run. All other kernel governance remains enforced in every mode.

`GuardrailEvaluation` is an immutable typed record containing guardrail ID and version, stage,
effect, stable reason codes, bounded duration, and whether the decision was enforced. New audit
writes use schema v4, whose domain-separated canonical HMAC envelope includes these evaluations.
The exact v1, v2, and v3 serializers remain frozen; those versions reject populated evaluation
fields as unsigned extensions. Mixed v3-to-v4 chains remain verifiable without rewriting history.

Input-transform and pre-execution evaluations are persisted exactly once on the admission event
or, for a pre-admission terminal, on that terminal. Post-execution evaluations are persisted
exactly once on the delivery terminal. `execution_completed` never carries guardrail evaluations.
Would-be shadow reasons remain evaluation evidence and do not become actual event reason codes.
Cancellation after a successful executor attempt commits `delivery_denied` with
`DELIVERY.CANCELLED` before cancellation propagates; cancellation-safe terminal writes preserve
the exactly-one-terminal invariant.

Replay exposes the exact observed guardrail/version/stage/effect/reasons. Dashboard and compliance
reporting deduplicate by `(invocation_id or event_id, stage, guardrail_id, guardrail_version)`,
surface conflicting duplicates, and keep shadow findings separate from enforced outcome and policy
metrics. A conflict retains every distinct observed effect and reason instead of trusting the first
lifecycle copy; global would-effect totals count unique invocations.

Persisted schema-v4 parsing forbids unknown top-level and nested signed-model fields. Invalid JSON,
unknown fields, and validation failures are treated as tamper evidence rather than being silently
discarded before HMAC verification.

**Consequences:**

- Positive: teams can measure would-be denials, escalations, and transforms before enforcement
  without changing native tool behavior.
- Positive: observation evidence is integrity-protected, versioned, and attributable to an exact
  guardrail implementation and lifecycle stage.
- Positive: shadow rollout data cannot inflate denial rates or policy-failure attestations.
- Negative: schema v4 increases event size and requires consumers to understand another frozen
  historical serializer.
- Limitation: HMAC evidence proves integrity and key possession, not that a guardrail's semantic
  judgment was correct or that the observed invocation was authentic.

---

## ADR-029 — Policy reload is explicit, copy-on-write, and pinned per invocation

**Status:** Accepted
**Date:** 2026-08-26

**Context:** Loading policies only during `PolicyEngine` construction requires a process restart
for every control change. Mutating the live rule list in place would let concurrent invocations
observe partial generations or use one generation before execution and another afterward. Signed
evidence and later attestation also require an exact, resolvable policy identity.

**Decision:** A `PolicyBundle` is one recursively immutable generation containing its policy sets,
enabled rules, rule IDs, and a path-independent canonical SHA-256 digest. Policy sets are ordered
by canonical semantic content rather than source path, and policy check values are restricted to
recursively immutable JSON-compatible values. Rule IDs must be unique across the complete bundle,
including disabled rules. `PolicyEngine.snapshot()` synchronously returns the active object.
`await PolicyEngine.reload()` serializes reload requests, builds and validates a complete candidate
off the event loop, then performs a short lock-protected pointer swap. Reload is explicit; no file
watcher or polling task is created. A failed candidate never changes the active generation.

`GovernanceKernel` snapshots the bundle before its first asynchronous boundary and supplies that
same object to every staged evaluation. All lifecycle evidence for the invocation carries the
pinned digest. The engine retains every generation activated during its lifetime, and
`ComplianceReporter` resolves each event against its stamped generation for both runtime-rule
provenance and attestation-stage evaluation. Unknown generations or unknown rule IDs make the
evidence non-attestable.

**Consequences:**

- Positive: a valid edit changes later enforcement without restart while active calls remain
  internally consistent and attributable to one signed digest.
- Positive: invalid YAML, unknown checks, and duplicate IDs preserve last-known-good enforcement.
- Positive: report generation can attest mixed known generations from one engine lifetime.
- Negative: callers must explicitly decide when to reload; file writes alone have no runtime
  effect.
- Limitation: generation history is in memory. Attesting historical evidence after a process
  restart requires reconstructing or otherwise archiving the referenced policy bundles.

---

## ADR-030 — Durable HITL begins with metadata-only requests, not execution replay

**Status:** Accepted
**Date:** 2026-08-26

**Context:** A restart-safe HITL workflow is an execution-continuation protocol, not merely a
file-persistence feature. The current kernel receives an ephemeral executor callable, guardrail
chains expose no authenticated cursor, policy history is process-local, and post-tool results exist
only in memory. Persisting payloads or accepting a replacement executor with only an opaque token
would enable disclosure, executor substitution, replay, or duplicate side effects.

**Decision:** Phase 3.4 is split into independently safe boundaries. Phase 3.4a persists only
control-plane request state: escalation ID, pending/expired status, revision, and timestamps. The
POSIX file store uses an explicit 256-bit-or-stronger HMAC key, owner-only permissions,
symlink-safe reads, one directory `flock`, atomic file replacement, file/directory `fsync`, and exact TTL
expiration. A 256-bit opaque token is returned once; only its SHA-256 verifier is stored. Tool
arguments, results, and continuation cursors are forbidden from this store.

When configured on `GovernanceKernel`, pending state is committed before a schema-v5
`escalation_requested` event. The raw token escapes only after the audit write succeeds. Durable
post-tool requests are nonterminal HITL events, not `delivery_escalated`, because a future approved
delivery must not create two delivery terminals. Without a store the legacy non-resumable event
and exception behavior remains unchanged. Schema v5 signs typed, redacted HITL evidence while the
exact v1-v4 serializers remain frozen. Dashboard HITL counters deduplicate lifecycle evidence by
escalation identity independently of final invocation outcomes.

No decision, claim, approval, or resume method is exposed by the store or kernel in Phase 3.4a.
Phase 3.4b must require an authenticated approver, signed/idempotent decision evidence, a trusted
executor registry, AEAD-protected continuation state, exact
policy and guardrail-chain fingerprints, a resumable cursor, RBAC recheck, and idempotent audit
commit semantics. Phase 3.4c separately handles protected post-execution results; Phase 3.4d
handles ambiguous crashes. Admitted execution with unknown completion is never retried
automatically.

**Consequences:**

- Positive: pending state, expiry, token verification, and signed request evidence survive process
  restart without serializing governed runtime data.
- Positive: a caller cannot receive an approval token unless both durable state and log-first audit
  evidence exist.
- Positive: future resumption cannot accidentally reuse the old terminal `delivery_escalated`
  semantics.
- Negative: Phase 3.4a can record and inspect escalation state but cannot approve or resume a
  governed call through the kernel.
- Limitation: the built-in store targets trusted local POSIX filesystems and has no signing-key
  rotation. Network filesystems and multi-host coordination require another store implementation.

---

## ADR-031 — Restart-safe HITL resumes only protected registered PRE-stage calls

**Status:** Accepted
**Date:** 2026-08-26

**Context:** A token alone cannot authenticate an approver, payload, executor, policy generation,
or guardrail position. The legacy kernel accepts ephemeral resolver and executor callables, policy
history is process-local, and exactly-once external side effects cannot be reconstructed after a
crash once execution begins.

**Decision:** Restart-safe Phase 3.4b resumption is limited to PRE_TOOL/PRE_MESSAGE guardrail
escalations initiated with `guarded_registered_tool_call`. Applications inject an
`ApproverAuthenticator`, a `ContinuationProtector` that provides authenticated encryption, and an
`ExecutorResolver`. No default/plaintext protector exists. The protected continuation binds the
original invocation and trace, immutable payload and digest, permission context, exact exported
policy snapshot, ordered chain fingerprint and cursor, prior decisions, TTL, and the complete
executor ID/version/fingerprint.

The store reserves exact timestamps, attaches only the opaque envelope, and retains only a token
verifier. Decisions transition through `DECISION_PREPARED`; a stable schema-v5 approval/denial
event is committed with `write_once` before `APPROVED`/`DENIED` becomes effective. Denial and
expiry also commit one stable `delivery_denied` before their effective terminal store transition.
Resume accepts only escalation ID and token. It validates the complete restart-resumable chain and
cursor, exact restored policy bundle, executor reference, current identity, RBAC, and evidence
snapshot before claim. The atomic claim persists a stable claim ID and timestamp; the kernel then
signs `escalation_resumed` and runs against the already pinned bundle. Cursor state records every
previously approved escalation, so later approvals continue strictly after each approved guardrail
without bypassing downstream controls. A changed active policy bundle or executor reference fails
closed before claim.

INPUT resume is excluded until action/resource resolvers have an equivalent trusted registry.
Guardrail-triggered post-execution result delivery is handled separately in Phase 3.4c.
Process-crash windows after an execution claim remain Phase 3.4d. Ordinary pre-admission
cancellation after claim is reconciled to a stable `delivery_denied`; claimed work is never
automatically retried. An admitted or executing process crash requires explicit `IN_DOUBT`
reconciliation.

**Consequences:**

- Positive: approver identity is credential-derived, signed before activation, and never supplied
  by decision request JSON.
- Positive: callers cannot substitute payloads or executors during resume, and revoked RBAC grants
  stop execution after approval.
- Positive: concurrent/replayed resume attempts can produce at most one claimant and executor call.
- Positive: denied, expired, revoked, and pre-admission-cancelled requests close the invocation with
  one delivery terminal.
- Negative: policy-only and INPUT escalations remain non-resumable; PRE resume still requires a
  registered executor.
- Limitation: policy snapshots bind rule definitions and check-type names, not the semantic version
  of a custom handler implementation.

---

## ADR-032 — Protected POST approval resumes delivery, never execution

**Status:** Accepted
**Date:** 2026-08-26

**Context:** A completed tool result waiting on a post-stage approval is materially different from
a pre-execution continuation. Reusing the PRE shape would retain executor authority after the side
effect already occurred and could permit duplicate execution. Persisting the result in plaintext or
accepting a caller-supplied replacement would also break confidentiality and integrity. Generic
exactly-once recovery is impossible when a process can crash after an external side effect but
before recording whether it completed.

**Decision:** Phase 3.4c supports restart-safe delivery only for enforced, guardrail-triggered
POST_TOOL/POST_MESSAGE escalations with an authenticated cursor, a fully restart-resumable chain,
an exact `PolicyBundle` snapshot, and an injected `ContinuationProtector`. The protected
`PostExecutionContinuation` contains the completed `ToolResultPayload` and digest, post-stage
cursor, full chain fingerprint, policy and prior-decision evidence, permission context, execution
timing, and TTL. It deliberately contains no `ExecutorRef`. Authenticated-encryption AAD and signed
store metadata distinguish PRE execution from POST delivery, preventing continuation-kind
substitution. The file store contains only the opaque sealed envelope and token verifier.

Resume accepts only escalation ID and token. It opens and validates the protected POST state,
active policy bundle, full chain/cursor, current identity, RBAC, and result evidence before an
atomic `DELIVERY_CLAIMED` transition. The kernel then continues strictly after the approved
post-stage guardrail and never consults the executor registry. One stable delivery event ID makes
`delivery_completed` and `delivery_denied` mutually exclusive; the audit event is committed before
the matching `DELIVERED` or `DELIVERY_DENIED` store transition. A later post escalation creates a
new protected child request before the parent becomes `HANDED_OFF`. Policy-only post escalations
remain metadata-only because the policy engine does not yet expose an authenticated resumable
cursor.

Crashes after a delivery or execution claim are not auto-replayed. Phase 3.4d adds an execution
journal plus authenticated `IN_DOUBT` reconciliation for admission/completion/store/audit windows;
the only generic resolution for an unknown side effect is to deny delivery.

**Consequences:**

- Positive: restart after a protected post-stage request can deliver the exact sealed result without
  another executor call, even when no executor resolver is configured in the restarted process.
- Positive: concurrent resumes have one delivery claimant, while denial, expiry, revoked RBAC, and
  ordinary cancellation close delivery without re-execution.
- Positive: sequential post approvals preserve the complete authenticated cursor and hand off to a
  protected child request without replaying the tool.
- Negative: policy-only post escalation and INPUT escalation remain non-resumable.
- Limitation: a process crash after claim but before the audit/store pair converges requires the
  Phase 3.4d journal and reconciliation authority.

---

## ADR-033 — Claimed protected executions use a separate journal and deny-only unknown reconciliation

**Status:** Accepted
**Date:** 2026-08-27

**Context:** A durable escalation claim proves that one caller owns a continuation, but it does not
prove whether an admitted executor returned, whether its result was protected, whether
post-processing ran, or whether the delivery audit and store terminal converged. Automatically
re-running an executor after admission can duplicate an external side effect. Treating an absent
audit event as proof without a trusted head is also unsafe because a truncated log is
indistinguishable from a real crash window.

**Decision:** Phase 3.4d adds an optional `ExecutionJournal` beside `EscalationStore`; legacy
behavior is unchanged when the journal is not configured. The POSIX journal uses owner-only files,
one directory lock, atomic durable replacement, and an application-provided HMAC key. Its public
records contain authenticated claim and lifecycle metadata. Exact successful executor output is
stored only in an AEAD-protected `ProtectedExecutionOutcome` bound to escalation, claim,
invocation, payload digest, policy bundle, and guardrail-chain fingerprint. The journal contains no
executor reference.

For journaled PRE resumption, the kernel commits stable
`invocation:{id}:admission`, `invocation:{id}:execution-completed`, and
`invocation:{id}:delivery` event IDs. It marks admission before executor entry and protects the
successful outcome before any post-processing. `reconcile_known_outcome` can therefore complete a
missing execution-completion audit and resume post-processing from the exact sealed result without
resolving or invoking an executor. Current identity, RBAC, policy, chain, and continuation bindings
are revalidated before delivery.

Executor exception, cancellation, and invalid-output paths do not remain ambiguous after the
journaled admission. They write the stable `invocation:{id}:delivery` denial and commit
`DELIVERY_DENIED`; repeated cancellation is drained until both terminal operations finish before
`CancelledError` propagates. For successful execution, the journal atomically commits
`POST_PROCESSING_CLAIMED` before a stable audit marker. The normal path uses
`execution_post_processing_claimed` at `invocation:{id}:post-processing-claimed`; protected-result
reconciliation uses `execution_reconciliation_resumed` at the reconciliation event ID. No POST
policy or guardrail callback starts before its marker commits. A crash after journal claim but
before the marker is consequently deny-only `IN_DOUBT`, not permission to rerun callbacks.

`assess_execution` and both reconciliation operations authenticate through
`ApproverAuthenticator` and require the credential-derived principal to hold `hitl:reconcile`.
Before classifying an absent boundary, assessment calls
`AuditLog.read_verified(require_checkpoint=True)` and combines that attested head with authenticated
escalation and journal state. Missing terminals are classified as `claimed_without_terminal`,
`admission_without_completion`, or `completion_without_protected_result`. Admission with no
protected outcome and already-claimed POST processing are ambiguous side-effect/control windows,
so they become `IN_DOUBT`; the only generic resolution is `deny_in_doubt`, which records an
authenticated reconciliation and one stable delivery denial. Executors and post guardrails are
never replayed for these unknown states.

Positive recovery checks use verified stable claim and delivery markers as evidence even without an
external checkpoint; they never treat absence as proof. If an older but correctly signed journal
record is restored, an existing claim marker restores/blocks the claimed state without rerunning
POST callbacks, and an existing stable delivery terminal converges the journal or raises on a
conflict. External checkpoint attestation remains mandatory only when missing lifecycle evidence is
used to distinguish an unknown window from log truncation.

Audit schema v6 signs typed `ReconciliationEvidence`: escalation, claim, and reconciliation IDs;
classification and state; credential-derived reconciler ID; reason digest; assessment time;
attested audit-chain head; and journal revision/digest. Frozen v1-v5 canonical forms remain
unchanged. Prepare→audit→commit journal transitions, stable lifecycle IDs, and stable POST-claim
markers make append-then-raise and valid signed-journal rollback windows converge without accepting
caller-supplied replacement authority.

The public reconciliation methods accept no result, payload, executor, executor ID, or disposition.
This phase covers claimed protected PRE/POST continuations only. It explicitly excludes legacy
caller-supplied executors, policy-only escalations, INPUT escalations, and general exactly-once
execution/replay.

**Consequences:**

- Positive: a protected known result can survive restart and continue through the remaining
  post-processing without a second executor call.
- Positive: unknown execution and post-claim windows are visible as signed `IN_DOUBT` evidence
  rather than being mislabeled allowed or automatically retried.
- Positive: checkpoint-attested absence, stable lifecycle IDs, and prepare→audit→commit transitions
  let audit and journal state converge after interrupted writes.
- Positive: a signed audit claim/terminal marker prevents POST callback replay even when local
  journal storage is rolled back to an older valid record.
- Negative: applications must provision and protect a separate journal signing key and continuation
  protector, then operationally route `IN_DOUBT` cases to an authorized reconciler.
- Limitation: denial closes delivery but cannot determine or undo an external side effect that may
  already have occurred.
- Limitation: process-local locking serializes one kernel instance; the POSIX journal is a local
  trusted-filesystem implementation, not a multi-host coordinator.

---

## ADR-034 — Mechanism-neutral authentication contracts precede runtime enforcement

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The governed runtime resolves a caller-supplied `agent_id` before RBAC. Adding one
credential verifier directly to that path would mix credential mechanism, identity proof,
authorization state, registry administration, adapter credential retrieval, and audit evolution in
one change. It would also invite role claims from a credential to become authorization authority.
Authentication failures need durable evidence, but rejected credentials must not cause claimed
identities, raw provider errors, or credentials to enter the audit log.

**Decision:** Phase 3.5a defines mechanism-neutral, async, runtime-checkable protocols:
`AgentCredentialProvider` returns one opaque per-call credential; `AgentAuthenticator` turns an
opaque credential into an `AuthenticatedAgentPrincipal`; and `ControlPlaneAuthenticator` returns a
distinct `ControlPlanePrincipal`. Agent principals contain credential-derived `agent_id`, method,
authority, a SHA-256 credential digest, and UTC issuance/validity/authentication timestamps. They
intentionally contain no roles or capabilities. The control-plane type has a separate principal ID
and immutable capabilities so future registry mutation cannot reuse the workload-agent trust
domain.

`AuthenticationFailure` is the canonical enumeration for the reserved machine-stable reason codes:
`AUTH.CREDENTIAL_MISSING`, `AUTH.CREDENTIAL_INVALID`, `AUTH.CREDENTIAL_EXPIRED`,
`AUTH.CREDENTIAL_NOT_YET_VALID`, `AUTH.CREDENTIAL_REVOKED`, `AUTH.PRINCIPAL_MISMATCH`,
`AUTH.IDENTITY_INACTIVE`, `AUTH.PROVIDER_FAILURE`, and `AUTH.INTERNAL_ERROR`.
`AuthenticationError` exposes only one of these classifications and provides no raw-error,
credential, or provider-detail channel.

Audit schema v7 adds frozen `AuthenticationEvidence` bound to the
`authentication_succeeded`/`authentication_rejected` lifecycle types. Verified evidence signs the
credential-derived identity, method, authority, SHA-256 credential digest, authentication and
validity timestamps, and optional registry revision. Rejected evidence signs only method, digest,
attempt time, and a canonical failure classification; it forbids trusted agent/authority fields,
credential validity timestamps, and registry metadata. Rejected-event producers reserve
`__unauthenticated__` as the outer `AuditEvent.agent_id` and must never persist a claimed identity,
roles, raw credential, or raw verifier/provider error.

Schema v7 has its own frozen `agentguard.audit.event.v7` HMAC domain and canonical envelope.
Verification retains explicit schema-specific v1-v6 branches, so their signed bytes and meanings
remain exact. Authentication evidence on a pre-v7 record is rejected as an unsigned extension.
Collector normalization round-trips the typed v7 evidence.

This ADR does not claim runtime authentication. Phase 3.5b must make the registry authoritative;
3.5c must authenticate before identity/executor lookup and bind protected continuations; 3.5d must
obtain fresh credentials per adapter call; and 3.5e must select and implement a concrete signed
short-lived credential verifier. Until those slices land, the kernel and adapters still accept a
self-asserted `agent_id`.

**Consequences:**

- Positive: credential mechanisms can change without changing the principal, provider, or audit
  contracts.
- Positive: authentication proves identity only; authorization roles remain a registry concern.
- Positive: rejected attempts have a stable, secret-free evidence shape and reserved actor boundary.
- Positive: adding authentication evidence does not rewrite or reinterpret v1-v6 audit history.
- Negative: applications cannot enable agent workload authentication by configuring these types
  alone; no concrete verifier ships in this slice.
- Limitation: the reserved unauthenticated actor is a producer contract for the future runtime path;
  Phase 3.5a does not yet emit kernel authentication events.

---

## ADR-035 — Authoritative registry mutations use a distinct authenticated, audit-first control plane

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The legacy `AgentRegistry` accepts caller-selected IDs and roles, while
`FileBackedRegistry` stores that authorization state as unsigned JSON. Reusing either type as the
authorization authority for authenticated workloads would let application code mint roles outside
an administrative trust boundary. A replacement also has to survive concurrent writers, retries,
cancellation, interrupted audit/store writes, and restart without claiming that an unaudited
mutation took effect. Roles cannot come from the workload credential defined in ADR-034.

**Decision:** Phase 3.5b introduces a separate read and administration boundary.
`AgentRegistryRecord` is deeply immutable and carries registry-owned identity metadata, sorted
roles, active/revoked status, credential epoch, record revision, and UTC lifecycle timestamps.
`AgentRegistrySnapshot` binds a defensive, canonically ordered record set to one registry ID and
monotonic global revision. Registration starts at record revision and credential epoch 1. Every
committed mutation advances the global revision and target record revision exactly once; role
replacement preserves the credential epoch, while credential rotation and revocation advance it.
Revoked records remain available through administrative reads but `resolve()` rejects them.

`AuthoritativeAgentRegistry` is read-only. Mutations are available only through
`AgentRegistryControlPlane`, which receives an opaque credential and calls the distinct
`ControlPlaneAuthenticator` before reading registry state. The resulting `ControlPlanePrincipal`
must hold the exact capability for register, replace roles, rotate credentials, or revoke.
`RoleGrantPolicy` additionally requires exact, separately configured grant/revoke capabilities for
each changed role; wildcard capability matching and unknown roles fail closed.

Each typed command supplies a stable operation ID and optional expected registry revision. The
registry prepares an immutable operation containing the authenticated-principal digest, request
digest, proposed record, base/target revisions, and deterministic event identity. The control
plane writes the exact authorization event, reads it back from verified audit history, validates
its signature-bound fields, and only then commits. Ledger state is
`PREPARED` → `AUDITED` → `COMMITTED` or `CONFLICTED`. An identical operation/principal retry returns
the committed result; operation-ID reuse with a different request or principal is rejected.
Concurrent stale-base commits become signed revision conflicts rather than lost updates. Repeated
cancellation is drained through the audit/commit boundary before `CancelledError` propagates.

Audit schema v8 adds frozen `RegistryMutationEvidence` and the
`agentguard.audit.event.v8` canonical HMAC domain. Authorized evidence binds the registry,
operation, mutation, authenticated administrator, authentication method/authority, credential and
capability digests, target, request, base/target revisions, before/after record digests, credential
epochs, and preparation time. Rejected evidence carries a canonical `REGISTRY.*` failure and does
not assert prepared state; only a revision conflict may include distinct requested and observed
revisions. Registry events cannot carry request payloads, workload roles, policy/guardrail/HITL
evidence, or raw credential/provider diagnostics. Verification retains explicit frozen v1-v7
serializers, and registry evidence on earlier schemas is rejected as an unsigned extension.

`InMemoryAuthoritativeAgentRegistry` provides process-local state and requires its own `AuditLog`.
Commit re-reads that sink and accepts only the exact operation event from a valid snapshot; a
module-private capability or control plane wired to another sink is not proof of durable evidence.
`SignedFileAuthoritativeAgentRegistry` persists the records, complete operation ledger, store and
registry revisions, latest committed audit reference, verified audit head, and key ID as canonical
JSON under a separate `agentguard.registry.state.v1` HMAC domain. A separately domain-signed,
hash-chained local checkpoint binds each durable state signature and permits only the exact
one-revision state-ahead crash window. A required `trusted_checkpoint_path` outside the registry
directory retains the latest checkpoint across restart. Its signing key must contain at least 32
bytes. The local POSIX implementation requires owner-controlled 0700 directories and owner-only
0600 regular state/checkpoint/lock files with one link; reads use `O_NOFOLLOW`; writers serialize
with process and `flock` locks, write unique temporary files, `fsync` them, replace atomically, and
`fsync` the directory. Blocking file transactions run through worker threads. It rejects malformed
or noncanonical state, schema/key/signature/checkpoint mismatch, symlinks, hard links, wrong
ownership/mode, and stale state or checkpoint observations.

Opening the signed store requires an audit sink that advertises durable checkpoints, reads verified
audit history, validates the persisted audit-head prefix, cross-binds every post-audit operation to
its exact signed event, rejects missing/conflicting operations, and resumes `PREPARED` or `AUDITED`
crash windows. Commit independently re-reads the store's own audit dependency, so a control plane
wired to another sink cannot authorize a mutation. Rejected administrative attempts also advance
the persisted audit head. These bindings detect restoration of one older valid registry or audit
file while its trusted counterpart remains current, including rollback of both registry-directory
files against the external trusted checkpoint. Deployments must retain that checkpoint path in an
independent failure domain. Coordinated rollback of it, the registry directory, and audit/checkpoint
files remains outside this boundary. This is a local POSIX store, not a distributed or multi-host
coordinator.

`AgentRegistry` and `FileBackedRegistry` remain available only for compatibility. They retain their
existing API and current kernel use, but their registration is self-asserted and their persistence
is unsigned. Phase 3.5b does not wire authentication or the authoritative resolver into
`GovernanceKernel`; that sticky runtime boundary remains Phase 3.5c. Per-call adapter credential
providers remain 3.5d, and selecting a concrete signed credential verifier and dependency remains
3.5e.

**Consequences:**

- Positive: workload credentials prove identity while registry state remains the sole role and
  lifecycle authority.
- Positive: administrative authentication, exact capability checks, signed evidence, and durable
  state are separate from the governed workload path and can evolve independently.
- Positive: prepare → audit → commit plus stable operation IDs makes retries, cancellation, and
  recoverable crash windows converge without applying an unaudited mutation.
- Positive: record/credential epochs give Phase 3.5c a monotonic value for revocation and protected
  continuation rechecks.
- Negative: secure deployments must provision and protect a separate registry HMAC key and audit
  backend, and must use the control plane rather than direct compatibility-registry mutation.
- Limitation: HMAC state provides symmetric integrity, not public non-repudiation; a compromise of
  the registry key can forge registry state.
- Limitation: this phase secures registry administration only. Governed calls still accept a
  self-asserted `agent_id` until Phase 3.5c.

---

## ADR-036 — Secure kernel mode authenticates before observation and binds resumable work

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The authoritative registry from ADR-035 was not yet on the governed workload path.
`GovernanceKernel` accepted a caller-supplied ID, registered calls could expose executor identifiers
before identity proof, and protected continuations bound only that asserted string. Authentication
also had to remain compatible with legacy applications and with exact schema-v1 continuation bytes.

**Decision:** `GovernanceKernel` has two mutually exclusive construction modes. Legacy mode accepts
only `AgentRegistry`; secure mode requires `AuthoritativeAgentRegistry` and `AgentAuthenticator`
together. Mixed and incomplete configurations fail at construction. Secure calls accept only an
opaque credential. Invocation identifiers are created without caller data; the authenticator first
returns a secret-free attempt descriptor, then a verified principal. The kernel validates the
credential window, obtains one atomic authoritative registry snapshot, requires an active matching
record, derives all roles and metadata from that record, and writes exact signed authentication
evidence before starting tracing or observing payload, action, resource, RBAC, or executor state.
Rejected attempts use the reserved unauthenticated actor and canonical `AUTH.*` reasons. Audit
failure blocks all downstream work.

Authenticated PRE and POST continuations use schema v2 and include a
`WorkloadAuthenticationBinding`: the credential-derived principal, registry identity and revision,
record revision, credential epoch, and exact signed authentication-event reference. Secure kernels
open only v2 AAD and re-read the referenced verified audit event; legacy kernels open only v1.
Version-aware serialization omits the v2 field entirely from schema-v1 PRE, POST, and nested journal
plaintext, preserving their frozen bytes and AAD.

Resume deliberately does not reacquire or revalidate the original short-lived credential and does
not compare its expiry to resume time. It rechecks the signed authentication binding, exact registry
identity, non-regressing registry/record revisions, active status, exact credential epoch, and
current registry-derived RBAC. PRE executor resolution and POST callbacks occur only after those
checks. Secure denial paths claim first and converge to stable signed non-replayable terminals;
cancellation after a durable PRE, POST, or journal post-processing claim is shielded and drained
before cancellation propagates.

**Consequences:**

- Positive: secure governed calls cannot fall back to self-asserted IDs or credential-supplied roles.
- Positive: credential rotation, identity revocation, and current RBAC changes invalidate approved
  PRE execution and POST delivery without requiring a long-lived credential.
- Positive: exact authentication evidence and registry epochs remain sticky through child handoffs,
  protected outcomes, restart, and reconciliation.
- Positive: legacy continuation plaintext and AAD remain byte-compatible.
- Negative: secure resume re-reads verified audit history and an authoritative registry snapshot.
- Limitation: no concrete signed credential verifier is selected until Phase 3.5e.
- Limitation: explicitly legacy kernel construction remains a self-asserted compatibility surface.

---

## ADR-037 — Adapters acquire fresh credentials through a deferred kernel-bound caller

**Status:** Accepted
**Date:** 2026-08-27

**Context:** Secure kernel calls accepted credentials, but first-party adapters still stored a
caller-supplied ID and constructed payload, action, resource, and tool/executor data before entering
the authenticate-first boundary. Acquiring a credential directly in each adapter would also leave
provider failures outside signed kernel evidence and make it easy to cache a credential or expose
raw provider diagnostics.

**Decision:** `GovernanceKernel.bind_adapter()` validates one identity source at adapter
construction and returns a mode-neutral `GovernedAdapterCaller`. Legacy bindings require exactly an
agent ID; secure bindings require exactly an `AgentCredentialProvider`. The provider is stored as a
credential source, but every returned credential remains local to one call coroutine and is never
stored by the adapter, caller, or kernel.

Adapters submit a synchronous zero-argument factory that produces a frozen `AdapterToolCall` or
`AdapterRegisteredToolCall`. In secure mode the caller first creates internal invocation IDs,
invokes the provider exactly once, authenticates the returned opaque credential, resolves one
authoritative registry snapshot, and writes signed authentication evidence. Only then may it invoke
the factory or expose request, payload, action, resource, tracer, tool registry, executor closure,
or registered executor ID. All five first-party adapters store only the bound caller and defer those
values. LangGraph performs neither claimed-actor logging nor tool lookup before authentication.

A provider exception or `None` result is classified as `AUTH.PROVIDER_FAILURE`. Its rejection
evidence uses the reserved unauthenticated actor and `AuthenticationAttempt.for_provider_failure()`:
the fixed method `agentguard.credential-provider.unavailable` and a domain-separated no-credential
digest. Provider type, configuration, exception, request, and credential data do not enter evidence
or exception chaining. Cancellation propagates without being mislabeled. The common authentication
event writer requires exact signed chain fields for success and rejection before the call may
continue or return its canonical authentication failure.

The deprecated `run_governed` shim remains structurally legacy-only and accepts no authenticator,
authoritative registry, or credential provider. First-party adapters do not call it.

**Consequences:**

- Positive: each secure adapter attempt uses a fresh credential and can rotate safely across
  sequential and concurrent calls.
- Positive: provider and authentication failure occur before request construction and produce
  signed, secret-free, fail-closed evidence.
- Positive: shared secure kernels can serve adapters with distinct credential providers without
  exposing a mutable kernel mode or global credential source.
- Negative: adapter request construction is deferred through a small public command/caller surface.
- Limitation: injected providers remain trusted not to log their own secrets internally.
- Limitation: no concrete signed verifier ships until Phase 3.5e; explicitly legacy adapters and the
  deprecated shim remain self-asserted compatibility surfaces.

---

## ADR-038 — Concrete workload authentication uses offline pinned RS256 JWT verification

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The secure kernel and adapters required fresh opaque credentials but shipped only a
mechanism-neutral `AgentAuthenticator` protocol. Phase 3.5e needed a concrete short-lived verifier
with explicit issuer, audience, subject, algorithm, rotation, expiry/skew, replay, and emergency
revocation semantics without importing a credential mechanism into registry administration.
Networked OIDC discovery or attacker-triggered key refresh would also add SSRF, cache, and event-loop
risks to the authentication-first boundary.

**Decision:** `agentguard[auth]` adds `PyJWT[crypto]>=2.13,<3` as an optional dependency and exposes
`JwtAgentAuthenticator`. The verifier accepts only bounded compact JWTs using fixed `RS256`, one
exact issuer and audience, canonical `sub` and `jti`, required integer `iat`/`nbf`/`exp`, a bounded
lifetime, and explicit leeway. JOSE headers must identify an operator-pinned local public RSA JWK by
canonical `kid`; token-provided keys, key URLs, critical extensions, private key members, weak keys,
and algorithm/use/key-operation mismatches are rejected. Signature verification runs through a
bounded semaphore in a worker thread. The verifier performs no discovery, network fetch, or unknown
key refresh.

`JwtKeySetProvider` returns immutable snapshots. The bundled provider atomically rotates to a new
strictly increasing integer revision using compare-and-swap, retains only the immediately previous current keys for a configured
bounded overlap, and drops them after that interval. `CredentialUseStore` atomically checks
revocation and consumes `(issuer, jti)` through the credential's effective expiry. Replay uses the
distinct `AUTH.CREDENTIAL_REPLAYED` failure; issuer, key, subject, token ID, and exact credential
digest can be revoked. Capacity or backend failure denies as `AUTH.INTERNAL_ERROR`, raw credentials
and backend diagnostics never enter exceptions, and cancellation propagates. Replay backends own a
serialized, nondecreasing trusted clock; the protocol deliberately accepts no caller-supplied
current time, and clock rollback fails closed before pruning or consumption. Rotation overlap uses
elapsed monotonic time rather than wall time and drops previous keys on a monotonic-clock violation.

JWT claims establish identity only. Roles and lifecycle state remain exclusively authoritative-
registry data, and the control plane keeps a separate authenticator and trust root. The bundled key
and credential-use stores are bounded process-local implementations; multi-process deployments must
inject shared atomic implementations. Emergency JWT key/subject revocation must be paired with
registry credential rotation or identity revocation when already-approved protected continuations
must also be invalidated.

**Consequences:**

- Positive: secure kernels now have a concrete, fixed-algorithm, short-lived workload credential
  verifier with adversarially tested key, claim, replay, rotation, and revocation semantics.
- Positive: pinned local key snapshots keep attacker-controlled networking and refresh outside the
  governed request path.
- Positive: protocol boundaries allow durable shared replay/key state without adding a database or
  network dependency to the library.
- Negative: operators must distribute pinned public keys and coordinate normal overlap and
  emergency rotation explicitly.
- Limitation: bundled replay and key state is process-local; it is not sufficient for independent
  workers without a shared implementation.
- Limitation: JWT revocation does not itself advance the registry credential epoch used by protected
  continuation resume.

---

## ADR-039 — Adverse-action reasons require explicit direction, provenance, and model binding

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The credit-risk template produced ad hoc values called feature importances, and the
notice generator ranked their absolute magnitude. Favorable and zero factors could therefore
become denial reasons, while unknown factors disappeared silently. The notice stored only English
strings, conflated Regulation B principal reasons with the separate FCRA credit-score-factor
limits, and could not identify the model, reference, attribution method, or taxonomy that produced
a reason.

**Decision:** Credit models now cross an explicit attribution boundary. Scorecard attribution uses
declared score direction and points lost from an exact reference; coefficient attribution uses
declared modeled-output direction and the signed coefficient delta from an exact transformed
reference profile. Both reject non-finite or mismatched inputs and emit only strictly positive
contributions. The immutable result retains the complete evaluated feature schema, including
favorable and zero factors, plus model ID, model version, reference ID, and method.

`ReasonCodeRegistry` separates a versioned ECOA vocabulary from per-model feature bindings and
from deployer-supplied FCRA bureau factor codes. The Appendix C seed uses explicitly
AgentGuard-local IDs; deployers must bind every feature actually evaluated. The mapper verifies
that the binding exactly covers the complete attribution schema before positive filtering,
consolidates features mapped to the same reason by summed contribution, and rejects empty or
unmapped evidence with stable `AA.*` failures. Those domain exceptions live in the shared
`agentguard.exceptions` hierarchy despite the file's security-runtime ownership because Phase 4.2
must map them to guardrail outcomes without parsing error text; this ADR authorizes that
cross-owner contract addition.

There is no default hard limit on ECOA principal reasons. An institution may configure a
presentation limit as policy. FCRA score-factor limits and inquiry handling remain a distinct
Phase 4.3 notice field. The ambiguous `feature_importances` and unversioned `reason_map` APIs are
removed as an intentional pre-1.0 correction rather than preserved through an unsafe compatibility
shim.

**Consequences:**

- Positive: a favorable or zero factor cannot be emitted as an adverse reason.
- Positive: an unbound feature fails before applicant-specific filtering, even when favorable for
  the current applicant.
- Positive: notices retain enough attribution and taxonomy provenance for Phase 4.2 integrity
  guardrails and signed audit linkage.
- Positive: FCRA bureau factors cannot substitute for ECOA principal reasons by type or namespace.
- Negative: existing callers must migrate from arbitrary importance dictionaries to an explicit
  attributor and per-model reason binding.
- Limitation: bundled Appendix C-derived wording and institution/bureau mappings still require
  deployer legal/compliance review before use.

---

## ADR-040 — Credit notices are typed regulatory artifacts rendered deterministically

**Status:** Accepted
**Date:** 2026-08-27

**Context:** ADR-039 established truthful principal-reason evidence but its interim notice wrapper
contained only applicant ID, creditor name, a PD score, and mapped reasons. It could not represent
the distinct Regulation B denial, counteroffer, incomplete-application, or withdrawal lifecycles;
prove written-notice timing; distinguish FCRA consumer-report, non-CRA third-party, and affiliate
disclosures; or reproduce the exact consumer document. It also coupled bureau factor vocabulary to
the ECOA registry even though the two disclosures have different legal roles and count rules.

**Decision:** Replace the interim generic generator and wrapper before 1.0 with frozen,
extra-forbid artifacts for denied applications, standalone counteroffers, combined
counteroffer/adverse action, counteroffer nonacceptance, incomplete applications, and withdrawal
records. The artifacts distinguish written notification from the initial counteroffer event,
calculate 30- and 90-day boundaries from actual events, and reject late records with stable
`AA.NOTICE_WINDOW_EXCEEDED` failures. Principal reasons use one ranked vocabulary but carry either
complete model attribution or explicit versioned policy/HITL component provenance. Denials support
both completed-application and action-taken triggers, while combined C-4 artifacts require written
acceptance instructions, a response address, and an acceptance deadline.

FCRA applicability is a required discriminated assertion. Consumer-report sources require unique
CRA contacts and an explicit score-used assertion; score disclosure is present if and only if a
score was used. Non-CRA third-party and affiliate sources retain separate typed written-request,
60-day request, and response rules. `BureauFactorRegistry` is independent from
`ReasonCodeRegistry`; it validates and ranks the complete adverse attribution, selects four factors
for display, and appends one unambiguous inquiry factor when that factor is not already displayed.

`NoticeRenderer` accepts only compatible complete artifacts. It exposes versioned current C-1,
C-3, C-4, C-6, and AgentGuard standalone-counteroffer profiles and produces canonical UTF-8 text
with LF line endings, one terminal newline, and a SHA-256 digest over the exact bytes. Rendering is
pure: render time is not notification time and no audit event is written. Phase 4.2 places only
typed redacted notice references in governed evidence; notice bodies and applicant PII do not
enter the audit chain.

**Consequences:**

- Positive: notice construction cannot silently invent notification dates, mix source regimes, or
  imply model attribution for a policy or human-review reason.
- Positive: the same validated artifact round-trips to identical bytes and digest.
- Positive: withdrawn applications are retained as records and cannot be rendered as notices.
- Negative: pre-1.0 callers must migrate from `AdverseActionGenerator`/`AdverseActionNotice` to an
  explicit reason mapper, typed artifact, and renderer.
- Limitation: the profiles are source-grounded implementation aids, not a representation that one
  template satisfies every product, jurisdiction, delivery channel, or institutional legal review.

---

## ADR-041 — Credit decisions use the kernel lifecycle and PII-free signed evidence

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The legacy `CreditDecisioningAgent` was a synchronous threshold helper with no
governance dependencies. One broad permission could not independently authorize scoring,
approval, review, decline, override, and notice recording. The helper also could not place a
decision at the kernel's post-execution control boundary, bind truthful reason/model evidence, or
correlate a delivered decline with its required notice without retaining sensitive decision data.
Generic HITL approval was additionally unsafe as a proxy for an underwriter's final credit
disposition.

**Decision:** Add immutable `DecisionPayload` results and `GuardrailStage.ON_DECISION` to the
existing `GovernanceKernel` lifecycle. The kernel preserves a returned decision payload and applies
the same authentication, derived-resource RBAC, staged policy, limiter/breaker, audit-first
admission, shadow, protected post-execution resume, and delivery-terminal contracts used by other
governed results. Domain code may not invoke the guardrail chain directly or create a second
credit-only governance path.

`CreditDecisionPolicy` owns only pure, versioned finite-PD banding into `approve`, `review`, or
`decline`. `GovernedCreditAgent` owns thin orchestration through the fixed actions `model:score`,
`decision:approve`, `decision:review`, `decision:decline`, `decision:override`, and `notice:issue`.
Mixed credit guardrails are action-scoped: the typed decision envelope, protected-feature schema,
trusted exact model/version validation and fairness evidence, review band, decline reason taxonomy,
and attribution integrity apply to decision actions; notice completeness applies only to
`notice:issue`. Trusted model provenance comes from an injected provider, never caller-supplied
decision attributes, and missing, stale, mismatched, failed, or insufficient evidence fails closed.
`ON_DECISION` is terminal and non-transformable so a later guardrail cannot invalidate the action
or safe-evidence envelope already checked for the emitted outcome.

A review result escalates at `ON_DECISION` with `HITL.REVIEW_BAND`. Approving that request releases
only the sealed review result and does not change its outcome or authorize credit. The
underwriter's final approve or decline is a separate `decision:override` call with its own RBAC
action. Inside the admitted executor, a checkpoint-backed validator requires the same reviewed
decision identifier and exact application/model/policy references across the ordered
`escalation_requested`, `approval_granted`, `escalation_resumed`, and delivered-review lifecycle;
only then is the typed parent escalation link emitted.

Signed audit retention uses explicit allowlisted projections and domain-separated opaque
application, decision, model, policy, and notice references. Raw identifiers, applicant data, PD,
feature names/values, contributions, reason text, and notice bodies are excluded from redacted
audit payloads. The full decision remains available to in-process controls and, when approval is
required, only inside the protected continuation; linked continuation schema v3 preserves this
separation without changing exact schema-v1/v2 bytes or any frozen audit wire version.
Caller projections remain digest-only on execution, cancellation, denial, and journal-marker
events until the post-execution/decision controls accept them.

`notice:issue` records an already-completed written notification. It does not send a notice or
treat rendering as delivery. Its safe evidence binds the opaque references, artifact/profile and
template versions, exact rendered-body digest, actual notification timestamp, and deadline; the
trusted local prepared-notice provider is populated inside the admitted executor and rerenders the
PII-bearing artifact for validation outside audit evidence. A notification timestamp later than
the trusted current time is incomplete and cannot be recorded as completed.

`find_unresolved_declines` classifies only checkpoint-attestable signed history. A delivered
decline is resolved only by a later delivered `notice:issue` with matching opaque decision and
application references, valid timely typed evidence, and an exact enforced
`credit-notice-completeness` allow evaluation. Final decline overrides are included; malformed
decline/override linkage produces an unresolved integrity finding rather than being skipped.
Denied, malformed, mismatched, unvalidated, or late attempts do not resolve it; invalid or
unanchored history raises instead of returning a clean result.

**Consequences:**

- Positive: score, decision band, override, and notice recording can be granted or denied
  independently and leave one consistent signed lifecycle.
- Positive: review approval cannot silently become a credit approval, and protected resume does
  not rerun scoring or decision execution.
- Positive: runtime controls inspect full-fidelity evidence while durable audit consumers receive
  only stable, linkable, PII-free projections.
- Negative: applications must configure the mixed guardrail chain, trusted model-evidence provider,
  prepared-notice provider, and action-specific RBAC grants explicitly.
- Limitation: the bundled static model-evidence provider, signed in-memory report source, and
  in-memory prepared-notice provider are local boundaries; durable report/private-notice storage,
  validation operations, and signing-key custody/rotation remain deployment responsibilities.
- Limitation: governed notice recording currently accepts decline candidates paired with a
  `DeniedApplicationNotice` or `CounterofferNonAcceptanceNotice`; the other typed notice artifacts
  are not yet accepted by this boundary.

---

## ADR-042 — Fairness evidence is directional, observation-level, and privately joined

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The original fairness analyzer selected group direction from observed sample extrema,
accepted caller-built aggregate dictionaries, applied no minimum denominators, treated sparse or
undefined rates as ordinary booleans, and compared one mean predicted PD with one mean outcome.
Consequently a finite random sample from an unbiased generator could be labeled unfair without
statistical context, calibration error could cancel across risk bands, and the API could not state
which group was disadvantaged. Feeding protected group, row-level PD, or matured outcomes into the
signed runtime audit would fix neither the statistics nor the privacy boundary.

**Decision:** `FairnessAnalyzer` requires explicit disadvantaged and reference group names and
immutable final-decision observations. Disparate impact is the favorable approval-rate ratio in
that fixed direction and the inclusive four-fifths point estimate controls its verdict. A pooled
two-sided two-proportion z-test is used only when every expected 2x2 cell is at least five;
otherwise an exact two-sided Fisher test is reported. The analyzer also reports a Katz log-risk-
ratio interval, with Haldane-Anscombe correction confined to zero-cell interval calculation.

Minimum sample size is applied independently to completed-decision, matured-default,
matured-non-default, and calibration denominators. Equalized odds defines decline as the adverse
prediction and default as the actual positive. Calibration uses fixed-width PD deciles and
count-weighted group ECE. Every check and the overall report use `PASS`, `FAIL`, or
`INSUFFICIENT_DATA`; inferential statistics remain descriptive and cannot override the
four-fifths point-estimate rule. The explicit aggregate compatibility method cannot claim
calibration because it has no row-level scored outcomes.

`FairnessMonitor` binds one canonical target model ID/version, reads only checkpoint-attestable
audit snapshots, and selects that model's delivered final approve, decline, or override events in
an open-closed time window. It requires exact opaque application/decision/model links, exact typed
decision evidence, and one enforced
`credit-decision-evidence` allow evaluation. Those opaque references are joined through an
injected trusted private provider to protected group, PD, and optional matured outcome. Missing,
malformed, duplicate, or failed joins prevent a clean pass. The returned monitoring report contains
only aggregate metrics, integrity counts, window/provider identity, and audit-head provenance;
private rows, opaque references, and event IDs are neither returned nor added to audit evidence.

**Consequences:**

- Positive: group direction and the four-fifths decision rule are stable across sample outcomes.
- Positive: sparse denominators and missing private evidence cannot become false passes.
- Positive: fixed-bin ECE detects calibration errors hidden by aggregate-mean cancellation.
- Positive: monitor output can feed exact model/version governance status without making protected
  attributes part of the runtime audit schema.
- Negative: callers must retain or privately join one observation per final decision and explicitly
  choose the policy-relevant group direction.
- Limitation: the analyzer supplies statistical evidence, not a legal conclusion or proof of
  fairness; deployers own group definitions, outcome maturation, sampling policy, thresholds, and
  review.
- Limitation: the bundled provider contract does not prescribe durable private storage or a
  multi-process scheduler.

---

## ADR-043 — Model validation authorizes only through verified exact-model reports

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The compatibility validator evaluated a few caller-supplied metrics and returned an
unsigned report. It could not prove which model or sample was evaluated, distinguish a stated Gini
definition, bind private fairness monitoring, track remediation revisions, resist field tampering
or rollback, or safely populate the trusted provider used by live decisions. Caller-controlled
guardrail attributes are intentionally non-authorizing.

Historical SR 11-7 supplies useful conceptual-soundness, ongoing-monitoring, outcomes-analysis,
effective-challenge, and remediation themes. Federal Reserve SR 26-2 superseded SR 11-7 on
April 17, 2026, while OCC Bulletin 2026-13 rescinded OCC Bulletin 2011-12. The current guidance is
principles-based and non-prescriptive; neither guidance generation mandates AgentGuard's schema,
Gini/AUC formula, thresholds, or an automated attestation.

**Decision:** Strict validation uses immutable versioned policy, exact-model backtest evidence,
optional same-sample challenger evidence, aggregate-only exact-model fairness-monitor evidence,
and owned finding lifecycles. ROC-derived Gini must be explicitly named and internally consistent
with AUC within policy tolerance. High/critical or overdue open remediation, insufficient/failed
fairness, stale evidence, and failed policy metrics produce an unvalidated report. New immutable
revisions retain one report identity, bind the exact predecessor reference, preserve every
unresolved finding through non-regressing lifecycle transitions, and require evidence-backed
closure no later than the new report time. Monitor status must agree with its aggregate verdict and
become insufficient when any integrity count is nonzero.

Only complete strict reports may enter a domain-separated canonical HMAC-SHA256 envelope. The
envelope binds its schema version, key ID, algorithm, canonical full report, and content reference;
verification uses pinned keys and constant-time comparison. A report source supplies the latest
exact model/version and predecessor revisions. The verifying provider pins source identity,
verifies the entire contiguous signed lineage and current validity window, then projects only the
existing trusted `ModelGovernanceEvidence`. Any exception or mismatch returns no evidence. A
current failed fairness binding retains its distinct live denial reason; invalid, insufficient,
future, expired, or otherwise unvalidated evidence receives the generic model-unvalidated denial.
The validity endpoint is not caller-selectable: it is the exact minimum of policy report validity,
backtest/fairness freshness, and unresolved-finding due dates (with a deterministic non-authorizing
boundary for already-expired inputs), and the provider recomputes it before projection.

The legacy convenience validator remains available only for unsigned offline compatibility. The
signer refuses its incomplete reports, and caller `GuardrailContext.attributes` never participate
in this trust handoff.

**Consequences:**

- Positive: live authorization is bound to one signed report revision, exact model/version,
  feature schema, fairness aggregate, policy, and validity window.
- Positive: contradictory metrics, fabricated challenger comparisons, report tampering, revision
  gaps/forks, and source identity changes fail closed.
- Positive: protected group labels and row-level outcomes remain in the private fairness provider;
  signed validation evidence carries only aggregate provenance.
- Negative: HMAC establishes integrity only inside one trust domain, not public non-repudiation.
- Limitation: the bundled report source is process-local. Durable multi-process storage,
  rollback-resistant checkpoints, independent validation operations, retention, and key
  custody/rotation are deployment responsibilities.
- Limitation: this report is an evidence contract, not legal advice, supervisory approval, or a
  regulatory attestation.

---

## ADR-044 — Synthetic data is a canonical testing namespace with compatibility exports

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The original finance domain exposed marginal random records and an unbounded WGAN as
if synthetic generation were a finance governance capability. The statistical generator had no
joint financial structure or calibrated bias control, while the optional WGAN lacked scaler state,
deterministic seeding, evaluation-mode single-row generation, and output bounds.

**Decision:** Canonical benchmark helpers live under `agentguard.testing`. The statistical generator
uses a seeded private RNG and one O(n) dependency-ordered pass: latent quality → income/property →
loan/LTV and obligations/DTI. Its uniformly assigned group labels are explicitly artificial;
`bias` deliberately shifts only `group_a` to produce a controlled disparity fixture, while
`bias=0` keeps group independent of latent quality. A fixed FICO/DTI/LTV approval predicate—not the
default label—defines the documented DI acceptance targets.

The optional WGAN accepts validated finite rectangular numeric data, persists an immutable
population standard scaler, uses explicit PyTorch RNGs, generates in evaluation mode under
`no_grad`, inverse-scales results, rejects invalid counts, and bounds named credit features
(including FICO to `[300, 850]`). PyTorch remains lazy and optional. The prior
`agentguard.domains.finance.synthetic` modules are identity-preserving compatibility re-exports
during the pre-1.0 transition; no production governance path consumes generated data.

**Consequences:**

- Positive: benchmark data has reproducible causal/joint structure and a measurable synthetic bias
  control suitable for fairness regression tests.
- Positive: WGAN output can be round-tripped through immutable scaler state and safely exercised on
  one-row batches without importing PyTorch in the base runtime.
- Negative: the bias fixture is artificial test data, not representative population evidence or a
  production credit model.
- Limitation: WGAN-GP remains an offline benchmark utility with no claim of model fidelity or
  regulatory suitability; durable artifact publication remains a deployment concern.

---

## ADR-045 — Phase 5 uses native optional boundaries and fail-closed assurance

**Status:** Accepted
**Date:** 2026-08-27

**Context:** The original integrations were tested only against async mocks and documented native
framework names without entering real graph/tool/session boundaries. Formal verification could
claim safety for unsupported wildcard/unicode cases or fabricate policy effects from severity.
Sandbox configuration accepted any runtime backend, and Docker output capture could materialize
unbounded logs.

**Decision:** First-party adapters retain dependency-free imports but expose native execution
boundaries: LangGraph nodes are callable in a compiled `StateGraph`, CrewAI uses an optional
`BaseTool` subclass with native synchronous `.run()` and async `.arun()` compatibility, ADK wraps
`FunctionTool`, MCP is validated through an in-memory `ClientSession`, and A2A delegates to
`message_send`. CI installs each declared framework extra in a matrix; local environments may
skip only package-specific tests.

Formal verification models RBAC wildcard/inheritance semantics where sound and returns `unknown`
for unsupported encodings, including Unicode outside the bounded Z3 character universe. SAT
witnesses are decoded to replayable runtime strings. The policy CLI never derives authorization
effects from compliance severity and exits nonzero for uncertainty/unsupported analysis.

Sandbox obligations are executable only at enforced PRE_TOOL, use the transformed authorized
argv, and require the hardened `DockerSandboxBackend`; host subprocess backends are rejected.
Docker uses non-root read-only containers, dropped capabilities, no-new-privileges, resource
quotas, daemon log rotation, and streaming byte caps. Runtime obligations are excluded from legacy
continuation serialization, preserving frozen v1 wire bytes; sandbox-before-escalation remains
non-resumable to prevent downgrade.

**Consequences:**

- Positive: native optional integrations and assurance uncertainty are exercised at their actual
  boundaries, not represented by mocks or optimistic exit codes.
- Positive: sandbox execution cannot silently fall back to host subprocesses, and output capture
  has bounded daemon/client memory behavior.
- Negative: framework and Docker tests require optional CI dependencies/daemon and are skipped in a
  minimal local environment.
- Limitation: MCP/A2A remain adapter boundaries around caller-provided sessions/transports; the
  project does not ship a central server or framework runtime.

---

*When you (Claude Code) make a new architectural decision, append it here following the same format. Increment the ADR number sequentially.*
