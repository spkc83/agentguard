---
created: "2026-04-19"
last_edited: "2026-04-19"
complexity: complex
---

# Cavekit: Security Runtime (Layer 1)

## Scope
The security runtime is the load-bearing foundation of AgentGuard. It enforces the four primitives every agent action passes through before reaching a tool: agent identity resolution, role-based access control, sandboxed execution, and immutable audit logging — protected by a circuit breaker and per-agent rate limiter. This kit covers what the runtime guarantees, not how upper layers (compliance, domain, observability) consume those guarantees.

## Requirements

### R1: Agent Identity Registry
**Description:** Agents are first-class principals identified by a stable, unique identifier carrying a name, an ordered list of role names, and arbitrary string metadata. Identity must be resolvable to the same record across the lifetime of an agent and may be persisted across process restarts.
**Acceptance Criteria:**
- [ ] Registering an agent without an explicit identifier assigns a freshly generated unique identifier.
- [ ] Registering two agents with the same explicit identifier raises a duplicate-agent error and does not mutate registry state.
- [ ] Resolving an unknown identifier raises an identity-not-found error.
- [ ] A file-backed registry restores all previously registered agents on construction from its persistence file and writes new registrations atomically (no torn writes if the process is killed mid-write).
- [ ] All registry mutations are safe under concurrent async callers (no lost or corrupted entries when multiple coroutines register simultaneously).
**Dependencies:** none

### R2: Role-Based Access Control with Deny-Override
**Description:** Permission decisions follow a deny-first, deny-override model: an agent has no rights unless explicitly granted, and any matching deny rule wins over any number of matching allow rules (per ADR-003). Roles support inheritance, and resolution must terminate even when inheritance graphs contain cycles.
**Acceptance Criteria:**
- [ ] An agent with no roles is denied every (action, resource) pair.
- [ ] An agent matched by both an allow and a deny permission for the same (action, resource) is denied.
- [ ] Action and resource patterns support wildcard matching so a single permission can cover families of actions or resources.
- [ ] Inherited role permissions are collected transitively and contribute to the deny-override evaluation.
- [ ] A permission check on a role graph that contains a cycle terminates and produces a deterministic decision (the cycle is logged but does not crash evaluation).
- [ ] Every permission decision returns a structured context that includes the decision (granted/denied) and a human-readable reason.

### R3: Append-Only HMAC-Chained Audit Log
**Description:** Every governed action produces an audit event written to an append-only log. Events form a tamper-evident chain (per ADR-007): each event embeds a cryptographic hash linking it to the previous event so that any modification, deletion, or reorder of past events is detectable. The audit log is the canonical record of governance activity (per ADR-019).
**Acceptance Criteria:**
- [ ] Constructing the audit log without a configured signing key raises an audit-key-missing error before any write is attempted.
- [ ] Each written event has a non-empty hash, and every event after the first has a previous-hash equal to the prior event's hash.
- [ ] On startup, the chain's prior-hash state is restored from existing on-disk events so a restarted process continues the existing chain.
- [ ] Verifying the chain over an unmodified log returns a successful result with the correct event count.
- [ ] Verifying the chain after any byte of any past event has been changed (or any event removed/reordered) raises a tamper-detected error identifying the first broken event.
- [ ] An audit event is written before its associated action executes (log-first, act-second per ADR-004); failure to write blocks the action.

### R4: Pluggable Audit Storage Backend
**Description:** Audit storage is an interface, not an implementation. The runtime ships with a date-partitioned file backend that produces newline-delimited JSON files, but any backend honoring the storage contract can be substituted without changing the audit log core or its callers.
**Acceptance Criteria:**
- [ ] The storage backend exposes append-one and read-all-in-order operations and nothing else.
- [ ] The default file backend writes one event per line to a date-stamped file under a configured directory and creates the directory if it does not exist.
- [ ] Reading from the default file backend returns all events from all date-stamped files in deterministic chronological order across files.
- [ ] A custom backend implementing the contract can replace the default without modifying audit log code (verified by an in-memory test backend).

### R5: Sandboxed Tool Execution
**Description:** Tool invocations executed by the runtime run inside an isolated sandbox enforcing timeout, memory limit, and default-off network access (per ADR-006). The runtime ships with a Docker container backend (default for production) and a no-op subprocess backend (development/testing only); both are interchangeable through a sandbox contract.
**Acceptance Criteria:**
- [ ] A sandbox execution that exceeds its configured timeout is forcibly terminated and returns a result distinguishable from a normal exit.
- [ ] The Docker backend defaults to disabling network access and only enables it when the per-call configuration explicitly opts in.
- [ ] The Docker backend enforces a memory limit on the spawned container.
- [ ] The Docker backend cleans up the spawned container on every code path (success, timeout, error).
- [ ] No execution path uses a shell with string-interpolated arguments (no `shell=True` equivalents in library code).
- [ ] If the Docker SDK is not installed, attempting to use the Docker backend raises a sandbox error pointing the user to the optional install.
- [ ] Every successful and failed sandbox run returns a structured result containing standard output, standard error, exit code, measured duration in milliseconds, and the backend name.

### R6: Sandbox Escape Resistance
**Description:** The sandbox is the primary defense against runaway or malicious agent tool code; deliberate escape attempts must not succeed. This requirement is verified by an adversarial test suite that exercises known escape vectors against the shipped backends.
**Acceptance Criteria:**
- [ ] Adversarial test cases that attempt shell injection through tool arguments do not execute on the host.
- [ ] Adversarial test cases that attempt to read host filesystem paths from inside the Docker backend do not return host file contents.
- [ ] Adversarial test cases that attempt to reach the network from a Docker container with networking disabled do not establish a connection.

### R7: Circuit Breaker
**Description:** A circuit breaker protects downstream services from cascading failure. After a configurable number of consecutive failures it transitions to an open state that rejects further calls; after a configurable cool-down it allows a probe call (half-open) and either re-closes on success or returns to open on failure.
**Acceptance Criteria:**
- [ ] In the closed state, calls pass through and successful calls reset the failure counter.
- [ ] After the configured number of consecutive failures, the breaker transitions to open and rejects subsequent calls with a circuit-open error without invoking the wrapped callable.
- [ ] After the recovery timeout elapses, the breaker reports a half-open state and admits the next call as a probe.
- [ ] A successful probe transitions the breaker back to closed; a failing probe leaves it in a state that again rejects calls until the next recovery interval.
- [ ] State transitions are safe under concurrent async callers.

### R8: Per-Agent Token-Bucket Rate Limiter
**Description:** Each agent has its own token bucket capping its call frequency. Buckets refill linearly at a configured rate up to a configured burst capacity; an agent that exhausts its bucket is rejected.
**Acceptance Criteria:**
- [ ] An agent making fewer than its allotted calls per second within the burst capacity is never rejected.
- [ ] An agent that issues calls faster than the refill rate eventually receives a rate-limit-exceeded error referencing its identifier and the configured limit.
- [ ] Rate limit state is tracked per agent identifier, so one agent exhausting its bucket does not affect another.
- [ ] Bucket accounting is safe under concurrent async callers.

### R9: Typed Shared Models and Exception Hierarchy
**Description:** All structures crossing layer boundaries (agent identity, permission decision, audit event, sandbox result, policy result) are validated typed schemas (per ADR-002). All runtime errors derive from a single base exception so callers can catch broadly or precisely.
**Acceptance Criteria:**
- [ ] Audit events, permission contexts, sandbox results, agent identities, and policy results are immutable after construction; mutations require producing a new copy.
- [ ] Constructing any shared model with a missing or wrongly typed field raises a validation error at the boundary, before the object reaches downstream code.
- [ ] Every runtime exception (permission denied, policy violation, audit key missing, audit tamper detected, identity not found, duplicate agent, sandbox error, circuit open, rate limit exceeded) inherits from a single base exception.
- [ ] Audit event timestamps are timezone-aware (UTC).

### R10: Log-First, Act-Second Execution Contract
**Description:** The runtime guarantees that no governed action observably executes before its corresponding allow/deny audit event is durably written, and that any execution failure produces a follow-up error event (per ADR-004). This invariant is enforced both by the security runtime layer and by every framework adapter (see cavekit-framework-integrations.md).
**Acceptance Criteria:**
- [ ] If audit log writing raises during the pre-execution event, the action is not executed.
- [ ] If a permission check denies the action, a denial event is written and the action is not executed.
- [ ] If execution raises after a successful pre-event write, an error event is written before the exception propagates to the caller.
- [ ] If writing the post-failure error event itself fails, the original execution exception still propagates to the caller (the secondary failure is logged but does not mask the primary).

## Out of Scope
- Compliance policy evaluation, formal verification, and human-in-the-loop escalation (see cavekit-compliance-engine.md).
- Domain-specific guardrails such as PII masking, fairness analysis, and adverse action notice generation (see cavekit-finance-credit-risk.md).
- Framework-specific tool wrappers for LangGraph, CrewAI, ADK, MCP, and A2A (see cavekit-framework-integrations.md).
- Replay, dashboards, and OpenTelemetry tracing (see cavekit-observability.md).
- Command-line interfaces over the runtime (see cavekit-cli-surface.md).
- WebAssembly sandbox backend (mentioned in architecture as optional but not implemented in v1.0.0).
- S3/GCS and PostgreSQL audit backends (mentioned in architecture as future options; only the file backend is shipped).
- Audit log rotation, compression, and retention policies (file backend writes one date-stamped file per day with no rotation/compression).
- HMAC key rotation tooling.

## Cross-References
- (none — this kit is the foundation other kits depend on.)

## Source Traceability
- R1 satisfied by: agentguard/core/identity.py + tests/unit/core/test_identity.py + tests/unit/core/test_file_registry.py
- R2 satisfied by: agentguard/core/rbac.py + tests/unit/core/test_rbac.py
- R3 satisfied by: agentguard/core/audit.py + tests/unit/core/test_audit.py
- R4 satisfied by: agentguard/core/audit.py (FileAuditBackend, AuditBackend Protocol) + tests/unit/core/test_audit.py
- R5 satisfied by: agentguard/core/sandbox.py + tests/unit/core/test_sandbox.py + tests/integration/test_sandbox_docker.py
- R6 satisfied by: agentguard/core/sandbox.py + tests/red_team/test_sandbox_escape.py
- R7 satisfied by: agentguard/core/circuit_breaker.py (CircuitBreaker, CircuitState) + tests/unit/core/test_circuit_breaker.py
- R8 satisfied by: agentguard/core/circuit_breaker.py (TokenBucketRateLimiter) + tests/unit/core/test_circuit_breaker.py
- R9 satisfied by: agentguard/models.py + agentguard/exceptions.py + tests/unit/test_models.py + tests/unit/test_exceptions.py
- R10 satisfied by: agentguard/core/audit.py (write ordering) + agentguard/integrations/_pipeline.py (run_governed) + tests/integration/test_core_e2e.py + tests/unit/integrations/test_pipeline.py

## Changelog
- 2026-04-19: Initial draft, reverse-engineered from v1.0.0 codebase.
