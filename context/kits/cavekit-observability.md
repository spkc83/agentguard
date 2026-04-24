---
created: "2026-04-19"
last_edited: "2026-04-19"
complexity: quick
---

# Cavekit: Observability (Layer 4)

## Scope
This kit covers the three observability surfaces that read from the audit log as their single source of truth (per ADR-019): an OpenTelemetry-native tracer for live spans, a replay debugger for historical reconstruction of governance decisions, and a metrics dashboard for aggregate KPIs. None of these surfaces introduces a second event store or mutates audit events.

## Requirements

### R1: OpenTelemetry-Native Tracer
**Description:** The tracer emits OpenTelemetry spans for governance decisions (RBAC checks, policy evaluations, tool calls). All custom span attributes use the project's namespace (`agentguard.*`) to align with OpenTelemetry semantic-conventions practice (per ADR-009).
**Acceptance Criteria:**
- [ ] Span attributes supplied by callers without the namespace prefix are emitted with the prefix added.
- [ ] Span attributes supplied with the namespace prefix already present are emitted unchanged.
- [ ] The tracer exposes convenience operations covering at least RBAC-check, policy-evaluation, and tool-call spans, each accepting the documented attribute set (agent identifier, action/resource/granted for RBAC; rule identifier/passed/severity for policy; tool name/result/duration for tool call).

### R2: NoOp Tracer Fallback
**Description:** OpenTelemetry is an optional dependency. When the SDK is not installed (or tracing is explicitly disabled), the tracer must yield no-op span objects with zero overhead and never raise (per ADR-018).
**Acceptance Criteria:**
- [ ] Constructing the tracer in an environment without the OpenTelemetry SDK installed succeeds and reports inactive status.
- [ ] Constructing the tracer with tracing explicitly disabled succeeds, reports inactive status, and yields no-op spans even when the SDK is installed.
- [ ] Calling any span operation on a no-op span (set attribute, set status, record exception, end) is a no-op and never raises.
- [ ] An inactive tracer's span context manager yields a no-op span without invoking any OpenTelemetry call.

### R3: Library-Mode Tracer Provider Safety
**Description:** AgentGuard is a library and must never mutate the host application's global tracer provider (per ADR-021). The tracer requests a named tracer from whatever provider the host application has configured and inherits that provider's behavior.
**Acceptance Criteria:**
- [ ] Tracer construction does not call any provider-mutating API on the OpenTelemetry SDK.
- [ ] When the host application configures an OpenTelemetry provider after AgentGuard's tracer is constructed, subsequent spans emitted by the tracer use the host's provider.

### R4: Replay Debugger Loading and Filtering
**Description:** The replay debugger loads audit events from the file backend and filters them by agent identifier, action substring, result, and time range. Events are returned in chronological order regardless of file storage order.
**Acceptance Criteria:**
- [ ] Loading from a directory returns every audit event in every date-stamped file in chronological order.
- [ ] Filtering by agent identifier returns only events whose agent identifier matches exactly.
- [ ] Filtering by action returns events whose action contains the provided string (substring match).
- [ ] Filtering by result returns only events whose result equals one of {allowed, denied, escalated, error} when supplied.
- [ ] Filtering by time range returns only events with timestamps within the inclusive range.
- [ ] Multiple filter criteria compose conjunctively (all supplied filters must match).

### R5: Replay Decision Timeline
**Description:** Given a list of audit events, the debugger produces an ordered timeline of structured entries, each containing the original event, a position index, a human-readable decision summary, and a list of warning flags.
**Acceptance Criteria:**
- [ ] Each timeline entry includes the underlying audit event unmodified.
- [ ] Denied events carry a "denied" flag and a summary referencing the permission decision reason.
- [ ] Error events carry an "error" flag and a summary indicating an execution error occurred.
- [ ] Escalated events carry an "escalated" flag and a summary referencing the escalation.
- [ ] Events with at least one failed policy result carry a "policy_violation" flag and a summary entry per failed rule referencing the rule identifier and severity.
- [ ] Timeline entries preserve the input event order and use a contiguous zero-based index.

### R6: Replay Summary Counts
**Description:** The replay debugger produces a quick summary of an event collection broken down by result, by agent, and by action.
**Acceptance Criteria:**
- [ ] The summary reports the total event count.
- [ ] The summary includes per-result counts covering each distinct value of {allowed, denied, escalated, error} present in the events.
- [ ] The summary includes per-agent and per-action counts.

### R7: Aggregate Governance Metrics
**Description:** The metrics dashboard computes aggregate governance KPIs from a list of audit events: total events, per-result counts, overall denial rate, latency p50/p95/p99, per-agent metrics, top-N actions, policy-violation trends, and the time range covered.
**Acceptance Criteria:**
- [ ] Computing on an empty event list returns a zero-valued metrics structure (no exception, no division by zero).
- [ ] Per-result counts (allowed, denied, error, escalated) sum to the total event count.
- [ ] Overall denial rate equals denied count divided by total event count.
- [ ] Latency percentiles are computed only over events with positive duration (events with zero or negative duration are excluded).
- [ ] Per-agent metrics include a denial rate per agent equal to that agent's denied count divided by its total count.
- [ ] Top actions are reported as the most frequent action names with their counts in descending order, capped at ten entries.
- [ ] Policy-violation trends report each rule that produced at least one failed evaluation, the count of failures, and the timestamp of the most recent failure.
- [ ] The metrics structure reports the earliest and latest event timestamps.

### R8: Metrics Serialization Surfaces
**Description:** The aggregate metrics structure is serializable to a machine format and a reviewer-readable text format suitable for dropping into a status report.
**Acceptance Criteria:**
- [ ] Metrics serialize to indented JSON containing every reported field.
- [ ] Metrics render to Markdown including the headline counts and rates, the latency percentiles, the time range, the top actions table, the per-agent table, and the policy violation table when the corresponding data is present.

## Out of Scope
- Identity, RBAC, audit log writing, sandbox, circuit breaker, rate limiter (see cavekit-security-runtime.md).
- Policy evaluation, formal verification, attestation reporting (see cavekit-compliance-engine.md).
- Credit-risk and PII analytics (see cavekit-finance-credit-risk.md).
- Framework adapter mechanics (see cavekit-framework-integrations.md).
- Command-line entry points to observability surfaces (see cavekit-cli-surface.md).
- Audit log pagination and streaming for very large logs (mentioned in ADR-019 as future work).
- Cost / token attribution attributes (`agentguard.cost.tokens`, `agentguard.cost.usd`) named in ARCHITECTURE.md as part of the semantic conventions; the tracer convenience helpers do not populate these in v1.0.0. [GAP]

## Cross-References
- See also: cavekit-security-runtime.md (audit events are the data source for replay and dashboard; AuditEvent schema is consumed unchanged)

## Source Traceability
- R1 satisfied by: agentguard/observability/tracer.py (AgentTracer.span, ATTR_PREFIX, trace_rbac_check/policy_evaluation/tool_call) + tests/unit/observability/test_tracer.py
- R2 satisfied by: agentguard/observability/tracer.py (_NoOpSpan, lazy import + enabled flag, is_active) + tests/unit/observability/test_tracer.py
- R3 satisfied by: agentguard/observability/tracer.py (no set_tracer_provider call; uses trace.get_tracer only) + tests/unit/observability/test_tracer.py
- R4 satisfied by: agentguard/observability/replay.py (ReplayDebugger.load and filter) + tests/unit/observability/test_replay.py
- R5 satisfied by: agentguard/observability/replay.py (ReplayDebugger.timeline, ReplayEntry) + tests/unit/observability/test_replay.py
- R6 satisfied by: agentguard/observability/replay.py (ReplayDebugger.summarize) + tests/unit/observability/test_replay.py
- R7 satisfied by: agentguard/observability/dashboard.py (MetricsDashboard.compute, DashboardMetrics, AgentMetrics, PolicyViolationTrend) + tests/unit/observability/test_dashboard.py
- R8 satisfied by: agentguard/observability/dashboard.py (MetricsDashboard.to_json, to_markdown) + tests/unit/observability/test_dashboard.py

## Changelog
- 2026-04-19: Initial draft, reverse-engineered from v1.0.0 codebase.
