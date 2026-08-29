# Architecture Index

The authoritative architecture reference lives at the repository root:
[`ARCHITECTURE.md`](../ARCHITECTURE.md). It covers the four-layer runtime
(Security Runtime → Compliance Engine → Domain Toolkit → Integrations +
Observability), the threat model, and deployment patterns.

ARCHITECTURE.md describes both what is implemented and what the design targets.
`agentguard.guardrails.GovernanceKernel` owns the live call path: immutable
payload transforms, derived-resource RBAC, staged policy and content guardrails,
rate limiting, circuit breaking, lifecycle audit evidence, authenticated protected
PRE_TOOL/PRE_MESSAGE resume for registered executors, protected guardrail-triggered
POST_TOOL/POST_MESSAGE and ON_DECISION delivery without executor replay, opt-in signed-marker
recovery, checkpoint-attested unknown-window classification for claimed protected continuations,
and OTel telemetry. `GovernedCreditAgent`
uses this lifecycle for fixed score, approve/review/decline, override, and completed-notice actions;
its signed evidence retains only opaque linked references and allowlisted metadata. Formal
verification, sandbox execution, and finance reporting/model-analysis tools remain offline. Unbuilt items are listed in that document's
[Roadmap section](../ARCHITECTURE.md#roadmap--not-yet-implemented), and the gap
analysis behind them is
[`plans/guardrails-realignment.md`](plans/guardrails-realignment.md).

Phase 3.5c wires authenticated workloads into an explicit secure kernel mode. Authentication and
its signed evidence precede request/tracer/registry/executor observation; roles come only from one
authoritative snapshot. Protected schema-v2 continuations bind the exact signed authentication
event plus registry and credential epochs; linked decision continuations use schema v3 to add
opaque subject/relationship references and allowlisted redacted evidence while retaining that
binding. Resume rechecks current status/epoch/RBAC without the original credential. First-party adapters now acquire a fresh credential inside a bound kernel
caller before deferred request construction. Optional `agentguard[auth]` supplies the concrete
offline RS256 verifier with exact issuer/audience/subject semantics, pinned local keys, bounded
rotation overlap, strict expiry/skew, atomic replay prevention, and emergency revocation.
Legacy kernel construction remains available only as a self-asserted compatibility path.

The reconciliation boundary uses stable execution, POST-claim, and delivery audit markers.
Journaled execution failures drain a durable delivery denial; successful outcomes claim
post-processing and commit a marker before callbacks. Verified markers prevent POST replay after a
valid signed journal rollback. Only absence-based unknown-window classification requires an
externally checkpointed audit head.

Credit decisions returned as immutable `DecisionPayload` objects run at `ON_DECISION` inside the
same kernel lifecycle. A review approval delivers only the sealed review result; it is not a credit
approval. A final underwriter result requires a separately authorized `decision:override` linked to
the escalation. Trusted exact model/version evidence, reason/attribution integrity, notice
completeness, PII-free redacted evidence, and verified unresolved-decline correlation are described
in ADR-041.

Related references:

- [`DECISIONS.md`](../DECISIONS.md) — Architectural Decision Records.
  Key entries: ADR-001 (append-only audit), ADR-002 (deny-override RBAC),
  ADR-004 (log-first / act-second), ADR-017 (protocol-based adapters),
  ADR-018 (OTel NoOp fallback), ADR-020 (original shared pipeline),
  ADR-021 (library-mode OTel policy), ADR-024 (guardrail contracts),
  ADR-025/026 (attestable audit evidence), ADR-027 (governance kernel),
  ADR-028 (signed shadow-mode evidence), ADR-029 (atomic policy reload), ADR-030–033
  (protected HITL and reconciliation), ADR-034–037 (authentication/registry/kernel/adapters), and
  ADR-038 (offline pinned RS256 workload verification), ADR-039 (truthful credit attribution and
  versioned adverse-action reasons), ADR-040 (typed credit notices and deterministic rendering),
  and ADR-041 (governed credit decisions and PII-free issuance evidence).
- [`AGENTS.md`](../AGENTS.md) — agent-oriented component guide.
- [`api/`](api/index.md) — module-by-module API overview.
- [`compliance/`](compliance/index.md) — policy frameworks reference.

This `docs/` tree is intentionally thin: it links into the root-level
references rather than duplicating their contents.
