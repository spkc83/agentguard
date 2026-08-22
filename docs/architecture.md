# Architecture Index

The authoritative architecture reference lives at the repository root:
[`ARCHITECTURE.md`](../ARCHITECTURE.md). It covers the four-layer runtime
(Security Runtime → Compliance Engine → Domain Toolkit → Integrations +
Observability), the threat model, and deployment patterns.

ARCHITECTURE.md describes both what is implemented and what the design targets.
Only Layer 1's identity, RBAC, audit, and circuit breaker are on the governed
call path today; the compliance engine, formal verifier, HITL, PII masking,
sandbox backends, and the finance toolkit are offline tools. Unbuilt items are
listed in that document's
[Roadmap section](../ARCHITECTURE.md#roadmap--not-yet-implemented), and the gap
analysis behind them is
[`plans/guardrails-realignment.md`](plans/guardrails-realignment.md).

Related references:

- [`DECISIONS.md`](../DECISIONS.md) — Architectural Decision Records.
  Key entries: ADR-001 (append-only audit), ADR-002 (deny-override RBAC),
  ADR-004 (log-first / act-second), ADR-017 (protocol-based adapters),
  ADR-018 (OTel NoOp fallback), ADR-020 (shared governance pipeline),
  ADR-021 (library-mode OTel policy).
- [`AGENTS.md`](../AGENTS.md) — agent-oriented component guide.
- [`api/`](api/index.md) — module-by-module API overview.
- [`compliance/`](compliance/index.md) — policy frameworks reference.

This `docs/` tree is intentionally thin: it links into the root-level
references rather than duplicating their contents.
