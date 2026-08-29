---
created: "2026-04-24"
last_edited: "2026-08-26"
---

# Review Findings

Build site: context/plans/build-site.md.

Findings from `/ck:check` post-loop review (2026-04-24). Historical verdict: **APPROVE** (0 P0 / 0 P1 / 2 P2 / 2 P3). Findings are test-fidelity polish — none blocked that release.

Status is evaluated against the checked-in planning baseline `d35f436`. The shared working tree now contains each fix, all acceptance commands passed freshly on 2026-08-26, and the evidence is recorded in the Phase 1 execution log. The fixes remain uncommitted but are closed as implementation findings.

| Finding | Severity | Exact file | Baseline status | Current working-tree state |
|---|---|---|---|---|
| F-001: The lazy-z3 AST test inspects `agentguard.compliance.engine` and `agentguard.compliance.hitl`, not the optional modules that can import z3. It also walks nested function bodies with `ast.walk`, which incorrectly forbids the lazy imports the contract permits. | P2 | `tests/unit/compliance/test_formal_verifier.py` (`test_compliance_engine_imports_without_z3`) | OPEN | CLOSED — acceptance passed 2026-08-26 |
| F-002: `test_concurrent_failures_open_breaker_exactly_once` promises a one-shot transition but asserts only terminal OPEN state and the presence of a failure. It does not prove exactly one `circuit_breaker_opened` emission under concurrency. | P2 | `tests/unit/core/test_circuit_breaker.py` (`TestCircuitBreakerConcurrent.test_concurrent_failures_open_breaker_exactly_once`) | OPEN | CLOSED — acceptance passed 2026-08-26 |
| F-003: `test_circular_inheritance_warns` replaces process-global structlog configuration and does not restore it, so test order can alter unrelated log assertions. This defect predates the Phase 1 work. | P3 | `tests/unit/core/test_rbac.py` (`TestRBACEngine.test_circular_inheritance_warns`) | OPEN | CLOSED — both file orders passed 2026-08-26 |
| F-004: The AST structural test opens each module source with bare `open(...)` and leaves resource lifetime to garbage collection. | P3 | `tests/unit/compliance/test_formal_verifier.py` (same lazy-z3 test as F-001) | OPEN | CLOSED — acceptance passed 2026-08-26 |

## Required fixes and acceptance

### F-001 — Test the actual lazy-import boundary

- Replace the inspected modules with `agentguard.compliance.formal_verifier` and `agentguard.compliance.z3_models`.
- Parse each module and inspect only `tree.body` for top-level `ast.Import` and `ast.ImportFrom` nodes. Nested imports are allowed by ADR-013.
- Rename and document the test so it states the precise contract: neither formal-verification module imports `z3` at module scope.
- Acceptance: `pytest --no-cov -q tests/unit/compliance/test_formal_verifier.py` passes, and temporarily adding a top-level `import z3` to either target makes the structural assertion fail.

### F-002 — Prove one OPEN transition

- Capture structured logs with `structlog.testing.capture_logs()` around the concurrent failure burst.
- Keep the state and exception assertions, then assert exactly one captured entry has `event == "circuit_breaker_opened"`.
- Do not satisfy the finding by weakening the test name; Phase 1.6 relies on one atomic OPEN transition.
- Acceptance: `pytest --no-cov -q tests/unit/core/test_circuit_breaker.py` passes repeatedly, including the concurrency test, and the captured OPEN-event count is exactly one.

### F-003 — Isolate structlog capture

- Replace global `structlog.configure(...)` mutation and `capsys` inspection with `structlog.testing.capture_logs()` scoped to the engine construction.
- Assert that at least one captured event is `circular_role_inheritance`.
- Acceptance: `pytest --no-cov -q tests/unit/core/test_rbac.py tests/unit/core/test_circuit_breaker.py` passes in both file orders without global logging leakage.

### F-004 — Read AST sources with managed lifetime

- Read source with `Path(mod.__file__).read_text(encoding="utf-8")`; do not use a bare file handle.
- Acceptance: the F-001 targeted test passes and `rg -n 'open\(' tests/unit/compliance/test_formal_verifier.py` finds no source-read call in the lazy-import test.

## Out of scope (deferred to Docker-CI / optional installs)

These are kit PARTIALs flagged by the surveyor; not new findings, already documented in `dead-ends.md` or kit Source Traceability.

- security-runtime R6 (T-019/T-020/T-021): Docker socket permission denied; rerun on Docker-enabled CI runner.
- compliance-engine R6 C4: import-error directive lives in docstring rather than wrapped error. Optional polish; mirror the `_import_torch()` pattern in `formal_verifier.py`.
- finance-credit-risk R7: `wgan_gp.py` 0% coverage because torch is in `[finance]` extra and not installed in dev env. Optional smoke test guarded by `pytest.importorskip("torch")`.

## Phase 1/2 completion review — 2026-08-26

An independent latest-tree review found five release-blocking issues and three evidence follow-ups.
All eight are closed in the current working tree:

- v1/v2 records reject populated fields outside their frozen signed schemas;
- policy and async guardrail execution are bounded and timed, with timeout-specific denial evidence;
- admitted executor cancellation writes `execution_completed` before cancellation propagates;
- runtime reason codes use the ADR-024 registry and failed policies emit their rule IDs directly;
- reports require exact current-bundle provenance for persisted policy results;
- an out-of-band trusted checkpoint detects paired local log/checkpoint rollback;
- steady-state file append reads only the signed checkpoint and durable tail; and
- repeated lifecycle copies of runtime policy results are counted once per invocation/rule.

Acceptance evidence: 578 unit tests passed with 93.18% coverage; Ruff, strict mypy across 44 source
files, and `git diff --check` passed. The six Docker integration/red-team tests remain environment-
blocked by Docker socket permissions and are assigned to Docker-enabled CI.
