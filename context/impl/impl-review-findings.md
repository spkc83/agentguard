---
created: "2026-04-24"
last_edited: "2026-04-24"
---

# Review Findings

Build site: context/plans/build-site.md.

Findings from `/ck:check` post-loop review (2026-04-24). Verdict: **APPROVE** (0 P0 / 0 P1 / 2 P2 / 2 P3). Findings are test-fidelity polish — none block release.

| Finding | Severity | File | Status | Fix |
|---------|----------|------|--------|-----|
| F-001: AST z3-import test exercises wrong modules (engine/hitl instead of formal_verifier/z3_models); also `ast.walk` walks into method bodies, so it's stricter than the lazy-import contract. | P2 | tests/unit/compliance/test_formal_verifier.py:152-180 | NEW | Restrict to `tree.body` top-level imports; include `formal_verifier` and `z3_models` modules; update docstring. |
| F-002: `test_concurrent_failures_open_breaker_exactly_once` only asserts terminal state; doesn't verify one-shot OPEN log emission as the name promises. | P2 | tests/unit/core/test_circuit_breaker.py:120-128 | NEW | Capture logs via `structlog.testing.capture_logs()` and assert exactly one `circuit_breaker_opened` entry, OR rename to `..._without_corruption`. |
| F-003: `test_circular_inheritance_warns` mutates global structlog config without teardown (pre-existing, not introduced by this loop). | P3 | tests/unit/core/test_rbac.py:210-234 | NEW | Snapshot/restore via fixture or use `structlog.testing.capture_logs()`. |
| F-004: Module file opened without context manager in AST structural test. | P3 | tests/unit/compliance/test_formal_verifier.py:166 | NEW | Use `Path(mod.__file__).read_text()`. |

## Out of scope (deferred to Docker-CI / optional installs)

These are kit PARTIALs flagged by the surveyor; not new findings, already documented in `dead-ends.md` or kit Source Traceability.

- security-runtime R6 (T-019/T-020/T-021): Docker socket permission denied; rerun on Docker-enabled CI runner.
- compliance-engine R6 C4: import-error directive lives in docstring rather than wrapped error. Optional polish; mirror the `_import_torch()` pattern in `formal_verifier.py`.
- finance-credit-risk R7: `wgan_gp.py` 0% coverage because torch is in `[finance]` extra and not installed in dev env. Optional smoke test guarded by `pytest.importorskip("torch")`.
