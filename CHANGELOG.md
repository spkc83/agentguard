# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) once it
reaches 1.0.

## [Unreleased]

### Changed (CI)
- CI now runs `pip-audit --strict` against the installed dependency set (`audit-dependencies` job).
- New `integration` job runs `tests/integration` and `tests/red_team` (Docker sandbox escape tests) on
  every push/PR; previously these tests never executed in automation. `tests/integration/test_core_e2e.py`
  is now marked `integration` so it is selected by `-m "integration or red_team"`.
- Release workflow generates a CycloneDX SBOM with syft and uploads it as a build artifact.

### Changed (governance — BREAKING)
- **RBAC resource is now derived by the integrator, never supplied by the agent (ADR-023).**
  `GovernedLangGraphToolNode` and `GovernedMcpClient` take a required keyword `resources=`
  mapping (tool name → static string or sync/async resolver callable); `GovernedCrewAITool`
  and `GovernedAdkTool` take a required keyword `resource=`. The call-time `resource`
  parameter is removed from `ainvoke`, `call_tool` and `run_async`; CrewAI `_resource=` raises
  `TypeError`. `run_governed` accepts `resource: str | None` and denies (audited, sentinel
  `<unresolved>`) before consulting RBAC when the resource cannot be derived.
- Derived resources are canonicalised (`canonicalize_resource`) before RBAC: fnmatch
  metacharacters, `<>`, control characters, absolute paths and `..` traversal are rejected.
- `Permission.matches` uses `fnmatch.fnmatchcase`; resources match case-insensitively,
  actions case-sensitively. A case variant such as `Admin/keys` can no longer evade
  `deny admin/*`.
- An unregistered LangGraph tool name is an audited denial instead of a `KeyError`.

### Fixed
- `AdverseActionNotice.decision_date`, `ModelValidationReport` timestamp, `HitlEscalation.timestamp`
  and `ApprovalDecision.timestamp` were evaluated once at import time; they are now per-instance.
- `AdverseActionNotice.reasons` is a `tuple` — the frozen model could previously be mutated in place.
- `scripts/generate_datasets.py` derived per-dataset seeds from `hash(name)` and was therefore not
  deterministic across processes; it now uses `zlib.crc32`.
- `python -m agentguard.cli` now runs the CLI.
- Unknown policy `check.type` values raised no error and evaluated as *passed*; they now fail at
  load time with `PolicyLoadError` (ADR-022). Custom check types are registered via
  `PolicyEngine(extra_check_handlers=...)`.
- `agentguard verify rbac|policy` print an install hint and exit 1 when the `verify` extra is absent.

### Changed (documentation)
- FINOS-aligned rules renamed from `FINOS-AIGF-NNN` to AgentGuard-local `AG-FINOS-NNN`; the bundle
  is described as an unofficial mapping (15 controls), not "46 risks mapped".
- `docs/api/index.md` rewritten against the real public API; a test now imports every documented
  symbol and asserts phantom CLI commands (`verify workflow`, `verify model`, `sandbox run`) are not
  documented.
- `ARCHITECTURE.md` gained a "Roadmap — not yet implemented" section; unbuilt features (Wasm
  sandbox, S3/GCS/Postgres audit backends, sidecar/gateway, Vault, seccomp, monotonicity proofs)
  are no longer described in the present tense.


## [0.9.0] - 2026-08-22

### Changed

- **Version reset from 1.0.0 to 0.9.0** to accurately reflect Alpha status
  (`Development Status :: 3 - Alpha` was already declared in classifiers but
  contradicted by the `1.0.0` version and "Production Release" README framing).
- **README status table restructured** into three sections — *Enforced at
  runtime*, *Offline analysis tools*, and *Wrappers awaiting framework
  validation* — instead of a single undifferentiated "Done" table, to make
  clear which components sit on the governed call path today versus which
  are analysis/reporting tools invoked out-of-band. See
  `docs/plans/guardrails-realignment.md` for the full gap analysis.
- **Dependency cleanup**: `httpx` and `anyio` removed from core dependencies;
  not imported by `agentguard`. `z3-solver` moved from a core dependency to
  the new `verify` extra — the formal verifier already lazily imports z3
  (ADR-013), so it should not be required for every install.
- `sandbox` extra: removed `wasmtime` (unused; Docker is the only implemented
  sandbox backend).
- `finance` extra: removed `scikit-learn`, `numpy`, `presidio-analyzer`,
  `presidio-anonymizer`, `aif360`, and `fairlearn` — none of these are
  imported anywhere under `agentguard/`. `pandas` and `torch` are retained
  (used by `scripts/generate_datasets.py` and the WGAN-GP synthetic data
  generator, respectively).

### Added

- `LICENSE` — MIT, previously declared in `pyproject.toml` but not shipped.
- `agentguard/py.typed` — PEP 561 marker so type checkers treat the installed
  package as typed.
- `SECURITY.md` — vulnerability disclosure policy and scope.
- `CHANGELOG.md` — this file.
