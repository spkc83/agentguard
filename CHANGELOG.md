# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) once it
reaches 1.0.

## [Unreleased]

### Changed (2026-08-30) — BREAKING for `AGENTGUARD_AUDIT_KEYS`

- Every epoch declared in `AGENTGUARD_AUDIT_KEYS` must now carry an
  `activation_certificate`: an HMAC (domain
  `agentguard.audit.key-epoch-activation.v1`) over the epoch's key id, key
  fingerprint, activation sequence, and predecessor key id, keyed by the
  predecessor epoch's key — the primary key for the first declared epoch, then
  each declared epoch in activation order. Environment write access alone can
  no longer introduce a signing epoch; a declaration is proof of authorization
  by the previous key holder. Certificates are minted with
  `AuditKeyring.mint_activation_certificate(...)` or `agentguard audit
  mint-epoch-certificate` (new key read from `AGENTGUARD_NEW_AUDIT_KEY`).
  Two-field declarations without a certificate now fail closed at startup.
  The `adopt_declared_epochs=True` restart gate is retained as defense in
  depth.

### Added (limitation closures, 2026-08-29)

- Added a governed path for non-model adverse-action reasons. A `policy_rule` reason is produced
  only by evaluating a versioned `CreditPolicyBundle` over the complete declared fact schema for
  one application/decision, and `PolicyReasonIntegrityGuardrail` recomputes every finding and
  requires exact equality (`AA.POLICY_REASON_UNBOUND` on any drift). A `human_review` reason binds
  a `ReviewJudgment` to the completed review lineage that `decision:override` verifies, with codes
  drawn only from the versioned ECOA registry (`AA.REVIEW_REASON_UNBOUND` otherwise). Mixed
  notices order principal reasons by decision chronology (policy overlay, then model, then human
  review) with deterministic within-basis ordering, and `prepare_notice_record` accepts only the
  selection recomputed from the decision's own bases. A decline with no truthful basis stays
  denied. Deferred: a pre-scoring decline (no model score at all) still cannot be represented
  because the signed evidence shapes require a model reference.
- Made the audit rollback anchor operational: `agentguard audit export-checkpoint` writes the
  signed head checkpoint (refusing to overwrite a newer witness), `agentguard audit verify
  --trusted-checkpoint` fails closed when the local head is behind the witness, and
  `AuditCollectorServer` accepts a `trusted_checkpoint_path` outside its state directory that it
  refuses to start behind and atomically re-exports after each checkpoint. Rollback of the whole
  evidence set is now detectable exactly as far as the witness is replicated off-host; that trust
  boundary is documented in ARCHITECTURE.md.
- Made audit key rotation survivable: `AuditKeyring.from_environment` also reads
  `AGENTGUARD_AUDIT_KEYS` (JSON epochs beyond the primary key, each under the same ≥32-byte
  floor), and `rotate_key` on an environment-sourced keyring refuses up front
  (`AuditKeyRotationRefusedError`) unless the epoch is already declared there — the one-way door
  that previously bricked the collector on restart can no longer be walked through by accident.
- Bounded the evidence caches without weakening any verification or dedup guarantee: the
  collector's event index retains hashes rather than whole events beyond a configurable window,
  `PolicyEngine` accepts `max_retained_generations` (default unlimited) with dropped generations
  still producing explicit unknown-provenance failures, and the escalation store and execution
  journal gain operator-invoked `prune_terminal` that deletes only terminal records older than a
  cutoff.
- The wheel-contents test now asserts every runtime subpackage ships, and the CrewAI `_resource`
  rejection guard is tested on the sync bridge that native `BaseTool.run()` delegates to.

### Added (governed runtime)

- Added canonical `agentguard.testing` synthetic benchmark helpers. Statistical records now use
  dependency-ordered income/property/loan/LTV and obligation/DTI generation with a seeded private
  RNG, explicit artificial `bias` controls, and a documented approval predicate. Optional WGAN-GP
  now validates rectangular finite inputs, persists an immutable standard scaler, seeds training
  and generation, supports `generate(1)` in evaluation mode, inverse-scales outputs, and bounds
  named credit features. The old finance-synthetic modules remain compatibility re-exports.
- Added strict immutable model-validation policies, backtests, same-sample challengers,
  aggregate-only fairness-monitor bindings, owned finding lifecycles, and revisioned exact-model
  reports. Complete reports can cross a domain-separated HMAC envelope and rollback-aware report
  source into the existing live provenance guardrail; incomplete, tampered, future, stale,
  mismatched, or broken-lineage evidence fails closed. Historical SR 11-7 structure is documented
  as provenance only because SR 26-2 superseded it in April 2026.
- Added deeply immutable tool/message payload contracts and fail-closed input, pre-execution,
  post-execution, and delivery guardrail stages.
- Added immutable `DecisionPayload` results and the `ON_DECISION` stage to the full kernel
  lifecycle. Decision results retain authentication, derived-resource RBAC, staged policy,
  limits/breakers, audit-first admission, shadow evaluation, protected post-execution resume, and
  one delivery terminal instead of bypassing governance through a domain-only path.
- Added staged policy enforcement on real tool arguments/results. The 35 shipped rules are
  explicitly migrated to 14 pre-tool, 1 post-tool, and 20 attestation rules with 3 deny,
  3 escalate, and 29 warn effects.
- Added generic recursive PII masking, secret egress denial, optional output-schema validation,
  and a process-wide structlog scrubber. The finance PII compatibility API now delegates to the
  generic implementation.
- Added invocation lifecycle evidence (`admission`, `execution_completed`, delivery terminals),
  stable reason codes, redacted payload evidence, and canonical payload digests.
- Added `GovernanceKernel` guardrail modes. Shadow mode runs every content guardrail, signs
  observed decisions, and applies neither blocks nor transforms while RBAC, policy, limits,
  breakers, audit, and native execution remain active.
- Added replay, dashboard, and compliance-report shadow views with lifecycle deduplication,
  conflicting-duplicate detection, and strict separation from enforced outcome/policy metrics.
- Added recursively immutable, content-addressed `PolicyBundle` generations with explicit atomic
  reload, last-known-good rollback, per-invocation kernel pinning, and in-memory historical
  provenance resolution for compliance reports.
- Added a metadata-only durable escalation foundation: HMAC-authenticated POSIX file state,
  opaque token verifiers, exact durable TTL expiry, schema-v5 signed HITL request evidence, and
  deduplicated lifecycle dashboard counters.
- Added authenticated restart-safe PRE_TOOL/PRE_MESSAGE resume for application-registered
  executors: injected approver authentication and AEAD protection contracts, opaque protected
  continuations, prepare→audit→commit decisions/expiry, exact policy/chain/executor binding,
  stable one-time claims, current-identity RBAC rechecks, exact pinned-bundle execution,
  multi-approval cursor resume, and delivery terminals for denial, expiry, revocation, and ordinary
  pre-admission cancellation.
- Added protected restart-safe POST_TOOL/POST_MESSAGE delivery for guardrail-triggered
  escalations. Completed results, post cursors, full chain identity, and exact policy snapshots are
  sealed without executor authority; approval uses a distinct one-time delivery claim and resumes
  only remaining post-processing. Concurrent resume, denial, expiry, RBAC revocation, cancellation,
  and sequential post approvals never replay the executor. Policy-only post cursors remain
  metadata-only.
- Added an opt-in signed `ExecutionJournal` for claimed protected continuations. Successful PRE
  results are AEAD-protected before post-processing; stable admission, execution-completion, and
  delivery event IDs make append-then-raise retries converge. Authenticated `hitl:reconcile`
  principals can checkpoint-classify missing lifecycle boundaries with `assess_execution`, resume
  a known protected result through `reconcile_known_outcome` without executor replay, or close an
  unknown/POST-claimed `IN_DOUBT` window through deny-only `deny_in_doubt`. The APIs accept no
  caller result, payload, executor, executor ID, or disposition.
- Journaled executor exception, repeated cancellation, and invalid-output paths now drain one
  stable invocation delivery denial before persisting `DELIVERY_DENIED`. Successful outcomes
  atomically claim post-processing before a stable `execution_post_processing_claimed` or
  `execution_reconciliation_resumed` audit marker; POST callbacks start only after the marker.
  Verified claim/delivery markers detect older valid signed journal state, prevent POST replay,
  and either converge the journal or fail closed. Positive marker checks do not require an external
  checkpoint; absence-based `IN_DOUBT` classification does.
- Added mechanism-neutral async `AgentAuthenticator`, `AgentCredentialProvider`, and distinct
  `ControlPlaneAuthenticator` contracts. Frozen credential-derived agent principals intentionally
  contain no roles/capabilities, and safe authentication errors expose only canonical `AUTH.*`
  classifications.
- Added frozen, secret-free `AuthenticationEvidence` for verified/rejected authentication
  lifecycle events. Rejected evidence forbids trusted identity, validity timestamps, registry
  metadata, roles, raw credentials, and provider diagnostics; rejected-event producers reserve the
  `__unauthenticated__` outer actor boundary.
- Added optional `agentguard[auth]` with a concrete, offline `JwtAgentAuthenticator`. It accepts
  only RS256, exact issuer/audience and required canonical claims; uses immutable operator-pinned
  local JWK snapshots with compare-and-swap rotation and bounded overlap; offloads bounded crypto
  verification; and atomically enforces one-use `jti` plus issuer/key/subject/token/digest
  revocation. Network JWKS discovery and token-supplied key sources are rejected. Pluggable key-set
  and credential-use protocols support shared production backends; bundled implementations are
  process-local and bounded.
- Added deeply immutable authoritative registry records and snapshots with active/revoked state,
  registry-owned roles, and monotonic global revision, record revision, and credential epoch.
- Added the distinct authenticated `AgentRegistryControlPlane`. Exact action and per-role
  capabilities govern typed registration, role replacement, credential rotation, and revocation
  commands through an idempotent `PREPARED` → `AUDITED` → `COMMITTED`/`CONFLICTED` ledger.
- Added `InMemoryAuthoritativeAgentRegistry` and `SignedFileAuthoritativeAgentRegistry`. The signed
  store uses canonical registry-domain HMAC state, hardened owner-only POSIX files, atomic durable
  replacement, a chained local checkpoint, a required trusted checkpoint outside the registry
  directory, a persisted verified-audit head, and restart recovery for prepared/audited operations.
  Both registries independently re-read their configured audit sink before commit. The signed store
  rejects non-checkpoint-capable audit sinks and performs blocking file transactions outside the
  event loop.
- Added schema-v8 `RegistryMutationEvidence` for authorized and rejected administrative decisions.
  It binds the authenticated administrator, capability/request digests, proposed state transitions,
  and canonical `REGISTRY.*` failures without persisting credentials or raw verifier diagnostics.
- Added explicit scorecard and coefficient attribution contracts for credit models. They require
  declared direction, exact finite transformed-feature schemas, versioned model/reference
  provenance, and emit only strictly positive adverse contributions.
- Added a versioned adverse-action reason registry with AgentGuard-local Appendix C-derived codes,
  explicit per-model feature bindings, deterministic same-reason aggregation, and stable
  fail-closed `AA.*` classifications.
- Added an independent FCRA bureau-factor registry and immutable score-factor selection. It
  preserves model/reference provenance and applies the four-factor rule plus the fifth
  inquiry-factor exception without imposing that factor's display position.
- Added frozen denial, standalone/combined counteroffer, counteroffer-nonacceptance,
  incomplete-application, and withdrawal artifacts. They distinguish actual written notification
  from oral counteroffers, enforce 30/60/90-day boundaries, preserve model/policy/HITL reason
  origin, and discriminate consumer-report, non-CRA third-party, and affiliate source regimes.
- Added deterministic versioned C-1/C-3/C-4/C-6 and standalone-counteroffer render profiles with
  canonical UTF-8/LF output and a SHA-256 digest over the exact rendered bytes.
- Added the pure, versioned `CreditDecisionPolicy` and the `GovernedCreditAgent` runtime boundary.
  The governed surface uses fixed independently authorizable actions: `model:score`,
  `decision:approve`, `decision:review`, `decision:decline`, `decision:override`, and
  `notice:issue`.
- Added mixed action-scoped `ON_DECISION` controls for typed decision evidence, protected-feature
  schemas, review-band escalation, exact trusted model/version validation and fairness evidence,
  decline reason taxonomy, attribution integrity, and completed-notice completeness. The terminal
  decision stage is non-transformable so a later control cannot invalidate its authorized action
  or safe-evidence envelope.
- Added domain-separated opaque application/decision/model/policy/notice references and explicit
  PII-free audit projections. PD values, model inputs, feature names/values, contributions, reason
  text, applicant data, and notice bodies are excluded from signed redacted payload evidence.
  Protected linked decision continuations use schema v3 while exact schema-v1/v2 bytes remain
  unchanged.
- Added `find_unresolved_declines`, which requires checkpoint-attestable audit evidence and emits
  immutable `AA.UNRESOLVED_DECLINE` findings for delivered declines without a later, timely,
  exactly linked delivered notice. It includes final decline overrides, refuses false-clean
  malformed linkage, and accepts a notice only with signed enforced completeness-control evidence.
- Added checkpoint-attested review-lineage validation for `decision:override`; the admitted
  executor requires one ordered requested/approved/resumed/delivered review-band lifecycle and
  exact decision/application/model/policy lineage.
- Added immutable per-decision fairness observations and explicit disadvantaged/reference group
  analysis. Reports now use denominator-specific `INSUFFICIENT_DATA`, the named four-fifths
  ratio, pooled two-proportion z or exact Fisher evidence, a Katz risk-ratio interval, decline-as-
  positive equalized odds, fixed-width PD deciles, and count-weighted calibration ECE.
- Added `FairnessMonitor`, which binds one exact target model ID/version, requires checkpoint-
  attestable audit history, accepts only exact delivered approve/decline/override evidence with the
  enforced decision-evidence control, joins
  protected attributes, PD, and matured outcomes through a trusted private provider, and returns
  aggregate metrics plus audit-head provenance. Missing, malformed, duplicate, or failed joins
  prevent a clean `ModelFairnessStatus.PASSED` result; private rows and opaque references are not
  returned or audited.

### Changed (audit compatibility and limits)

- Historical unversioned/v1, Phase 1 v2, Phase 2 v3, guardrail v4, HITL v5, reconciliation v6,
  and authentication v7 records verify with their exact frozen canonical forms. Schema v8 signs
  typed `RegistryMutationEvidence` without rewriting exact v1-v7 history.
- Phase 3.5c adds an explicit secure kernel mode. It authenticates before request, tracer, registry,
  or executor observation; derives roles only from an authoritative snapshot; signs secret-free
  success/rejection evidence; and binds protected schema-v2 continuations to the exact signed event,
  registry identity/revision, record revision, and credential epoch. Resume rechecks current status,
  epoch, and RBAC without requiring the original credential. Legacy schema-v1 continuation bytes
  remain exact.
- Phase 3.5d binds every first-party adapter to exactly one legacy ID or secure credential provider.
  Secure providers run once per call inside the kernel before deferred request construction, tracing,
  registry/resolver access, or executor lookup. Provider failure/absence emits one signed,
  secret-free `AUTH.PROVIDER_FAILURE` event; returned credentials remain coroutine-local. The
  deprecated `run_governed` shim is explicitly legacy-only.
- Phase 3.5e selects patched `PyJWT[crypto]>=2.13,<3` as an optional local verification dependency.
  JWT roles are ignored, replay has the distinct `AUTH.CREDENTIAL_REPLAYED` classification, and
  verification/storage/provider failures expose only safe fail-closed authentication errors.
- The pre-1.0 adverse-action API now accepts a provenance-bearing `AttributionResult`; ambiguous
  `feature_importances` dictionaries and unversioned `reason_map` inputs were removed. Credit
  decisions no longer fabricate proxy feature importances. ECOA principal reasons have no claimed
  statutory four-item cap; any configured presentation limit is institution policy, while FCRA
  score-factor limits remain a separate notice concern.
- Removed the pre-1.0 `CreditDecisioningAgent`/`CreditDecisionConfig` compatibility surface; use
  pure `CreditDecisionPolicy` plus kernel-backed `GovernedCreditAgent`.
  New callers use `CreditDecisionPolicy` for pure banding and `GovernedCreditAgent` for live
  emission. Generic HITL approval of a review result authorizes only delivery of that sealed review;
  final credit disposition requires a separate `decision:override` authorization linked to the
  escalation.
- `notice:issue` now means recording an already-completed written-notification event. Rendering a
  notice does not claim transport or delivery, and the governed event retains only typed metadata
  and the exact rendered-body digest. Future notification times fail closed, and the private
  prepared-notice store is not mutated before admission and RBAC.
- The pre-1.0 directionless fairness dictionary API is retired. New analysis requires explicit
  disadvantaged/reference names and typed final observations; the separately named aggregate
  compatibility method cannot claim calibration without observation-level PD/outcome data.
- `AgentRegistry` and `FileBackedRegistry` are explicitly compatibility-only. Their registration is
  self-asserted and their file format is unsigned; new security-sensitive code should use the
  authoritative registry/control-plane boundary.
- Dashboard aggregation is invocation-aware and conservatively resolves duplicate terminal events.
- Resource/action resolvers run after input transforms with bounded synchronous capacity and timeouts.
- Rate limiting is keyed by `(agent_id, action)`; circuit-breaker admission reserves a single
  half-open probe and writes the admission event atomically before execution.

### Added (evidence integrity)

- Froze exact v1 and Phase 1 v2 HMAC serializers and introduced a domain-separated, canonical
  schema v3 for new writes. New envelopes sign `sequence`, `key_id`, `chain_id`, opaque subject
  references, typed links, chain mode, and a canonical policy-bundle digest.
- Added a frozen schema-v4 serializer that also signs typed per-stage guardrail evaluations;
  v1-v3 records reject those fields as unsigned extensions.
- File audit writes now allocate their predecessor and sequence inside one directory-wide
  `flock` transaction, append with `O_APPEND`, handle partial writes, `fsync` the log, and
  atomically advance a separately domain-signed head checkpoint.
- Added lock-consistent verified snapshots. Compliance reports refuse empty, legacy-only,
  unsupported-backend, tampered, truncated, or checkpoint-invalid evidence rather than emitting
  a clean attestation. A clean report also requires an out-of-band trusted head and exact policy
  bundle provenance. Replay can filter by opaque subject and linked evidence references.
- Added bounded, timed policy-handler execution, lifecycle evidence on executor cancellation,
  registry-backed runtime reason codes, and direct policy-rule reason codes.
- Steady-state file appends now read only the signed checkpoint and durable tail instead of
  reparsing the full audit history. Reports deduplicate lifecycle-repeated runtime policy results.

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
  metacharacters, `<>`, control characters, absolute paths and any `..` segment (checked on the
  raw value, before normalisation, so a namespace prefix can never be eaten) are rejected.
- `GovernedA2AClient` canonicalises the target once and uses it for both the action and the
  resource, so a cased target cannot evade an action-scoped deny rule.
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
