# Compliance Frameworks Reference

AgentGuard ships three schema-v2 YAML policy bundles under
[`agentguard/compliance/policies/`](../../agentguard/compliance/policies/): OWASP Agentic AI,
15 AgentGuard-local controls informed by FINOS AIGF v2.0, and EU AI Act high-risk controls.
Policy files are versioned source and are loaded by `PolicyEngine`; unknown check types and missing
schema-v2 runtime fields fail at startup.

## Runtime behavior

Every schema-v2 rule declares `stage`, `applies_to`, and `on_fail`. The built-in bundle contains
35 rules: 14 `pre_tool`, one `post_tool`, and 20 `attestation`; effects are three `deny`, three
`escalate`, and 29 `warn`. `GovernanceKernel` evaluates runtime stages against the
transformed tool arguments or actual result before execution or delivery. Handler work runs in a
bounded executor with a timeout; exception, timeout, or saturation denies fail-closed.

Runtime events carry the exact canonical policy-bundle digest and failed policies use their stable
rule IDs directly as reason codes. Severity does not imply enforcement: only explicit `on_fail`
does. The attestation-stage rules remain evidence checks and should not be interpreted as proof of
regulatory conformity.

Policy loading is copy-on-write. `PolicyEngine.snapshot()` returns the active recursively
immutable `PolicyBundle`; `await PolicyEngine.reload()` serializes reload requests, then reads and
validates all configured files off the event loop and atomically publishes the complete candidate. Reload is explicit—AgentGuard
does not watch files or poll. Invalid candidates and duplicate rule IDs raise `PolicyLoadError`
without replacing the last-known-good bundle. A governed invocation pins one bundle before any
asynchronous work and uses it for every policy stage and signed lifecycle event, so an in-flight
call cannot mix generations. All generations activated by the current engine instance remain
available to `ComplianceReporter`; an unresolvable stamped generation is refused rather than
attested. Durable policy archives across process restarts remain an application responsibility.

Content guardrails may run in `shadow` mode without weakening these policy rules, RBAC, rate
limits, circuit breakers, or audit. Schema-v4 events sign each observed guardrail ID, version,
stage, effect, reason codes, duration, and `enforced=False` marker. Shadow transforms never replace
the payload sent to the resolver, executor, or caller. Replay, dashboard, and compliance output
label these records as observed-not-enforced and keep them separate from actual policy and outcome
metrics.

## Durable escalation and protected resume

`GovernanceKernel` optionally accepts an `EscalationStore`. All durable requests persist only a
SHA-256 token verifier and HMAC-authenticated control state with exact TTL, `flock`, atomic
replacement, and owner-only permissions. Legacy/caller-supplied executor requests remain
metadata-only.

For `guarded_registered_tool_call`, a resumable PRE_TOOL/PRE_MESSAGE guardrail escalation can also
store an opaque envelope produced by the mandatory injected `ContinuationProtector`. The protected
plaintext binds the invocation, immutable payload, original permission context, exact policy
snapshot, chain cursor/fingerprint, and complete trusted executor reference. `decide_escalation`
derives approver identity and capabilities from `ApproverAuthenticator`, signs the idempotent
decision event before activation, and persists no credential or raw reason. `resume_tool_call`
accepts only escalation ID and token. It validates the complete chain and multi-approval cursor,
pins the exact restored policy bundle, resolves the executor and current identity, rechecks RBAC,
then records a stable one-time claim. Denial and expiry write their HITL transition plus one
`delivery_denied`; revoked RBAC and ordinary pre-admission cancellation also close delivery. Policy
or executor changes fail closed before claim. INPUT resume remains out of scope.

For an enforced, guardrail-triggered POST_TOOL/POST_MESSAGE escalation, the kernel can seal the
completed `ToolResultPayload`, authenticated post cursor, complete chain identity, exact policy
snapshot, and prior evidence in a `PostExecutionContinuation`. This continuation deliberately has
no executor reference. Approval validates the protected state and current RBAC before a distinct
delivery claim, resumes only the remaining post guardrails, and commits one stable
`delivery_completed` or `delivery_denied` event before the corresponding store terminal. A later
post escalation creates a protected child request and hands off the parent without re-executing the
tool. Policy-only post escalations remain metadata-only.

For claimed protected continuations, applications may inject an `ExecutionJournal` with its own
signing key and an application-provided authenticated-encryption boundary. The journal is
opt-in. It records signed claim/admission/completion state and seals an exact successful result
before post-processing; it contains no executor reference and exposes no raw result in public
metadata. The kernel uses stable `invocation:{id}:admission`,
`invocation:{id}:execution-completed`, and `invocation:{id}:delivery` audit IDs so retries converge
on one lifecycle boundary.

Reconciliation credentials are authenticated by `ApproverAuthenticator` and must carry
`hitl:reconcile`. `assess_execution` requires `read_verified(require_checkpoint=True)` before it
treats an absent audit event as evidence. It can classify `claimed_without_terminal`,
`admission_without_completion`, or `completion_without_protected_result` as `IN_DOUBT`. Schema-v6
`ReconciliationEvidence` signs the escalation/claim/reconciliation IDs, classification and state,
credential-derived reconciler, hashed reason, attested audit head, and journal revision/digest;
v1-v5 signed forms remain unchanged.

`reconcile_known_outcome` opens an already protected result, revalidates current RBAC and the exact
policy/chain bindings, and resumes post-processing without resolving or invoking an executor.
Unknown execution windows and already-claimed POST processing are deny-only through
`deny_in_doubt`; no API accepts a replacement result, payload, executor, executor ID, or
disposition. This protocol does not cover legacy caller-supplied executors, policy-only
escalations, INPUT escalations, or general exactly-once replay.

Journaled executor exception, cancellation, and invalid-output paths write one stable
`invocation:{id}:delivery` denial and then persist `DELIVERY_DENIED`. Cancellation handling drains
that audit/journal terminal even when cancellation repeats before propagating `CancelledError`.
Successful execution instead atomically enters `POST_PROCESSING_CLAIMED` before the kernel writes
the stable `execution_post_processing_claimed` marker; known-outcome reconciliation uses
`execution_reconciliation_resumed` as its authenticated marker. POST policy and guardrail callbacks
start only after the applicable marker commits. If the process stops after claim but before the
marker, recovery classifies the window `IN_DOUBT` and never starts the callbacks.

Verified stable claim and delivery markers are also rollback evidence. If an older, still-valid
signed journal record is restored, a claim marker prevents POST replay, while a delivery marker
converges the journal terminal or rejects an incompatible state. These positive signed-marker
checks do not require an external checkpoint. A checkpoint is required when the absence of a
lifecycle event is itself used to classify an unknown window.

## Built-in bundles

- `owasp_agentic.yaml`: ten rules covering prompt injection, tool misuse, supply-chain and related
  agentic risks. IDs use `OWASP-AGENT-NN`.
- `finos_aigf_v2.yaml`: 15 AgentGuard-local `AG-FINOS-NNN` controls informed by FINOS AIGF v2.0.
  This is not an official mapping to FINOS `AIR-*` identifiers.
- `eu_ai_act.yaml`: ten controls referencing high-risk-system obligations relevant to credit
  scoring. These controls help collect evidence; legal conformity still requires domain review.

## Reporting and evidence integrity

`ComplianceReporter` accepts an `AppendOnlyAuditLog`, reads one lock-consistent snapshot, verifies
the HMAC chain, sequence, local signed checkpoint, an out-of-band trusted checkpoint, and exact
policy provenance before producing a clean report. Empty, legacy-only, unsupported, unanchored,
tampered, truncated, or unknown-bundle evidence is refused. Repeated lifecycle copies of the same
runtime rule result are counted once per invocation. Shadow findings are deduplicated by
invocation, stage, guardrail ID, and guardrail version; conflicting duplicates are surfaced instead
of silently changing an enforced compliance result. Every distinct conflicting effect and reason
is retained, and would-effect totals count unique invocations rather than lifecycle copies.

```bash
agentguard policy validate --policy-dir agentguard/compliance/policies
agentguard policy report --log-dir ./audit-logs \
  --trusted-checkpoint ./trusted/audit-head.json --output-format markdown
```

The local `audit-head.json` shares the log's rollback boundary. Persist the checkpoint returned by
`AppendOnlyAuditLog.export_checkpoint()` separately, or use `AuditCollectorServer` with its signed
`CollectorState` in a separate failure domain. Applications then use the keyless
`SigningAuditBackend`; the collector owns sequence allocation, persistence, signing, immutable key
epochs, recovery, and verified snapshot pagination.

Collector mode is fail-closed and bounded: owner-only UDS paths, peer-UID checks, framed request
limits/timeouts, one collector lock per log directory, fixed verified snapshots, and server/client
event and byte caps. It protects key custody, ordering, and rollback detection only while the
collector state cannot be rolled back with the local log. It does not establish event truth,
protect against a same-UID compromise of both failure domains, or turn symmetric HMAC evidence
into a publicly verifiable signature.

## Formal verification

`FormalVerifier` exposes RBAC reachability and policy consistency through Z3 (optional `verify`
extra), plus Python graph-search workflow safety. The CLI exposes:

```bash
agentguard verify rbac --config policy.yaml
agentguard verify policy --policy-dir agentguard/compliance/policies
```

Workflow safety is Python-API only. The current encodings are static-analysis aids: RBAC checks do
not model all runtime glob/inheritance semantics, and policy consistency abstracts rule conditions.
See ADR-005, ADR-016, ADR-024, ADR-025, ADR-028, and ADR-029 in
[`DECISIONS.md`](../../DECISIONS.md).
