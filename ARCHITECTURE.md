# AgentGuard — Architecture Reference

## System Overview

AgentGuard is a **governance middleware** — it does not orchestrate agents; it governs them. Every agent action (tool call, inter-agent message, external API call) routed through an AgentGuard adapter passes through its runtime before execution. The architecture is a four-layer stack that can be adopted incrementally: a team can start with Layer 1 (security) alone and add compliance, domain toolkits, and observability over time.

> **Read this first.** This document describes both what is implemented and what the
> architecture is designed to support. `GovernanceKernel` owns the governed call
> path: immutable payload transforms, derived action/resource resolution, RBAC,
> staged policy and content guardrails, rate limiting, circuit breaking, lifecycle
> audit evidence, authenticated protected HITL resumption and reconciliation,
> `ON_DECISION` credit controls, and OpenTelemetry instrumentation. Formal
> verification, sandbox execution, and the remaining domain analysis tools stay
> offline. Items that do not exist yet are
> collected in [Roadmap — not yet implemented](#roadmap--not-yet-implemented) and
> flagged inline as **(roadmap)**. The gap analysis behind those flags is
> [`docs/plans/guardrails-realignment.md`](docs/plans/guardrails-realignment.md).

> **Agent authentication boundary.** Secure `GovernanceKernel` mode authenticates opaque workload
> credentials before observing request data, tracing, registry state, or executor identifiers and
> derives roles only from the authoritative registry. Protected schema-v2 continuations retain the
> signed authentication/registry binding across HITL resume. Adapters obtain fresh credentials
> exactly once per call through a kernel-bound caller before deferred request
> construction. Optional `agentguard[auth]` supplies a concrete offline RS256 verifier with pinned
> keys, strict claims, replay prevention, bounded rotation overlap, and emergency revocation.
> Legacy kernel construction remains an explicitly self-asserted compatibility path.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Agent Application                    │
│          (LangGraph / CrewAI / Google ADK / Raw Python)         │
└───────────────────────────┬─────────────────────────────────────┘
                            │  tool calls / agent messages
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AgentGuard Runtime Middleware                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 1: Security Runtime                                │   │
│  │  Identity → RBAC → Limits → Circuit Breaker → Audit      │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 2: Compliance Engine                               │   │
│  │  Runtime Policy → Offline HITL/Verification/Reports       │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 3: Domain Toolkit (Finance / Healthcare / Gov)     │   │
│  │  Credit Risk → Adverse Action → Synthetic Data → PII     │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Layer 4: Observability                                   │   │
│  │  OTel Traces → Replay Debugger → Cost/Metrics Dashboard  │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────┬─────────────────────────────────────┘
                            │  governed execution
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│               Tools / Services / External APIs                   │
│        (databases, file systems, web, internal APIs)             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Security Runtime

The security runtime is the load-bearing foundation. Every other layer depends on it. It is designed around the principle: **log first, act second, fail closed**.

### Execution Flow

`agentguard.guardrails.GovernanceKernel` owns this flow. The five integration
adapters call `guarded_tool_call`; `agentguard.integrations._pipeline.run_governed`
is a deprecated compatibility shim that constructs a kernel and delegates to it.

```
Agent calls tool/message adapter
       │
       ▼
1. resolve_identity; build immutable typed payload
       │
       ▼
2. run input transforms; derive and canonicalize action/resource
       │
       ├── invalid/unresolved → audit denial → raise PermissionDeniedError
       │
       ▼
3. RBAC → staged pre-policy → pre-tool/message guardrails
       │
       ├── deny/escalate → audit terminal decision → raise
       │
       ▼
4. rate-limit; enter circuit-breaker admission boundary
       │
       ├── rejected → audit rejection → raise
       ▼
5. write invocation:{id}:admission → execute → write invocation:{id}:execution-completed
       │
       ├── executor error/cancellation → write execution_completed(error) → re-raise
       │
       ▼
6. post-policy → post-tool/message or on-decision guardrails → write invocation:{id}:delivery
       │
       └── delivery_completed | delivery_denied | delivery_escalated
```

The guardrail chain has `enforce`, `shadow`, and `off` modes. Only content
guardrail behavior changes: shadow evaluates the full chain and signs each
would-be effect without blocking or applying transforms, while off skips the
chain. Identity, RBAC, policy, rate limiting, circuit breaking, audit, and the
execution lifecycle remain active in all three modes. Schema-v4 events attach
input/pre evaluations once to the admission or pre-admission terminal and post
evaluations once to the delivery terminal; `execution_completed` carries none.
If cancellation arrives after execution, the kernel commits a `delivery_denied`
terminal with `DELIVERY.CANCELLED` before re-raising it.

The circuit breaker remains a kernel boundary rather than a guardrail. Its
`before_execute` callback writes `admission` only after the breaker grants the slot
and immediately before execution, including the single HALF_OPEN probe. An admitted
executor always produces `execution_completed`; successful execution is not proof of
delivery until a delivery terminal is committed.

**Step 5 executes an in-process callable by default.** When a guardrail emits a sandbox
obligation, the governed PRE_TOOL boundary instead routes the authorized transformed argv through
the hardened Docker backend; host subprocess backends are rejected. Standalone sandbox helpers
remain available for offline use.

### Agent Authentication Contracts

`agentguard.core.authentication` defines three async, runtime-checkable protocols without choosing
a credential mechanism: `AgentCredentialProvider`, `AgentAuthenticator`, and the distinct
`ControlPlaneAuthenticator`. Authentication returns a frozen `AuthenticatedAgentPrincipal` with
the trusted `agent_id`, method, authority, SHA-256 credential digest, and UTC validity timestamps.
It intentionally has no roles or capabilities. `ControlPlanePrincipal` uses a separate principal
identifier and immutable capabilities so future registry administration cannot reuse the agent
trust domain.

`AuthenticationFailure` supplies the reserved machine-stable classifications
`AUTH.CREDENTIAL_MISSING`, `AUTH.CREDENTIAL_INVALID`, `AUTH.CREDENTIAL_EXPIRED`,
`AUTH.CREDENTIAL_NOT_YET_VALID`, `AUTH.CREDENTIAL_REPLAYED`, `AUTH.CREDENTIAL_REVOKED`, `AUTH.PRINCIPAL_MISMATCH`,
`AUTH.IDENTITY_INACTIVE`, `AUTH.PROVIDER_FAILURE`, and `AUTH.INTERNAL_ERROR`.
`AuthenticationError` exposes only one of those classifications; it has no raw-error or credential
detail channel.

Schema v7 adds frozen, typed `AuthenticationEvidence` for `authentication_succeeded` and
`authentication_rejected` events. Verified evidence contains only credential-derived identity,
validity, digest, and optional registry revision. Rejected evidence contains a failure
classification and digest but forbids trusted identity fields, credential validity timestamps,
and registry metadata. Rejected-event producers reserve `__unauthenticated__` as the outer audit
actor; they must not copy a claimed actor ID into signed evidence. The schema-v7 HMAC serializer is
domain-separated from v1-v6, and verification keeps each frozen v1-v6 canonical serializer intact.

`agentguard.core.jwt_authentication` implements those contracts for one exact RS256 workload trust
domain. `JwtAgentAuthenticator` accepts only bounded compact JWTs with exact issuer/audience,
canonical subject and token ID, integer short-lived time claims, fixed local `kid` selection, and
operator-pinned public RSA JWKs. It rejects token-provided key material and URLs, performs no OIDC
discovery or request-path network I/O, and runs bounded cryptographic verification in worker
threads. `CredentialUseStore` atomically enforces one-use token IDs and issuer/key/subject/token/
digest revocation; `JwtKeySetProvider` supplies immutable snapshots. Their bundled implementations
are bounded and process-local, so multi-process deployments must inject shared atomic backends.
Replay backends own their serialized, nondecreasing trusted clock; the consume protocol accepts no
caller-supplied current time. Key-overlap duration uses a monotonic clock and drops prior keys if
that clock's contract is violated.
Key/subject revocation must be paired with authoritative-registry credential rotation or identity
revocation when protected continuations must also be invalidated.

### Authoritative Registry and Administrative Control Plane

`agentguard.core.registry` defines the read boundary. An `AgentRegistryRecord` is deeply immutable
and contains registry-owned name, roles, metadata, active/revoked status, credential epoch, record
revision, and UTC lifecycle timestamps. A full `AgentRegistrySnapshot` binds those records to one
monotonic global registry revision. Registration starts at record revision and credential epoch 1;
every committed mutation advances the global and target record revisions, role replacement retains
the credential epoch, and credential rotation or revocation advances it. Revoked records remain
available to administrative reads but cannot resolve as active identities.

`AgentRegistryControlPlane` is distinct from the workload-agent trust domain. Each register,
replace-role, credential-rotation, or revocation call accepts an opaque credential and invokes the
injected `ControlPlaneAuthenticator` before observing registry state. `RoleGrantPolicy` requires an
exact action capability plus exact, separately configured grant/revoke capabilities for every role
change; wildcard capabilities are invalid. The control plane prepares an immutable proposed state,
writes and reads back the exact signed authorization event, and only then commits. Its operation
ledger moves `PREPARED` → `AUDITED` → `COMMITTED` or `CONFLICTED`. Stable operation IDs make an
identical principal/request retry idempotent and reject reuse with different authority or content.
Cancellation is drained through the audit-and-commit boundary before it propagates.

`InMemoryAuthoritativeAgentRegistry` provides process-local state. The local POSIX
`SignedFileAuthoritativeAgentRegistry` persists the full record and operation ledger as canonical
JSON under a separate `agentguard.registry.state.v1` HMAC domain. A chained local checkpoint handles
atomic crash windows; the required `trusted_checkpoint_path`, which must be outside the registry
directory, supplies the monotonic restart anchor. It requires owner-controlled 0700 directories and
0600 owner-only regular state, checkpoint, and lock files with one hard link; uses `O_NOFOLLOW`,
`flock`, unique temporary files, file `fsync`, atomic replacement, and directory `fsync`; and runs
those blocking transactions in worker threads. Both registry implementations re-read their own
configured audit sink before commit. Opening the signed store additionally requires a
checkpoint-capable audit sink, verifies the persisted audit-head prefix, cross-binds every
post-audit operation to its exact signed event, and recovers one-step state/checkpoint and
`PREPARED`/`AUDITED` crash windows. Rolling back both registry-directory files is rejected while the
trusted checkpoint remains current. Coordinated rollback of the registry directory, trusted
checkpoint failure domain, and audit/checkpoint files remains outside this local boundary; this is
not a multi-host coordinator.

`AgentRegistry` and `FileBackedRegistry` in `core.identity` remain compatibility-only. They accept
self-asserted registration, do not authenticate administration, and persist unsigned JSON. Only an
explicitly legacy kernel uses that resolver; secure construction requires the authoritative
registry and authenticator together and never falls back.

### RBAC Model

```
Role
 ├── name: str
 ├── permissions: list[Permission]
 └── inherited_roles: list[Role]     # role hierarchy

Permission
 ├── action: str                      # "tool:*", "tool:web_search", "data:read:pii"
 ├── resource_pattern: str            # glob or regex
 ├── conditions: list[Condition]      # time-based, context-based
 └── effect: Literal["allow", "deny"]

AgentIdentity
 ├── agent_id: str                    # stable UUID assigned at registration
 ├── name: str
 ├── roles: list[Role]
 └── metadata: dict                   # framework, version, owner, environment
```

Permission resolution uses **deny-override**: if any matching permission has `effect="deny"`, the action is denied regardless of other permissions. This mirrors AWS IAM's explicit-deny model.

### Sandbox Design

Two execution backends are available through the `SandboxBackend` protocol. Both take a
`list[str]` command and return a `SandboxResult`; only the hardened Docker backend is accepted for
governed sandbox obligations. The in-process callable remains the default when no obligation is
emitted.

**`DockerSandboxBackend`:**
- Each execution runs in a fresh container from a caller-supplied image
- Applies `network_disabled`, read-only non-root execution, dropped capabilities,
  no-new-privileges, quotas, daemon log rotation, and bounded streaming capture
- Execution timeout, default 30 seconds
- Per-call volume mounts are intentionally unsupported; the governed command is the authorized
  transformed argv.

**`NoOpSandboxBackend`:**
- Direct `asyncio.create_subprocess_exec` with timeout enforcement, no isolation
- Development and testing only; never `shell=True`

### Audit Log

Append-only, tamper-evident log using HMAC chain:

```
AuditEvent N:  { ...event data..., prev_hash: HMAC(event N-1), hash: HMAC(event N) }
```

Applications depend on the `AuditLog` protocol. `AppendOnlyAuditLog` provides local
versioned HMAC evidence through `FileAuditBackend`; `SigningAuditBackend` is a keyless client
for `AuditCollectorServer` over an owner-only Unix socket. Remote cloud and database
backends remain roadmap items; there is no `agentguard[postgres]` extra.

The audit log is never the first place a write fails. If the log write fails, the action is blocked.

Schema v3 sequence numbers and signed head checkpoints detect tail truncation when a
trusted checkpoint is retained outside the log/checkpoint failure domain. Collector
mode separates signing-key custody and ordering from the agent process. Symmetric HMAC
still does not prove event truth or provide public third-party verification, and a
same-UID compromise of both failure domains remains outside the collector boundary.

#### Rollback witness trust boundary

`audit-head.json` lives inside the audit directory, and `AuditCollectorServer`'s signed
state lives beside it on the same host. An attacker with root can restore both together,
so neither proves the log was not rewound. The only artifact that can prove it is a
**checkpoint replicated off-host**: `agentguard audit export-checkpoint` writes the signed
head, and `agentguard audit verify --trusted-checkpoint` (or
`AppendOnlyAuditLog(trusted_checkpoint=...)`) refuses a log that no longer reaches it,
raising `AuditRollbackDetectedError`. A collector configured with
`trusted_checkpoint_path=` — which must resolve outside both the audit and collector-state
directories — refuses to start behind that witness and advances it after every committed
checkpoint, so replicating the file off-host is a file-copy problem rather than a code one.

What this detects: in-place edits and reordering (HMAC chain), tail truncation
(sequence + local checkpoint), and a rollback to any head older than the last exported
witness, including one that restores the audit directory and collector state together.

What it does **not** detect: a rollback to a state *newer* than the last witness that
reached off-host storage — the window between exports is unwitnessed; a same-host copy of
the witness, which shares the attacker's reach and proves nothing; forged event content
signed with a compromised key; and event truth, since HMAC binds who wrote a record, not
whether the record describes reality. Export frequency sets the size of the undetectable
window, and the witness must be replicated to storage the audit host cannot write.

#### Signing-key epoch continuity

`AGENTGUARD_AUDIT_KEY` supplies epoch 1. `AGENTGUARD_AUDIT_KEYS` optionally declares later
epochs as a JSON object mapping `key_id` to
`{"key": ..., "activation_sequence": ..., "activation_certificate": ...}`,
subject to the same >=32-byte floor. This declaration is what makes rotation survivable:
key bytes exist only in the environment, so an epoch the environment does not declare
cannot be rebuilt after a restart and every event signed under it becomes unverifiable.
`AuditCollectorServer.rotate_key` therefore refuses to activate an undeclared epoch on an
environment-sourced keyring (`AuditKeyRotationRefusedError`) rather than opening that
one-way door; a caller-injected keyring owns its own continuity and still rotates in place.

Every declared epoch is **authenticated by an activation certificate**: an HMAC
(domain `agentguard.audit.key-epoch-activation.v1`) over the epoch's binding —
key ID, key *fingerprint* (never the key itself), activation sequence, and
predecessor key ID — keyed by the PREDECESSOR epoch's key. The first declared
epoch is certified by the primary key; each later epoch by the one before it in
activation order, so the chain is sequential and a link cannot be skipped. An
epoch declaration is therefore proof of authorization by the previous key
holder, not mere presence in the environment: an attacker with environment
write access but no existing signing key cannot mint a certificate, and a
stolen certificate cannot be rebound to a different key, sequence, or
predecessor. Mint certificates with
`AuditKeyring.mint_activation_certificate(...)` or
`agentguard audit mint-epoch-certificate` (the new key is read from
`AGENTGUARD_NEW_AUDIT_KEY`, never from an argument).

Residual boundary — what the certificate does NOT defend. `AGENTGUARD_AUDIT_KEY`
itself carries no certificate, so custody of the *primary* key remains an
environment-protection problem. The certificate chain stops environment write
access from escalating into new signing epochs; it does not stop an attacker who
supplies their own primary key. Against an **existing** log that swap is caught —
substituting the primary breaks the chain from event 1 and verification raises
`AuditTamperDetectedError`. Against a **fresh** log it is not: an attacker who
sets `AGENTGUARD_AUDIT_KEY` to a key of their choosing and writes a new log from
sequence 1 produces a chain that verifies clean under their key. Only the
off-host trusted checkpoint / collector signed state (whose `signing_key_id` and
head the attacker cannot reproduce) detects a re-rooted fresh log — replicate the
checkpoint witness, do not rely on chain self-verification alone. Likewise,
possession of any key that is or was a chain predecessor, combined with dropping
later `AGENTGUARD_AUDIT_KEYS` declarations, can still mint an epoch; the
collector's signed epoch state (the strict-suffix prefix check) contains this,
the certificate does not. Defense in depth on top of the certificate: a restart
that sees newly declared epochs still refuses to start unless the operator passes
`adopt_declared_epochs=True`, and adoption commits them into signed state only as
a strict suffix extension whose activations fall after the committed head, so no
already-signed event can be reinterpreted.

New writes use schema v8. Its domain-separated canonical envelope signs typed
`RegistryMutationEvidence` in addition to the v4 guardrail, v5 HITL, v6 reconciliation, and v7
authentication extensions. Authorized registry evidence binds the authenticated administrator,
capability and request digests, proposed revisions, record digests, credential epochs, and prepare
time; rejected evidence signs the canonical `REGISTRY.*` reason without asserting prepared state.
Verification retains exact schema-specific v1-v7 serializers, so the new evidence does not rewrite
or reinterpret historical signed bytes. Registry evidence on a pre-v8 record is rejected as an
unsigned extension.

---

## Layer 2: Compliance Engine

The compliance engine evaluates a set of YAML-defined policy rules against `AuditEvent`
records. It is separate from RBAC (which is about *who can do what*) — compliance is
about *whether what was done meets regulatory standards*.

Schema-v2 `pre_tool`, `post_tool`, `pre_message`, and `post_message` rules run in the
kernel against the transformed input or actual result. Each rule has an explicit
`allow | deny | escalate | warn` effect; severity does not determine enforcement.
Attestation-stage rules remain offline evidence checks used by the CLI and
`ComplianceReporter`. When an `EscalationStore` is configured, the runtime persists
metadata-only pending state and a token verifier before signing schema-v5
`escalation_requested` evidence and blocking the call. Protected registered PRE calls and
guardrail-triggered POST delivery support authenticated approval/resumption; an optional execution
journal adds signed-marker recovery and checkpoint-attested unknown-window classification for
claimed protected continuations.
See [`docs/compliance/index.md`](docs/compliance/index.md) for the exact bundle split.

`PolicyEngine` publishes recursively immutable, SHA-256-addressed `PolicyBundle`
snapshots. `await engine.reload()` serializes reload requests, rebuilds and validates
configured YAML off the event loop, then swaps the complete bundle under a short lock. There is no implicit file
watcher. Invalid YAML, unknown checks, or duplicate rule IDs leave the last-known-good
bundle active. The kernel pins one snapshot before its first await, so pre- and
post-execution policy stages and every signed lifecycle event use one version even when
a reload completes during execution. Activated generations remain resolvable in memory
for reporting; evidence from an unknown generation is non-attestable.

### Policy Rule Schema

```yaml
# Example: OWASP Agentic AI - Prompt Injection check
- id: OWASP-AGENT-01
  name: Prompt Injection Detection
  severity: critical
  description: >
    Detects user-supplied content being injected into system prompts
    or tool arguments that could override agent instructions.
  check:
    type: content_scan
    targets: [tool_args, agent_messages]
    patterns:
      - "ignore previous instructions"
      - "disregard your system prompt"
      - "you are now"
  remediation: >
    Sanitize user inputs before interpolation into prompts.
    Use structured tool schemas with strict validation.
  references:
    - https://owasp.org/www-project-top-10-for-large-language-model-applications/
```

### Built-in Policy Sets

**OWASP Top 10 for Agentic AI** (`policies/owasp_agentic.yaml`):
- OWASP-AGENT-01: Prompt Injection
- OWASP-AGENT-02: Sensitive Data Exposure
- OWASP-AGENT-03: Supply Chain Attacks (tool poisoning)
- OWASP-AGENT-04: Privilege Escalation
- OWASP-AGENT-05: Excessive Agency (scope creep)
- OWASP-AGENT-06: Overreliance / Hallucination in Action
- OWASP-AGENT-07: Data Poisoning
- OWASP-AGENT-08: Insecure Plugins / Tools
- OWASP-AGENT-09: Insecure Output Handling
- OWASP-AGENT-10: Model Denial of Service

**FINOS AIGF v2.0-aligned controls** (`policies/finos_aigf_v2.yaml`):
- 15 controls informed by FINOS AIGF v2.0, spanning Governance, Risk Management,
  Technology, and Operations themes
- Rule IDs are AgentGuard-local (`AG-FINOS-NNN`); this is **not** an official mapping
  to the FINOS risk registry (`AIR-*` IDs). An official mapping requires domain review.
- Several controls retain historical SR 11-7 model-risk themes; SR 26-2 superseded that guidance
  in April 2026, and the shipped controls are not regulatory attestations

**EU AI Act** (`policies/eu_ai_act.yaml`):
- Annex III High-Risk AI: credit scoring (Article 6)
- Article 9: Risk management system requirements
- Article 10: Data governance requirements
- Article 13: Transparency and information provision
- Article 14: Human oversight requirements
- Article 17: Quality management system

### Human-in-the-Loop Escalation

HITL implementation is **callback-based** — `HitlManager` builds a `HitlEscalation` and
hands it to a handler you supply, which returns an `ApprovalDecision`:

```python
from agentguard.compliance.hitl import ApprovalDecision, HitlEscalation, HitlManager


async def my_approval_handler(escalation: HitlEscalation) -> ApprovalDecision:
    # Send to Slack, PagerDuty, internal workflow system
    return ApprovalDecision(approved=True, approver_id="...", reason="...")


manager = HitlManager(handler=my_approval_handler)
```

`GovernanceKernel` can produce an escalation from an explicit policy effect or guardrail
decision. Without a store it preserves legacy non-resumable behavior. Metadata-only requests also
remain available for caller-supplied executors. For a trusted executor selected through
`guarded_registered_tool_call`, an enforced PRE_TOOL/PRE_MESSAGE guardrail escalation can reserve
state, seal the exact continuation through an injected `ContinuationProtector`, attach only the
opaque envelope, commit schema-v5 request evidence, and then return the verifier-backed token.

`decide_escalation` authenticates credentials through an injected `ApproverAuthenticator`; the
approver ID is never accepted from request data. It prepares the decision, writes stable
`approval_granted`/`approval_denied` evidence with `write_once`, and only then activates it.
`resume_tool_call` accepts no payload or executor. Before claim it verifies the complete
restart-resumable chain and cursor, restores and pins the exact protected policy snapshot, resolves
the complete executor reference and current agent, rechecks RBAC, and constructs evidence. The
atomic claim persists a stable claim ID/timestamp. Resume then continues after every guardrail whose
approval is authenticated in the cursor; a later unapproved escalation still stops and creates a
new request. Denial, expiry, revoked RBAC, and ordinary pre-admission cancellation each commit one
stable `delivery_denied`. Policy reload invalidates an outstanding continuation at validation and
can never substitute a different bundle during an accepted resume. INPUT resume needs a trusted
resolver registry. Guardrail-triggered POST_TOOL/POST_MESSAGE/ON_DECISION escalations instead seal
the completed `ToolResultPayload` or `DecisionPayload`, exact post cursor, full chain identity, and
pinned policy bundle. Approval claims delivery ownership and resumes only the remaining post chain;
it never resolves or invokes an executor. Linked decision continuations use schema v3 to retain
opaque subject/relationship references and an allowlisted redacted-evidence projection; exact
schema-v1/v2 serialization remains unchanged.

Applications can additionally inject an `ExecutionJournal` into `GovernanceKernel`. This opt-in,
process-safe store signs claim-state metadata and seals an exact successful executor outcome before
post-processing. Its reconciliation APIs authenticate the caller through the same
`ApproverAuthenticator` and require `hitl:reconcile`; none accepts a replacement result, payload,
executor, executor ID, or disposition. `assess_execution` classifies only from authenticated
store/journal state and `AuditLog.read_verified(require_checkpoint=True)`, so a missing event is
treated as evidence only when a committed checkpoint attests the audit head.

If the journal contains a protected result, `reconcile_known_outcome` completes any missing stable
`execution_completed` audit and resumes post-processing without resolving or invoking an executor.
If execution may have crossed the admission boundary without a protected result, or POST delivery
was already claimed without a terminal, the journal records `IN_DOUBT`; `deny_in_doubt` is the only
generic resolution and commits a stable delivery denial. This is crash-window convergence for
claimed protected PRE/POST continuations, not a general exactly-once execution facility. Legacy
caller-supplied executors, policy-only escalations, and INPUT escalations remain outside the
resumable/reconciliation protocol.

Journaled executor exceptions, cancellations, and invalid outputs close through the stable
`invocation:{id}:delivery` denial and durable `DELIVERY_DENIED` journal state. Repeated cancellation
is drained until both audit and journal terminals finish, then `CancelledError` propagates. For a
successful result, `POST_PROCESSING_CLAIMED` is atomically persisted before the kernel writes either
the stable `execution_post_processing_claimed` marker
(`invocation:{id}:post-processing-claimed`) or the authenticated
`execution_reconciliation_resumed` marker. Policy and guardrail callbacks do not begin before that
marker is committed. A crash between the journal claim and its marker therefore fails closed as
`IN_DOUBT` instead of replaying POST work.

Recovery also compares verified audit markers with signed journal state. A stable claim marker
prevents POST callbacks from running when an older but valid signed journal record is restored; a
stable delivery marker repairs a lagging/rolled-back journal terminal or reports a state conflict.
These positive marker checks use verified signed history and do not require an external checkpoint;
checkpoint-attested absence is required only when missing lifecycle evidence is used to classify an
unknown window.

### Formal Policy Verification (Z3 SMT Solver)

The formal verifier runs as a **static analysis tool** — it does not sit in the hot path of agent execution. It answers questions that runtime checks cannot: not "was this action allowed?" but "is it *possible* for any agent to reach this forbidden state given these policies?"

The Z3 SMT solver (Microsoft Research, pure Python via `z3-solver`) encodes AgentGuard concepts as logical formulas and checks satisfiability:

**Property 1 — RBAC Privilege Escalation:**
```
Prove: ∀ agent a, ∀ role sequence R₁...Rₙ:
  assigned_roles(a) = {R₁...Rₙ} ∧ none_explicitly_granted(a, P)
  → ¬reachable(a, permission P)
```
Encoded as bitvector arithmetic. If Z3 returns SAT, the counterexample is a concrete role sequence that achieves escalation.

**Property 2 — Policy Consistency:**
```
Prove: ∀ rules r₁, r₂ ∈ policy_set:
  ¬(conditions(r₁) ∧ conditions(r₂) → effect(r₁) = ALLOW ∧ effect(r₂) = DENY)
```
Detects contradictions and redundant rules before deployment.

**Property 3 — Workflow Safety:**
```
Check: ∀ execution paths P in agent graph G:
  (node_with_role(X) ∈ P) ∧ (tool_requiring(Y) ∈ P)
  → ∃ hitl_node ∈ P between them
```
`verify_workflow_safety` implements this as a **breadth-first search over the directed
graph** — it contains no Z3 at all (ADR-016). It is a graph check, not a proof, and it
is exposed through the Python API only; there is no `verify` CLI subcommand for it.

Properties 4 (credit model monotonicity) and 5 (adverse action determinism) are
**roadmap** — no monotonicity or determinism encoding exists in `agentguard/`.

All verification results produce a `VerificationResult` with status `sat | unsat | timeout | unknown`. When SAT (property violated), Z3's counterexample is translated back to human-readable AgentGuard terms. Verification timeout defaults to 10 seconds.

```bash
# CLI usage — these two subcommands are the whole `verify` group
agentguard verify rbac --config rbac_config.yaml
agentguard verify policy --policy-dir agentguard/compliance/policies
```

One soundness caveat applies to what ships today, tracked in Phase 5.2: the
policy-consistency encoding treats rule conditions as unconstrained strings, which
makes the satisfiability question close to vacuous — treat it as a lint-grade signal,
not a proof. The RBAC encoding no longer shares this caveat: it models `fnmatch`
subsumption as Z3 regexes and flattens role inheritance exactly as the runtime does,
with a differential test against `RBACEngine`.

---

## Layer 3: Credit Risk Domain Toolkit

### Governed Credit Decisions

`CreditDecisionPolicy` is a pure, synchronous, side-effect-free PD-band policy. Its frozen,
versioned configuration accepts only finite thresholds in `[0, 1]`, and its only outcomes are
`approve`, `review`, and `decline`. It does not log applicant data, fabricate model reasons, or
perform authorization.

`GovernedCreditAgent` is the runtime orchestration boundary. It sends every score, decision,
override, and notice record through `GovernanceKernel` with a fixed action:

```
trusted scorer ── model:score ──► CreditModelScore
                                      │
                                      ▼
                              CreditDecisionPolicy
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
        decision:approve      decision:review      decision:decline
                                      │                    │
                       HITL.REVIEW_BAND             notice:issue
                                      │                    │
                         sealed review delivery     completed-notice record
                                      │
                                      └── separate decision:override
```

The scorer callback runs under `model:score`. A returned `DecisionPayload` is preserved rather
than wrapped as a generic tool result, so policy and the mixed action-scoped guardrail chain run at
`ON_DECISION` inside the existing authentication, RBAC, limiter, breaker, audit, shadow, and
protected POST lifecycle. The decision controls validate the typed envelope, protected-feature
schema, exact trusted model/version evidence, decision band, decline reason taxonomy, and exact
attribution-to-reason mapping. Notice issuance has its own completeness control.

A review-band result escalates with `HITL.REVIEW_BAND`. Approval resumes only the sealed
post-execution review result and never reruns scoring or policy evaluation. That generic approval
is not an approval or decline of credit. A final underwriter outcome requires a separately
authorized `decision:override` call linked to the review escalation.

The kernel signs only allowlisted redacted evidence: domain-separated hashes of application,
decision, model, policy, and notice identifiers plus the minimum decision or notice metadata.
Applicant data, raw identifiers, PD values, feature names/values, contributions, reason text, and
notice bodies remain outside signed audit payloads and continuation metadata. A full decision is
available to in-process controls and, when escalated, sealed inside the protected continuation.
`notice:issue` records an already-completed written notification; rendering alone is not delivery. The offline
`find_unresolved_declines` correlator requires checkpoint-attestable audit history and reports a
delivered decline without a later, timely, exactly linked delivered notice as
`AA.UNRESOLVED_DECLINE`.

The current governed notice-recording slice accepts final decline candidates paired with a
`DeniedApplicationNotice` or `CounterofferNonAcceptanceNotice`. Phase 4.3's other artifact types
remain constructible/renderable but are not accepted by this recording boundary.

### Non-Model Principal Reasons

Regulation B requires a notice to state the decline's actual principal reasons, and not every
decline is a model decline. A candidate can therefore carry two further reason bases, each bound to
this application and decision so it cannot be lifted from another file:

- A `PolicyDenialSelection` is produced only by evaluating a versioned `CreditPolicyBundle` over the
  complete declared fact schema. It carries the facts it was computed from, so
  `PolicyReasonIntegrityGuardrail` — holding the same bundle — recomputes every finding and denies
  `AA.POLICY_REASON_UNBOUND` on any drift, including a denial that omits a rule which also fired. A
  bundle denial is a hard cutoff: it declines whatever band the PD falls in.
- A `ReviewJudgment` records a reviewer's own codes, drawn from the same versioned ECOA registry,
  against the escalation whose completed review lineage `verify_review_escalation` attests.
  `ReviewReasonIntegrityGuardrail` admits it only on a `decision:override` decline naming that
  application, decision, and taxonomy, and denies `AA.REVIEW_REASON_UNBOUND` otherwise; `override`
  additionally refuses a judgment citing an escalation other than the one being reviewed.

`PrincipalReasonSelection.from_decision_basis` composes a mixed notice in decision chronology —
policy rules, then model reasons, then reviewer judgment — preserving each producer's own
deterministic order within its basis and stating a code shared by two bases once, from the earlier
one. A decline with no basis at all still fails closed, and the notice control accepts only the
selection recomputed from the decision's own bases, so a human decline can never be signed by
restating the model's reasons.

**Roadmap — formal verification hook.** Model monotonicity and an adverse-action ordering proof
are not implemented. Runtime reason and notice controls enforce concrete evidence contracts, but
they do not constitute those formal proofs.

### Adverse Action Attribution and Notice Artifacts

ECOA and Regulation B require specific principal reasons for covered adverse actions. The current
Phase 4.1/4.2/4.3 boundary produces truthful reason evidence, complete typed credit-notice
artifacts, deterministic source-grounded text renderings, and governed PII-free issuance evidence.
It does not transport notices or place applicant data in the audit chain. The implementation:

- Derives strictly positive contributions from an explicit scorecard or coefficient reference and
  declared direction; it rejects ambiguous feature-importance dictionaries.
- Preserves model ID, model version, reference ID, method, and the complete evaluated feature
  schema, including favorable and zero factors.
- Requires an exact deployer feature binding to a versioned ECOA reason vocabulary and keeps
  deployer-supplied FCRA bureau factors in an independent registry and namespace.
- Consolidates features mapped to one reason and ranks them deterministically by summed adverse
  contribution and stable local code.
- Produces immutable denied, counteroffer, incomplete-application, and withdrawal artifacts with
  creditor/applicant details, fixed-version ECOA text, discriminated FCRA source regimes, and
  actual-notification timing.
- Renders eligible Appendix C C-1/C-3/C-4/C-6 or standalone-counteroffer profiles to canonical
  UTF-8/LF text and hashes the exact bytes. Rendering is deterministic and is not a delivery event.
- Records already-completed written notification through `notice:issue` with opaque application,
  decision, notice, and model links plus the exact body digest; it does not treat rendering as
  notification.

### Model Validation Evidence and Signed Live Handoff

AgentGuard models the conceptual-soundness, ongoing-monitoring, outcomes-analysis, effective-
challenge, and remediation themes associated with historical SR 11-7. The Federal Reserve's
[SR 26-2](https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm) superseded SR 11-7
on April 17, 2026, and [OCC Bulletin 2026-13](https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13.html)
rescinded OCC Bulletin 2011-12. The current guidance is principles-based and non-prescriptive;
neither generation mandates AgentGuard's report schema, Gini/AUC metrics, formula, or thresholds.
These are versioned project/institution policy choices, not a legal attestation.

```
Typed Validation Evidence
      │
      ├── exact-model backtest and optional same-sample challenger
      ├── aggregate-only private fairness-monitor binding
      ├── versioned thresholds and freshness policy
      └── immutable owned findings and closure evidence
                    ▼
       revisioned ModelValidationReport
                    ▼
       domain-separated HMAC envelope
                    ▼
 exact-model report source → verifying evidence provider
                    ▼
       ModelProvenanceGuardrail
```

The signer refuses incomplete compatibility reports. The verifying provider checks the canonical
report reference, signature, exact model/version, contiguous predecessor lineage, source identity,
internal status, feature schema, fairness binding, and validity window. Any source, verification,
future-date, expiry, or binding failure produces no authorizing evidence. The in-memory source is
process-local; deployments own durable rollback resistance and HMAC key custody/rotation.

### WGAN-GP Synthetic Benchmark Generator

The optional WGAN-GP helper lives under `agentguard.testing` because it generates benchmark data,
not production model inputs. It accepts a finite rectangular numeric matrix and persists a frozen
population standard scaler:

```
Generator G:  noise(z) → [FC → BN → LeakyReLU] × 3 → standardized numeric row
Critic D:     real/fake_application → [FC → LayerNorm → LeakyReLU] × 3 → scalar

Training:
  - Gradient penalty λ=10 (Gulrajani et al. 2017)
  - Optimizer: Adam(lr=1e-4, β1=0.5, β2=0.9)
  - Critic steps per generator step: 5
  - Explicit seeded CPU generators for reproducible training and sampling
  - Evaluation-mode generation with `no_grad`, scaler inversion, finite-value checks, and
    named feature bounds (FICO `[300, 850]`)
```

Output schema for the statistical `synthetic_credit_applications_v1` dataset:
```
application_id, fico_score, dti_ratio, ltv_ratio, annual_income,
employment_status, loan_purpose, loan_amount, term_months,
delinquency_24m, months_employed, credit_utilization,
num_open_accounts, synthetic_demographic_proxy [for fairness testing only],
is_default [label]
```

### Fairness Analysis Tools

- **Disparate impact (four-fifths rule):** explicitly named disadvantaged/reference approval-rate
  ratio, with a descriptive Katz interval and pooled z or exact Fisher comparison.
- **Equalized odds:** decline is the adverse prediction; matured default and non-default samples
  supply separately size-gated true-positive and false-positive rates.
- **Calibration:** fixed-width predicted-PD deciles expose group ECE without substituting one
  aggregate mean PD.
- **Rolling monitoring:** checkpoint-attested final decision evidence is joined to protected group,
  PD, and matured outcomes only through a trusted private provider; reports retain aggregates and
  audit-head provenance, not private rows.

The library never infers demographics. The bundled demo uses explicitly synthetic proxies; real
deployments must supply appropriately governed group observations and establish their own legal,
privacy, sampling, and monitoring policy.

### PII Detection and Masking

The framework-independent detector in `agentguard.guardrails.content` recursively
inspects immutable message, tool-call, and tool-result payloads. The default input
guardrail masks detected PII before authorization/execution evidence is built; the
default egress guardrails deny delivery of detected PII or secrets. The finance
`pii` module remains a compatibility/preset boundary over the same mechanics.

The generic pattern library covers:
- SSN: `\d{3}-\d{2}-\d{4}` and variants → masked as `XXX-XX-####` in logs
- Account numbers: 8–17 digit sequences in financial context → last 4 digits only
- Routing numbers: 9-digit ABA format → fully masked
- DOB: multiple date format patterns → masked
- Email and formatted/bare phone numbers → masked

Structured values are normalized and recursively scanned. Raw matches are excluded
from `PiiMatch`; evidence stores only redacted values plus a digest of the runtime
payload. FCRA/GLBA-specific categories remain finance-layer presets and require the
application to represent them in inspectable payload fields.

---

## Layer 4: Observability

Layer 4 provides three complementary surfaces that all read from the same
audit log so there is no second source of truth:

1. **`AgentTracer`** — OpenTelemetry spans emitted by the governance kernel
   (live, real-time).
2. **`ReplayDebugger`** — filter and reconstruct historical audit events
   into decision timelines (post-hoc, offline).
3. **`MetricsDashboard`** — aggregate KPIs (denial rate, latency
   percentiles, per-agent activity, policy violation trends).

### OpenTelemetry Semantic Conventions

AgentGuard defines custom span attributes under the `agentguard.*` namespace.

**Emitted today.** A governed call produces a root `agentguard.tool_call` span covering
identity resolution through terminal delivery. It includes:

```
agentguard.agent.id              string   The acting agent's id
agentguard.tool.action           string   Resolved tool/action (fallback before resolution)
agentguard.tool.resource         string   Derived canonical resource or <unresolved>
agentguard.result                string   allowed | denied | escalated | rejected | error
agentguard.denial.reason         string   Denial detail when denied
agentguard.reason_codes          string[] Stable escalation reason codes
```

The root contains `agentguard.rbac_check`, `agentguard.policy_eval`, and
`agentguard.tool_execution`; audit operations are `agentguard.audit_write` descendants at the
point each lifecycle event is committed. Current child attributes include:

```
agentguard.agent.name            string   Human-readable name
agentguard.permission.granted    bool
agentguard.permission.reason     string
agentguard.policy.stage          string
agentguard.policy.bundle_version string
agentguard.policy.result_count   int
agentguard.policy.violation_count int     Count of policy violations
agentguard.policy.critical       bool     Any critical violations
agentguard.audit.event_type      string
agentguard.audit.result          string
agentguard.audit.duration_ms     float
agentguard.invocation.id         string
```

Configured OTel meter providers also receive:

```
agentguard.governance.outcomes   Counter   Attribute: agentguard.result
agentguard.governance.duration   Histogram milliseconds by terminal result
```

Future domain instrumentation may add:

```
agentguard.sandbox.backend       string   "docker" | "none"
agentguard.sandbox.duration_ms   float
agentguard.cost.tokens           int      Total LLM tokens in this trace
agentguard.cost.usd              float    Estimated cost
agentguard.hitl.required         bool
agentguard.hitl.approved         bool
```

`AgentTracer` imports OTel lazily and never configures the host's global providers. Without an
explicit SDK `TracerProvider`/`MeterProvider`, spans and instruments are no-ops and `is_active` is
false. Integration adapters accept an optional tracer; tracing failures are best-effort and cannot
mask the governed call's original exception.

### Audit Replay

The replay debugger takes audit log events and produces a filtered decision
timeline:

```bash
agentguard observe replay --log-dir ./audit-logs --agent-id <uuid> --result denied
agentguard observe replay --log-dir ./audit-logs --start-time 2026-04-10T00:00:00+00:00
```

Each timeline entry reports the agent, action, resource, governance
decision, and warning flags (`denied`, `error`, `escalated`,
`policy_violation`). Events are sorted by timestamp and linked back to the
original `AuditEvent` for full inspection.

### Metrics Dashboard

`MetricsDashboard.compute(events)` aggregates KPIs over any slice of the
audit log. Output is available as a structured `DashboardMetrics` model,
JSON (via `to_json`), or Markdown table (via `to_markdown`):

```bash
agentguard observe dashboard --log-dir ./audit-logs --output-format markdown
agentguard observe summary --log-dir ./audit-logs
```

Latency percentiles (p50/p95/p99) use completed invocation lifecycles. The
kernel writes measured `duration_ms` on `execution_completed` and delivery
terminal events; configured OTel histograms provide the corresponding live
runtime signal.

---

## Protocol Integration Design

All framework adapters route tool calls through a shared
`agentguard.guardrails.GovernanceKernel`, so behavior is identical across
MCP, LangGraph, CrewAI, Google ADK, and A2A:

```
transform -> derive action/resource -> RBAC/policy/guardrails -> rate limit
          -> circuit breaker [atomic admission -> execute]
          -> execution_completed -> post-policy/guardrails -> delivery terminal
```

Adapters are thin: they build the typed payload and executor callable for their
framework, then delegate to the kernel. Constructors accept either a preconfigured
`kernel=` or the legacy dependency arguments; mixing the two configurations is
rejected. The private `_pipeline.run_governed` entry point remains only as a
deprecated compatibility shim.

### MCP Middleware (`GovernedMcpClient`)

Wraps an MCP `ClientSession` at the `call_tool` boundary:

```python
from agentguard.integrations import GovernedMcpClient

client = GovernedMcpClient(
    session=mcp_session,
    agent_id=agent.agent_id,
    registry=registry,
    rbac_engine=engine,
    audit_log=audit,
    # RBAC resources are derived by the integrator at construction time —
    # never accepted from the agent at call time (ADR-023). Tools without an
    # entry here cannot be called: the resource is unresolvable, so the call
    # is denied and audited.
    resources={
        "web_search": "web/search",
        "read_record": lambda args: f"records/{args['record_id']}",
    },
)
result = await client.call_tool("web_search", {"query": "..."})
```

### Resource derivation (all adapters)

`ResourceResolver = str | Callable[[Any], str | Awaitable[str]]`. Every derived
resource is canonicalised before RBAC (`canonicalize_resource`: rejects
`*?[]<>`, control characters, absolute paths and `..` traversal; normalises;
case-folds) and an unresolvable resource is a fail-closed, audited denial
against the sentinel `<unresolved>`. `Permission.matches` uses
`fnmatch.fnmatchcase` — resources compare case-insensitively, actions
case-sensitively. See ADR-023.

### LangGraph Integration (`GovernedLangGraphToolNode`)

Constructed with `resources: Mapping[tool_name, ResourceResolver]` (resolver
input: `tool_input`). Exposes the legacy `ainvoke(tool_name, tool_input)`
form, and also acts as a native async node: `ainvoke` accepts a LangGraph
messages-state mapping (tool calls are read from the last message, and native
`ToolMessage` objects are returned when `langchain-core` is installed), and
`__call__` delegates to `ainvoke`. A tool with no resolver entry — or a
resolver entry with no registered tool — is denied and audited rather than
raising `KeyError`.

### CrewAI Integration (`GovernedCrewAITool`)

Wraps a CrewAI tool (sync `_run` method) so invocations go through the
governance kernel. Constructed with a required `resource: ResourceResolver`
(resolver input: `{"args": args, "kwargs": kwargs}`); exposes async
`arun(*args, **kwargs)` and a governed sync `_run` behind CrewAI's native
`.run()` (inherited from `BaseTool` when the `crewai` extra is installed —
see ADR-045). Passing `_resource=` raises `TypeError`.

### Google ADK Integration (`GovernedAdkTool`)

Wraps an ADK tool's `run_async(args, tool_context)` method. Constructed with
a required `resource: ResourceResolver` (resolver input: `args`); there is no
per-call override.

### A2A Middleware (`GovernedA2AClient`)

Agent-to-agent messages are governed at the `send_message` boundary.
Actions are encoded as `a2a:send:<target_agent>` with resource
`agent/<target_agent>` so RBAC can allow/deny specific agent-to-agent
relationships.

---

## Security Threat Model

Primary threats and the mitigation each one is *designed* to have. Status applies only
when the application routes calls through an AgentGuard adapter or the kernel directly.

| Threat | Vector | Intended mitigation | Status |
|--------|--------|---------------------|--------|
| Privilege escalation | Agent requests higher-permission tool | RBAC deny-override; no self-grant | **Mitigated on the adapter boundary** — trusted adapter resolvers derive and canonicalize action/resource; unresolved subjects deny before RBAC. Raw-tool bypass remains an application-boundary risk. |
| Audit log tampering | Attacker modifies past events | HMAC chain; append-only storage | **Partial** — schema-v8 sequence/checkpoint verification detects edits, truncation, and signed guardrail/HITL/reconciliation/authentication/registry-evidence tampering with an external trusted head; `agentguard audit export-checkpoint` plus a collector `trusted_checkpoint_path` make that head operational, so a rollback of the audit directory and collector state together is detected against an off-host witness; collector mode separates keys and ordering, but a rollback newer than the last exported witness, same-UID dual-domain compromise, and symmetric-key repudiation remain. |
| Prompt injection | User input → agent prompt → tool args | Content scanning policy (OWASP-AGENT-01) | **Partial** — pre-stage policy and input guardrails inspect the transformed payload and can deny/escalate known patterns; semantic attacks outside configured checks remain. |
| Data exfiltration | Agent leaks PII via tool calls | PII detection; sandbox egress control | **Partial** — post-stage PII and secret guardrails can deny delivery of inspected results; configured sandbox obligations force hardened network-disabled execution, while host/raw-tool bypass remains an application-boundary risk. |
| Sandbox escape | Tool escapes the container | Minimal base images; seccomp profiles; read-only FS | **Mitigated when a sandbox obligation is configured** — enforced PRE_TOOL obligations require the hardened Docker backend with read-only non-root execution, dropped capabilities, no-new-privileges, quotas, bounded logs, and no network; applications without the obligation remain unsandboxed. |
| HITL bypass | Agent retries without waiting for approval | Durable authenticated approval state | **Partial** — PRE_TOOL/PRE_MESSAGE registered-executor requests and guardrail-triggered POST_TOOL/POST_MESSAGE/ON_DECISION delivery requests support authenticated decisions, protected continuations, exact runtime binding, signed activation evidence, distinct one-time claims, RBAC recheck, optional signed-marker recovery, and checkpoint-attested unknown-window classification. Credit review approval releases only the sealed review outcome; final credit disposition is a separately authorized `decision:override`. INPUT, policy-only, and legacy caller-executor continuation remain unsupported; ambiguous work is never replayed. |
| Agent impersonation | Caller asserts another agent's id | Verified short-lived workload credentials | **Mitigated on the secure boundary** — secure kernel mode rejects ID-only calls, authenticates before observation, and uses registry-only roles with sticky continuation binding. First-party adapters obtain a fresh credential before constructing request data; the optional concrete verifier enforces fixed RS256 signatures, claims, replay protection, pinned rotation, and revocation. Explicitly legacy kernel construction remains self-asserted. |
| Tool poisoning | Malicious tool definition injected | Tool registry with signature verification | **Roadmap** — no tool registry or signing exists |
| Credential theft | Agent accesses secrets it shouldn't | Vault integration; short-lived per-sandbox tokens | **Roadmap** — no secrets-manager integration exists |

Two further caveats that are properties of the design rather than of any one threat:
the adapters wrap a callable the caller still holds, so calling the raw tool bypasses
governance entirely; and a guardrail bypass is only as strong as the boundary the
application chooses to route through.

---

## Deployment Patterns

**Pattern 1 — Library (embedded).** *The only supported pattern.*
AgentGuard runs in-process with the agent application. Suitable for single-machine
agent systems. Note that in-process governance is advisory with respect to the
application itself: code in that process can call the wrapped tool directly. Local
`AppendOnlyAuditLog` mode also keeps its HMAC key in process; collector mode moves key
custody and ordering behind a same-host Unix-socket boundary.

**Patterns 2 and 3 — sidecar and gateway — are roadmap.** No HTTP surface, proxy,
server, or remotely deployable control-plane service ships in this package. The authoritative
registry control plane is an in-process library API, not a sidecar or gateway.

---

## Versioning and Stability Contract

- **`agentguard.core.*`**: Stable API — breaking changes require major version bump and deprecation notice
- **`agentguard.guardrails.*`**: Public runtime API — `GovernanceKernel`, immutable payload contracts, guardrail chain, and content controls
- **`agentguard.compliance.*`**: Stable API — policy schema changes are backward-compatible within minor versions
- **`agentguard.domains.*`**: Beta — may change in minor versions; domain modules are versioned independently
- **`agentguard.integrations.*`**: Stable in v1.0 — public adapter classes and constructor signatures are frozen. The `_pipeline` module is a deprecated private compatibility shim.
- **`agentguard.observability.*`**: Stable in v1.0 — `AgentTracer`, `ReplayDebugger`, and `MetricsDashboard` APIs are frozen. Shadow views and summaries are additive evidence surfaces.

---

## Roadmap — not yet implemented

Everything in this table is described elsewhere in this document as part of the target
architecture and **does not exist in the shipped package**. Phase numbers refer to
[`docs/plans/guardrails-realignment.md`](docs/plans/guardrails-realignment.md) §6.

### Layer 1 — Security runtime

| Item | Status | Phase |
|---|---|---|
| Wasm sandbox backend (`wasmtime-py`) | Not started. No `wasmtime` import exists anywhere in the package. | — |
| Sandbox on the governed path | **Shipped** (ADR-045). `GovernanceKernel` accepts a `sandbox_backend` and runs sandbox-obligated tool commands through it. | — |
| Custom seccomp profile for the Docker sandbox | Not started. The backend already sets `read_only`, non-root `user`, `cap_drop=ALL`, `no-new-privileges`, `pids_limit`, and a CPU quota; only a bespoke seccomp profile remains (Docker's default profile applies). | 5.3 |
| Per-call temporary volume mounts and per-tool network opt-in | Not started. | 5.3 |
| S3 / GCS audit backends | Not started. No cloud storage backend ships. | — |
| PostgreSQL audit backend and an `agentguard[postgres]` extra | Not started. No such extra exists, and a core DB dependency is explicitly out of scope per CLAUDE.md. | — |

### Layer 2 — Compliance

| Item | Status | Phase |
|---|---|---|
| `AgentGuard` facade class with `hitl_handler=` | **No such class exists.** Adapters are constructed with explicit dependencies. | 5.4 |
| Property 4 — credit model monotonicity proof | Not started. No monotonicity encoding exists. | — |
| Property 5 — adverse action ordering proof | Not started. Ordering is enforced by a sort tie-break, not proven. | — |
| Z3 Datalog/µZ workflow reachability | Not planned. `verify_workflow_safety` is a BFS and stays one (ADR-016). | — |
| Sound RBAC encoding (fnmatch subsumption, role inheritance) and a differential test against `RBACEngine` | **Shipped.** `z3_models.py` compiles fnmatch patterns to Z3 regexes, the verifier flattens role inheritance exactly as the runtime does, and `test_formal_verifier_differential.py` checks the encoding against `RBACEngine`. | — |
| Official FINOS AIR-\* risk mapping | Not started. Rule IDs are AgentGuard-local `AG-FINOS-NNN`. | 4/5 |

### CLI

| Item | Status | Phase |
|---|---|---|
| `verify` subcommand for workflow safety | Not implemented. The `verify` group is `rbac` and `policy` only; workflow safety is Python-API only. | — |
| `verify` subcommand for model properties (monotonicity) | Not implemented; depends on Property 4. | — |
| `sandbox` command group | Not implemented. There is no `sandbox` group. | — |

### Layer 4 and operations

| Item | Status | Phase |
|---|---|---|
| Metrics endpoint (`/metrics` or Prometheus exporter) | OTel outcome and duration instruments ship; AgentGuard does not expose an HTTP metrics endpoint. | — |
| Replay as re-evaluation against a pinned policy bundle | Not started. `ReplayDebugger` filters and prints. | — |
| Sidecar deployment (HTTP proxy endpoint) | Not started. No HTTP surface ships. | — |
| Gateway deployment (standalone governance service, central policy management) | Not started. | — |
| Tool registry with signature verification | Not started. | — |
| Vault / secrets-manager integration, short-lived per-sandbox tokens | Not started. | — |

### Adapters

| Item | Status | Phase |
|---|---|---|
| Validation against the real LangGraph / CrewAI / Google ADK / MCP packages | LangGraph messages-state/ToolMessage, CrewAI BaseTool, ADK FunctionTool, MCP `ClientSession.call_tool`, and A2A `message_send` boundaries are implemented. Optional framework-shape tests run in the CI extras matrix; local environments without extras skip those package-specific cases. | 5.1 |
