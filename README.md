# AgentGuard

**Framework-agnostic governance and security runtime for AI agents in regulated industries.**

AgentGuard sits between your agent orchestration framework (LangGraph, CrewAI, Google ADK, or raw Python) and the tools/services your agents access. Today its governed path enforces input transformation, derived-resource RBAC, staged policy checks, rate limits, circuit breakers, PII/secret egress controls, lifecycle-aware HMAC audit evidence, durable escalation requests, authenticated restart-safe PRE_TOOL/PRE_MESSAGE resumption for trusted registered executors, protected POST_TOOL/POST_MESSAGE/ON_DECISION delivery after guardrail approval, and opt-in reconciliation for claimed protected continuations. Secure kernels and first-party adapters authenticate fresh per-call workload credentials before request observation; an explicitly legacy compatibility mode still accepts a self-asserted `agent_id`. Checkpoint-attested rolling fairness monitoring is available as an offline evidence producer with private observation joins. Strict revisioned model-validation reports can populate the live trusted provider through a verified exact-model signed-report source; durable multi-process report storage and signing-key custody remain deployment responsibilities. Hardened Docker sandbox obligations are available on the governed PRE_TOOL path when configured; host subprocess backends are rejected (see `docs/plans/guardrails-realignment.md`). The goal is a live guardrails engine for environments where security and regulatory compliance are non-negotiable.

Financial services / credit risk is the flagship domain. The current toolkit includes a pure,
versioned `CreditDecisionPolicy`; a `GovernedCreditAgent` that uses separately authorizable score,
decision, override, and notice actions; direction-aware adverse-contribution evidence; trusted
model-provenance guardrails; independent ECOA and FCRA reason registries; typed credit-notice
artifacts; deterministic source-grounded renderers; and verified unresolved-decline correlation.
Signed runtime evidence retains only domain-separated opaque references and allowlisted metadata,
not applicant data, PD values, feature details, reason text, or notice bodies.

## Current Status: v0.9.0 (Alpha)

AgentGuard is being realigned from a governance decorator into a live guardrails engine — see [docs/plans/guardrails-realignment.md](docs/plans/guardrails-realignment.md) for the gap analysis and phased plan.

### Enforced at runtime

Reachable from the governed call path today:

| Component | Description |
|-----------|-------------|
| Audit Logger | Versioned HMAC-SHA256 chain with lifecycle evidence, v4 signed guardrail evaluations, v5 signed HITL evidence, v6 signed `ReconciliationEvidence`, v7 signed `AuthenticationEvidence`, v8 signed `RegistryMutationEvidence`, sequence numbers, prepared/fsynced file commits, signed checkpoints, immutable key epochs, and an opt-in keyless UDS collector client |
| Authenticated agent identity | Secure `GovernanceKernel` mode authenticates opaque credentials before request observation, resolves roles only from an authoritative registry snapshot, and signs the exact authentication event bound into resumable work. Optional `agentguard[auth]` supplies a local-only RS256 verifier with pinned keys, strict claims, replay prevention, bounded rotation overlap, and emergency revocation. |
| Agent identity (legacy) | `AgentRegistry` and `FileBackedRegistry` remain compatibility-only, unsigned, self-asserted registries for explicitly legacy kernel construction. |
| RBAC Engine | Deny-override semantics, role inheritance, wildcard matching |
| Policy Engine | Staged YAML rules on real tool input/output; immutable content-addressed bundles support explicit atomic reload with per-invocation version pinning; shipped bundles contain 3 deny, 3 escalate, and 29 warn rules |
| Content guardrails | Deeply immutable payloads, PII input masking, PII/secret output denial, and optional output-schema validation |
| Circuit Breaker | Atomic CLOSED/OPEN/HALF_OPEN admission + token buckets keyed by agent and action |
| Governance kernel | Reusable `GovernanceKernel`: transform → derive action/resource → RBAC/policy/guardrails → atomic admission → execute → post-check → delivery terminal; used by every adapter. Guardrails support enforce, shadow, and off modes without disabling RBAC, policy, limits, breakers, or audit. |
| Governed credit decisions | `GovernedCreditAgent` emits `model:score`, `decision:approve`, `decision:review`, `decision:decline`, `decision:override`, and `notice:issue` through the full kernel lifecycle. `DecisionPayload` results run at `ON_DECISION`; review approval releases only the sealed review result, while a final underwriter outcome requires a separate `decision:override` authorization. |
| Durable HITL resume | Optional `EscalationStore` persists verifier-only tokens and opaque protected continuations. Registered PRE_TOOL/PRE_MESSAGE calls support authenticated decisions, complete-chain and multi-approval cursors, exact pinned policy/executor binding, stable execution claims, and current RBAC recheck. Guardrail-triggered POST_TOOL/POST_MESSAGE/ON_DECISION requests seal the completed result and resume only post-processing through a distinct delivery claim; they never resolve or invoke an executor. Linked decision continuations use schema v3 for opaque references and allowlisted redacted metadata while preserving exact schema-v1/v2 bytes. Raw payloads, credentials, tokens, and results are never stored in plaintext. |
| Protected execution reconciliation | Optional `ExecutionJournal` signs claim-state metadata and AEAD-protects an exact completed result before post-processing. Reconciliation requires an authenticated `hitl:reconcile` principal. A protected known result resumes post-processing without executor replay; checkpoint-attested unknown or already-claimed post-processing becomes `IN_DOUBT` and supports denial only. Executor exception, cancellation, or invalid output commits one stable invocation delivery denial and durable `DELIVERY_DENIED`; repeated cancellation waits for that terminal. Before any POST callback, the journal atomically claims post-processing and the kernel writes a stable claim/resume audit marker. Verified claim and delivery markers detect signed journal rollback, prevent POST replay, and converge or fail closed. |

### Authentication and registry boundary

`agentguard.core.authentication` defines mechanism-neutral async protocols for agent credentials,
agent authentication, and a separate control-plane authenticator. A verified
`AuthenticatedAgentPrincipal` contains credential-derived identity and validity facts but no roles
or capabilities; authorization comes from registry-owned records. Schema v7 signs
secret-free verified/rejected `AuthenticationEvidence` and reserves machine-stable `AUTH.*`
failure codes. Rejected-event producers must use the reserved `__unauthenticated__` actor and must
not persist claimed identity, provider diagnostics, credentials, roles, or credential timestamps.

`InMemoryAuthoritativeAgentRegistry` and `SignedFileAuthoritativeAgentRegistry` expose deeply
immutable active/revoked records. `AgentRegistryControlPlane` authenticates a distinct
`ControlPlanePrincipal`, enforces exact mutation and per-role capabilities, and uses an idempotent
prepare → audit → commit ledger. Each registry re-reads its configured audit sink before commit;
the control plane's capability object alone is not proof of a durable event. Schema v8 signs typed
`RegistryMutationEvidence` while preserving
the exact v1-v7 serializers. The signed file store uses a separate HMAC domain and hardened local
POSIX persistence, a chained local checkpoint, an independently retained trusted checkpoint path,
and a persisted verified-audit head. It requires a checkpoint-capable audit sink and offloads file
locking and I/O from the event loop.
Secure `GovernanceKernel` construction now requires an `AgentAuthenticator` and
`AuthoritativeAgentRegistry` together, rejects caller-supplied IDs, writes signed secret-free
authentication evidence before observing request data, and seals schema-v2 continuations bound to
the exact signed event, registry revision, record revision, and credential epoch. Resume rechecks
current registry status, epoch, and RBAC without requiring the original short-lived credential.
All five first-party adapters now obtain a fresh credential per call through a kernel-bound caller,
before constructing or observing request data. `JwtAgentAuthenticator` is the concrete optional
verifier: it accepts only bounded RS256 JWTs from one exact issuer/audience, resolves operator-pinned
local JWK snapshots without network discovery, validates short-lived claims with explicit skew,
and atomically enforces replay and emergency revocation. The included stores are process-local;
multi-process deployments must inject shared implementations of `JwtKeySetProvider` and
`CredentialUseStore`; shared replay stores must use backend-owned, nondecreasing trusted time and
must not trust caller timestamps. JWT/key revocation must be paired with registry credential rotation or
identity revocation when already-approved protected continuations must also be invalidated.
`AgentRegistry` and `FileBackedRegistry` remain compatibility-only.

### Offline analysis tools

Run by CLI / reports — not yet on the runtime call path:

| Component | Description |
|-----------|-------------|
| Policy attestation rules | Twenty shipped rules remain detect-only attestation checks until trusted evidence producers exist |
| Formal Verifier | Z3 SMT solver, RBAC model only — see ADR-013 caveat |
| Compliance Reporter | JSON and Markdown compliance attestations with a separate observed-not-enforced shadow findings section |
| Replay Debugger | Audit replay with filtering, lifecycle timelines, and signed shadow decision details |
| Metrics Dashboard | Invocation-aware denial/latency/policy metrics plus deduplicated shadow-mode, HITL lifecycle, and unresolved `IN_DOUBT` summaries |
| OTel Tracer | Root governance span with RBAC, policy, execution, and audit descendants plus outcome/latency instruments; NoOp unless the host configures SDK providers |
| Credit-risk analysis support | Truthful attribution/reason construction, typed Regulation B/FCRA notice construction and deterministic rendering, strict revisioned model-validation evidence with a signed exact-model provider handoff, private-join fairness monitoring, PII masking, and synthetic data generation. Only verified current provider evidence can authorize the governed credit boundary; reports and caller attributes cannot. |

### Framework adapters

Each adapter degrades gracefully to a duck-typed wrapper when its framework
is not installed, and binds to the native framework surface when it is
(lazy imports: `langchain-core` `ToolMessage`s, CrewAI `BaseTool`
subclassing, ADK `FunctionTool` export, `mcp.types` error results; the A2A
adapter is fully framework-independent). Native-boundary tests against the
real frameworks live in `tests/unit/integrations/test_real_adapters.py` and
run when the matching extra is installed (`uv sync --extra dev --extra
<langgraph|crewai|adk|mcp>`):

| Component | Description |
|-----------|-------------|
| LangGraph | `GovernedLangGraphToolNode` |
| CrewAI | `GovernedCrewAITool` |
| Google ADK | `GovernedAdkTool` |
| MCP | `GovernedMcpClient` |
| A2A | `GovernedA2AClient` |

Unit tests run with `pytest tests/unit/` (coverage gate: 80%, enforced by the pytest configuration).

## Quickstart

```bash
pip install -e "."
# Add the concrete workload verifier with: pip install "agentguard[auth]"
export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

```python
import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agentguard.core import AgentRegistry, AppendOnlyAuditLog, FileAuditBackend
from agentguard.core import RBACEngine, Role, Permission
from agentguard.models import AuditEvent


async def main():
    # 1. Register an agent in the legacy compatibility registry.
    # This quickstart intentionally demonstrates the legacy compatibility boundary.
    registry = AgentRegistry()
    agent = await registry.register(name="Credit Bot", roles=["credit-analyst"])

    # 2. Define RBAC roles (deny-override: explicit deny always wins)
    engine = RBACEngine(
        roles=[
            Role(
                name="credit-analyst",
                permissions=[
                    Permission(action="tool:credit_check", resource="bureau/*", effect="allow"),
                    Permission(action="data:read:pii", resource="*", effect="deny"),
                ],
            ),
        ]
    )

    # 3. Check permissions
    allowed = await engine.check_permission(agent, "tool:credit_check", "bureau/experian")
    print(f"Credit check: granted={allowed.granted}")  # True

    denied = await engine.check_permission(agent, "data:read:pii", "customer_ssn")
    print(f"PII access:   granted={denied.granted}")  # False

    # 4. Write to tamper-evident audit log
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=Path("./audit-logs")))
    await audit.write(
        AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            agent_id=agent.agent_id,
            action="tool:credit_check",
            resource="bureau/experian",
            permission_context=allowed,
            result="allowed",
            duration_ms=5.0,
            trace_id=str(uuid.uuid4()),
        )
    )

    # 5. Verify chain integrity
    result = await audit.verify_chain()
    print(f"Audit chain: valid={result.valid}, events={result.event_count}")


asyncio.run(main())
```

## Architecture

```
Your Agent Application (LangGraph / CrewAI / ADK / Python)
                    |
                    v
        AgentGuard Runtime Middleware
        +----------------------------------+
        | Layer 1: Security Runtime        |  Enforced at runtime
        |   Payloads, RBAC, Policy, PII,   |
        |   Audit, Limits, Breakers, MCP   |
        +----------------------------------+
        | Layer 2: Compliance Engine       |  Runtime + offline analysis
        |   Staged Policy-as-Code, HITL,   |
        |   Z3, OWASP, FINOS, EU AI Act   |
        +----------------------------------+
        | Layer 3: Domain Toolkit          |  Offline analysis tool
        |   Credit Risk, Adverse Action,   |
        |   Fairness, PII, Synthetic Data  |
        +----------------------------------+
        | Layer 4: Integrations + Observe  |  Wrappers / offline analysis
        |   LangGraph, CrewAI, ADK, A2A,  |
        |   OTel Traces, Replay, Metrics  |
        +----------------------------------+
                    |
                    v
        Tools / Services / External APIs
```

### Design Principles

- **Zero-trust by default** — agents have no permissions unless explicitly granted
- **Log-first, act-second** — every action is audit-logged before execution; if logging fails, the action is blocked
- **Deny-override RBAC** — explicit deny always wins, like AWS IAM
- **Tamper-evident audit** — HMAC-SHA256 chain; modifying any past event breaks the chain
- **Framework-agnostic** — works with any agent framework; integrations are adapters, not requirements
- **Fail-safe over fail-open** — when governance errors, it blocks the action, not allows it

## CLI

```bash
# Audit log operations
agentguard audit show --log-dir ./audit-logs
agentguard audit verify --log-dir ./audit-logs
agentguard audit verify --log-dir ./audit-logs \
  --trusted-checkpoint ./offhost/audit-head.json  # Also detect a rolled-back log
agentguard audit export-checkpoint --audit-dir ./audit-logs \
  --output ./offhost/audit-head.json            # Signed head to replicate off-host
agentguard audit replay --log-dir ./audit-logs

# Policy management
agentguard policy validate                    # List all loaded policy rules
agentguard policy report --log-dir ./audit-logs \
  --trusted-checkpoint ./trusted/audit-head.json # Generate a clean attestation

# Formal verification
# The two `verify` commands need the Z3 extra: pip install 'agentguard[verify]'
agentguard verify policy                      # Check policy consistency via Z3
agentguard verify rbac --config rbac.yaml     # Verify RBAC escalation absence

# Observability
agentguard observe dashboard --log-dir ./audit-logs  # Aggregate metrics (JSON/Markdown)
agentguard observe replay    --log-dir ./audit-logs \
  --agent-id <uuid> --result denied           # Filtered replay with decision summaries
agentguard observe summary   --log-dir ./audit-logs  # Quick counts by result/agent/action
```

`audit-head.json` inside the log directory proves local consistency but shares the log's rollback
boundary. Export the signed head with `agentguard audit export-checkpoint` and replicate it to
storage the audit host cannot write; passing it back with `--trusted-checkpoint` makes a log that
no longer reaches that head fail as `ROLLBACK DETECTED`, and unanchored evidence remains
inspectable but is refused as a clean compliance attestation. Export refuses to overwrite a
witness that already commits to a higher head, so the witness itself cannot be rolled back
quietly. A same-host copy of the witness proves nothing, and the window between exports is
undetectable — export frequency sets how much history a rollback could silently discard.

### Out-of-process audit collector

Production deployments can keep signing keys out of the agent process. Run an
`AuditCollectorServer` in a separate supervised process with its own key environment, then give
the agent only a `SigningAuditBackend` pointing at the owner-only Unix socket:

```python
from pathlib import Path

from agentguard.core import (
    AppendOnlyAuditLog,
    AuditCollectorServer,
    FileAuditBackend,
    SigningAuditBackend,
)

# Collector process only: AGENTGUARD_AUDIT_KEY is present here.
local_log = AppendOnlyAuditLog(FileAuditBackend(Path("/var/lib/agentguard/audit")))
collector = AuditCollectorServer(
    socket_path=Path("/run/agentguard/audit.sock"),
    audit_log=local_log,
    state_path=Path("/var/lib/agentguard-anchor/state.json"),
    # Must resolve outside both directories above; replicate it off-host.
    trusted_checkpoint_path=Path("/var/lib/agentguard-witness/audit-head.json"),
)
await collector.start()

# Agent process: no audit key is present.
audit = SigningAuditBackend(Path("/run/agentguard/audit.sock"))
```

The collector assigns all integrity fields, serializes concurrent writers, stores a signed key
epoch/fingerprint commitment, and uses bounded framed requests and immutable paginated snapshots.
It fails closed when unavailable or malformed. A prepared checkpoint makes a crash before append
discardable and a crash after event `fsync` recoverable without creating a fork.

With `trusted_checkpoint_path` set, the collector refuses to start when its local head is behind
that witness and rewrites the witness after every committed checkpoint, so replicating the file
off-host is all that stands between you and rollback detection.

This boundary protects the key and ordering only when the collector and external state are in
separate failure domains from the agent and log. It does not prove event semantics, resist a
same-UID attacker that can replace both domains and roll back to a point newer than the last
off-host witness, or provide third-party verification of the HMAC. The UDS directory is
owner-only, peers are UID-checked, and one lifetime lock prevents two collectors from owning the
same log directory.

#### Rotating the audit signing key

Key bytes live only in the environment, so an epoch the environment does not declare cannot be
rebuilt after a restart. Declare the next epoch first, then activate it:

```bash
export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
# Declare epoch 2 before rotating; activation_sequence is where it takes effect.
export AGENTGUARD_AUDIT_KEYS='{"epoch-2": {"key": "<32+ byte key>", "activation_sequence": 900}}'
```

`AuditCollectorServer.rotate_key` refuses an epoch that `AGENTGUARD_AUDIT_KEYS` does not declare,
so the one-way door — post-rotation events that no restart can verify — cannot be opened by
accident. Keep every past epoch in the variable for as long as you need to verify events signed
under it.

Adding an epoch to a collector that is already running against committed state requires
`AuditCollectorServer(..., adopt_declared_epochs=True)` for that start: the declaration is not
signed by anything, so committing it is a deliberate operator action rather than a side effect of
a restart. Protect `AGENTGUARD_AUDIT_KEYS` exactly as you protect `AGENTGUARD_AUDIT_KEY` —
whoever can write it can introduce a signing epoch.

## Roadmap

Milestones below track code landing in `main`, not independent releases — only
`v0.2.0` has ever been tagged. The package version was `1.0.0` through M6 despite
this; see [CHANGELOG.md](CHANGELOG.md) for the `0.9.0` correction and
[docs/plans/guardrails-realignment.md](docs/plans/guardrails-realignment.md) for
what's next.

| Milestone | Code landed | Status | What |
|-----------|-------------|--------|------|
| M0+M1 | v0.1.0 | **Code complete** | Audit logger, RBAC, identity, CLI |
| M2 | v0.2.0 (tagged) | **Code complete** | Circuit breaker, Docker sandbox, MCP middleware, file-backed registry |
| M3 | — | **Code complete** | Compliance engine, Z3 formal verifier, OWASP/FINOS/EU AI Act policies |
| M4 | — | **Code complete** | Credit risk attribution/reason evidence, typed notices/renderers, governed decision and notice emission, unresolved-decline correlation, private-join statistical fairness monitoring, signed model-validation evidence, and deterministic synthetic benchmark corrections |
| M5 | — | **Code complete** | LangGraph, CrewAI, Google ADK, A2A integrations |
| M6 | — | **Code complete** | Observability (OTel tracer, replay debugger, metrics dashboard) |

## Development

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Lint + format
ruff check . --fix && ruff format .

# Type check
mypy agentguard/

# Test
AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") pytest tests/unit/ -v

# All tests with coverage
AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") pytest tests/ --cov=agentguard --cov-report=term-missing
```

## Project Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — full architecture reference (4 layers, threat model, deployment patterns)
- [DECISIONS.md](DECISIONS.md) — architectural decision records (45 ADRs)
- [AGENTS.md](AGENTS.md) — agent role definitions for parallel development

## License

MIT
