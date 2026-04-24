---
created: "2026-04-19"
last_edited: "2026-04-19"
complexity: quick
---

# Cavekit: CLI Surface

## Scope
This kit covers the user-facing command-line interface that exposes AgentGuard's audit, policy, formal verification, and observability operations. The CLI is a thin entry point: every command delegates to the layer it represents and is responsible only for argument parsing, output formatting, and exit code propagation.

## Requirements

### R1: Top-Level Command Groups
**Description:** The CLI is organized into four top-level command groups whose names map directly to the layers they expose: audit, policy, verify, observe. Invoked with no arguments, the CLI prints help.
**Acceptance Criteria:**
- [ ] Invoking the CLI with no arguments prints a help message rather than performing an action.
- [ ] The CLI advertises four command groups: audit, policy, verify, observe.
- [ ] Each command group prints its own help message when invoked with no subcommand.
- [ ] A top-level option toggles JSON-formatted log output for the duration of the invocation.

### R2: Audit Show Command
**Description:** A command lists audit events from a configured audit log directory, optionally filtered by agent identifier, in a human-readable table.
**Acceptance Criteria:**
- [ ] The command accepts an audit log directory option (default `./audit-logs`).
- [ ] The command accepts an optional agent identifier filter that restricts output to events for that agent.
- [ ] A successful run prints a table including event identifier, timestamp, agent identifier, action, resource, and result for each event.
- [ ] When no events match, the command prints a clear "no events" message and exits with success status.
- [ ] Result values render with severity-appropriate visual emphasis (denied and error are visually distinguished from allowed and escalated).

### R3: Audit Verify Command
**Description:** A command verifies the HMAC chain of an audit log directory and exits with non-zero status if tampering is detected.
**Acceptance Criteria:**
- [ ] On an unmodified log, the command prints a success message including the verified event count and exits with status zero.
- [ ] On a tampered log, the command prints a tamper-detected message identifying the broken event index and identifier and exits with non-zero status.

### R4: Audit Replay Command
**Description:** A command prints each audit event in the configured directory in chronological order with a multi-line per-event display covering identifier, timestamp, agent, action, resource, result, duration, and (when present) the permission decision reason.
**Acceptance Criteria:**
- [ ] When no events exist, the command prints a clear "no events" message and exits with success status.
- [ ] Each event displayed includes its identifier, timestamp, agent identifier, action, resource, result, and duration.
- [ ] When the permission decision carries a reason string, that reason is included in the per-event display.

### R5: Policy Validate Command
**Description:** A command lists every loaded policy rule from a configured policy directory (or the built-in directory when no override is supplied) in a human-readable table.
**Acceptance Criteria:**
- [ ] The command accepts an optional policy directory option that overrides the default (built-in shipped policies).
- [ ] The command prints a table containing rule identifier, name, severity, check type, and enabled flag for each rule.
- [ ] After the table, the command prints a summary of how many policy sets and rules were loaded.
- [ ] Severity values render with severity-appropriate visual emphasis.

### R6: Policy Report Command
**Description:** A command generates a compliance attestation report from an audit log directory and prints it in either JSON or Markdown format.
**Acceptance Criteria:**
- [ ] The command accepts audit log directory and policy directory options.
- [ ] The command accepts an output format option that selects between JSON and Markdown (default Markdown).
- [ ] When no events exist, the command prints a clear "no events" message and exits with success status.
- [ ] Otherwise, the command prints the generated compliance report in the chosen format and exits with success status.

### R7: Verify RBAC Command
**Description:** A command runs the RBAC privilege-escalation verifier against a YAML configuration file describing roles, target permission, and forbidden roles, and reports the verification result.
**Acceptance Criteria:**
- [ ] When no config is supplied, the command prints a usage hint and exits with success status (no verification attempted).
- [ ] When the config path does not exist, the command prints an error and exits with non-zero status.
- [ ] When the target permission is not referenced by any role in the config, the command prints an error and exits with non-zero status.
- [ ] When the verifier returns the property holds (no escalation path), the command prints a success message and exits with status zero.
- [ ] When the verifier returns a counterexample (escalation possible), the command prints the counterexample and exits with non-zero status.
- [ ] When the verifier returns timeout or unknown, the command prints the result status without an error exit.

### R8: Verify Policy Command
**Description:** A command runs the policy-set consistency verifier against the loaded rule set and reports any contradicting rule pairs.
**Acceptance Criteria:**
- [ ] The command accepts an optional policy directory option.
- [ ] When no rules are loaded, the command prints a clear "no rules" message and exits with success status.
- [ ] When verification finds no contradictions, the command prints a success message including the rule count and exits with status zero.
- [ ] When verification finds contradictions, the command prints each contradicting rule pair by identifier.
- [ ] When the verifier returns timeout or unknown, the command prints the result status without raising.

### R9: Observe Dashboard Command
**Description:** A command computes the aggregate metrics dashboard from an audit log directory and prints it in JSON or Markdown.
**Acceptance Criteria:**
- [ ] The command accepts audit log directory and output format options (default format Markdown).
- [ ] The command prints the dashboard metrics in the chosen format on every run, including the empty-events case (the dashboard handles empty input gracefully per cavekit-observability.md R7).

### R10: Observe Replay Command
**Description:** A command runs the replay debugger against an audit log directory with optional filters by agent identifier, action substring, result, and ISO 8601 time range. ISO timestamps without an explicit offset are interpreted as UTC.
**Acceptance Criteria:**
- [ ] The command accepts an audit log directory option and optional agent identifier, action substring, result, start time, and end time filter options.
- [ ] ISO 8601 timestamps supplied without a timezone offset are coerced to UTC before filtering.
- [ ] When no events match the filters, the command prints a clear "no matches" message and exits with success status.
- [ ] When events match, the command prints each timeline entry's index, decision summary, and warning flags.
- [ ] After the timeline, the command prints a count of events shown.

### R11: Observe Summary Command
**Description:** A command prints quick counts of audit events from a directory broken down by result, by top agents, and by top actions.
**Acceptance Criteria:**
- [ ] The command accepts an audit log directory option.
- [ ] The command prints the total event count.
- [ ] The command prints per-result counts covering each distinct result value present in the events.
- [ ] The command prints up to ten most-active agents by event count.
- [ ] The command prints up to ten most-frequent actions by event count.

### R12: Exit Code Discipline
**Description:** Commands that imply a pass/fail check (audit verify, verify rbac) exit with non-zero status on failure so the CLI is suitable for use in CI pipelines and supervisory scripts.
**Acceptance Criteria:**
- [ ] Audit verify exits with non-zero status when tampering is detected.
- [ ] Verify rbac exits with non-zero status when a privilege escalation counterexample is found, when the config file is missing, or when the target permission is not referenced.
- [ ] All other commands exit with status zero on successful execution (including the empty-input cases).

## Out of Scope
- Identity, RBAC, audit log writing, sandbox, circuit breaker, rate limiter (see cavekit-security-runtime.md).
- Policy evaluation, HITL, formal verification implementation (see cavekit-compliance-engine.md).
- Credit-risk, PII, fairness, synthetic data (see cavekit-finance-credit-risk.md).
- Framework adapter wrappers (see cavekit-framework-integrations.md).
- Replay, dashboard, and tracer implementations (see cavekit-observability.md).
- Interactive shell, REPL, or daemon modes.
- Web UI or HTTP API.
- A `verify model` or `verify workflow` subcommand referenced in ARCHITECTURE.md examples; these verifier properties are exposed as a library API but not as CLI subcommands in v1.0.0. [GAP]

## Cross-References
- See also: cavekit-security-runtime.md (audit show, audit verify, audit replay)
- See also: cavekit-compliance-engine.md (policy validate, policy report, verify rbac, verify policy)
- See also: cavekit-finance-credit-risk.md (no direct subcommands today, but credit-risk outputs flow through compliance reports)
- See also: cavekit-framework-integrations.md (adapters are not exercised through the CLI but their audit output is)
- See also: cavekit-observability.md (observe dashboard, observe replay, observe summary)

## Source Traceability
- R1 satisfied by: agentguard/cli.py (app/audit_app/policy_app/verify_app/observe_app, main callback) + tests/unit/test_cli.py
- R2 satisfied by: agentguard/cli.py (audit_show) + tests/unit/test_cli.py
- R3 satisfied by: agentguard/cli.py (audit_verify) + tests/unit/test_cli.py
- R4 satisfied by: agentguard/cli.py (audit_replay) + tests/unit/test_cli_replay.py
- R5 satisfied by: agentguard/cli.py (policy_validate) + tests/unit/test_cli_policy_verify.py
- R6 satisfied by: agentguard/cli.py (policy_report) + tests/unit/test_cli_policy_verify.py
- R7 satisfied by: agentguard/cli.py (verify_rbac) + tests/unit/test_cli_verify.py
- R8 satisfied by: agentguard/cli.py (verify_policy) + tests/unit/test_cli_policy_verify.py + tests/unit/test_cli_verify.py
- R9 satisfied by: agentguard/cli.py (observe_dashboard) + tests/unit/test_cli_observe.py
- R10 satisfied by: agentguard/cli.py (observe_replay, _parse_iso_utc) + tests/unit/test_cli_observe.py
- R11 satisfied by: agentguard/cli.py (observe_summary) + tests/unit/test_cli_observe.py
- R12 satisfied by: agentguard/cli.py (typer.Exit calls in audit_verify and verify_rbac) + tests/unit/test_cli.py + tests/unit/test_cli_verify.py

## Changelog
- 2026-04-19: Initial draft, reverse-engineered from v1.0.0 codebase.
