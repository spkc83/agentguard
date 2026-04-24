---
created: "2026-04-22"
last_edited: "2026-04-22"
---

# Implementation Tracking: CLI Surface

Build site: context/plans/build-site.md

Brownfield strict-as-built verification.

## Tier 3 CLI — Tasks T-121..T-135

| Task | Status | Notes |
|------|--------|-------|
| T-121 | DONE | R1 C1-4 no-arg help, four groups, per-group help, --json toggle (cli.py:35-48 Typer app + audit/policy/verify/observe sub-apps with no_args_is_help=True; main callback --json option + test_cli.py). |
| T-122 | DONE | R2 C1-5 audit show command (cli.py:61-106 audit_show with log_dir default ./audit-logs, agent_id filter, Rich table with 6 columns, no-events yellow message, result styled per severity + test_cli.py). |
| T-123 | DONE | R3 C1-2 + R12 C1 audit verify exit codes (cli.py:109-133 audit_verify: green success + exit 0; AuditTamperDetectedError caught + Exit code=1 + test_cli_verify.py). |
| T-124 | DONE | R4 C1-3 audit replay (cli.py:136-170 audit_replay: no-events message + per-event multi-line render incl id/ts/agent/action/resource/result/duration; reason line when present + test_cli_replay.py). |
| T-125 | DONE | R5 C1-4 policy validate (cli.py:173-209 policy_validate: policy-dir override, table id/name/severity/check-type/enabled, severity styled, footer set/rule counts + test_cli_policy_verify.py). |
| T-126 | DONE | R6 C1-4 policy report (cli.py:212-241 policy_report: log-dir+policy-dir+format options default=markdown; no-events message; otherwise prints reporter output + test_cli_policy_verify.py). |
| T-127 | DONE | R7 C1-3 + R12 C2 verify rbac pre-run checks (cli.py:244-310: no-config hint exit 0; missing config Exit 1; target-perm not-referenced Exit 1 + test_cli_verify.py). |
| T-128 | DONE | R7 C4-6 + R12 C2 verify rbac verdicts (cli.py:312-337: unsat green+exit 0; sat prints counterexample + Exit 1; timeout/unknown prints status no error exit + test_cli_verify.py). |
| T-129 | DONE | R8 C1-3 verify policy (cli.py:339-379 verify_policy: policy-dir option; no-rules message exit 0; unsat success with rule count + test_cli_policy_verify.py). |
| T-130 | DONE | R8 C4-5 verify policy contradictions (cli.py:375-379: sat prints rule1<->rule2 pairs; timeout/unknown printed without raise + test_cli_policy_verify.py). |
| T-131 | DONE | R9 C1-2 observe dashboard (cli.py:382-402 observe_dashboard: log-dir+format options, prints metrics always including empty case + test_cli_observe.py). |
| T-132 | DONE | R10 C1-2 observe replay filters + ISO-UTC coercion (cli.py:405-448 observe_replay: all filter options; cli.py:20-32 _parse_iso_utc coerces naive → UTC + test_cli_observe.py). |
| T-133 | DONE | R10 C3-5 observe replay output (cli.py:436-446: no-matches message exit 0; per-entry index+summary+flags; footer event count + test_cli_observe.py). |
| T-134 | DONE | R11 C1-4 observe summary (cli.py:451-476 observe_summary: log-dir option; prints total, per-result, top-10 agents, top-10 actions + test_cli_observe.py). |
| T-135 | DONE | R12 C3 non-failure commands exit 0 (audit show/replay, policy validate/report, verify policy, all observe commands contain no typer.Exit calls → default exit 0 + test_cli.py end-to-end runs). |

## Summary

15/15 CLI tasks DONE. 31 tests pass across tests/unit/test_cli*.py.
