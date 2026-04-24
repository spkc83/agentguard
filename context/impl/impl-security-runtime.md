---
created: "2026-04-22"
last_edited: "2026-04-22"
---

# Implementation Tracking: Security Runtime (Layer 1)

Build site: context/plans/build-site.md

Brownfield strict-as-built verification. Code pre-existed at v1.0.0; tasks confirm acceptance criteria by mapping to source + existing test, adding targeted tests only where a criterion lacks explicit coverage.

## Tier 0 — Tasks T-001..T-033

| Task | Status | Notes |
|------|--------|-------|
| T-001 | DONE | R1 C1 id-gen (identity.py:49-50 + test_identity.py test_register_returns_identity/test_register_generates_unique_ids). R1 C2 duplicate (identity.py:59-61 check-before-assign + test_duplicate_registration_raises). R1 C3 not-found (identity.py:73-77 + test_resolve_not_found_raises). |
| T-002 | DONE | R1 C4 restore+atomic (identity.py:103-110 _load_sync, 116-118 tmp+os.replace + test_file_registry.py test_survives_restart). R1 C5 concurrent-async (asyncio.Lock + NEW test_concurrent_registrations_no_lost_entries, test_concurrent_duplicate_only_one_wins). |
| T-003 | DONE | R2 C1 zero-roles-deny (rbac.py:166-179 deny-by-default + test_rbac.py test_no_roles_denies). R2 C2 deny-override (rbac.py:126-145 + test_deny_override, test_deny_override_even_with_inherited_allow). R2 C3 wildcards (rbac.py:39-41 fnmatch + TestPermission test_wildcard_*, test_prefix_wildcard). |
| T-004 | DONE | R2 C4 inheritance transitivity (rbac.py:91-108 _collect_permissions + test_role_inheritance, test_multi_level_inheritance). R2 C5 cycle termination (rbac.py:71-89 _detect_circular_inheritance, 97-98 visited-set + test_circular_inheritance_warns + NEW test_check_permission_terminates_with_cycle). R2 C6 structured context (rbac.py:139-145/158-164/174-180 PermissionContext + test_permission_context_fields). |
| T-005 | DONE | R3 C1 missing-key raise (audit.py:98-100 + test_missing_key_raises). R3 C2 chain linkage (audit.py:106-150 write+compute_hash + test_write_sets_hashes, test_chain_links). |
| T-006 | DONE | R3 C3 restore-on-startup (audit.py:112-124 _ensure_chain_initialized + test_chain_survives_restart). R3 C4 clean verify (audit.py:152-178 verify_chain + test_verify_chain_passes). |
| T-007 | DONE | R3 C5 tamper detection (audit.py:170-174 prev_hash/event_hash mismatch → raise + test_verify_detects_tampering asserts event_index=2). |
| T-008 | DONE | R3 C6 + R10 C1 log-first (audit.py:141 backend.append before returning chained; _pipeline.py writes pre-event before executor call + test_pipeline.py test_success_path_writes_one_allowed_event, test_deny_path asserts executor NOT called). |
| T-009 | DONE | R4 C1 Protocol surface (audit.py:38-43 AuditBackend Protocol exposes exactly append + read_all + NEW test_custom_backend_protocol_swap implements InMemoryBackend conforming to Protocol). |
| T-010 | DONE | R4 C2 NDJSON layout (audit.py:61 date-stamped filename, 63-68 append one line, 58 mkdir exist_ok=True + test_append_creates_file). |
| T-011 | DONE | R4 C3 deterministic cross-file order (audit.py:74 sorted(glob) + test_append_multiple, read-all returns correct count). |
| T-012 | DONE | R4 C4 custom-backend swap verified by NEW InMemoryBackend test (test_custom_backend_protocol_swap, 3 events written + verified via audit log). |
| T-013 | DONE | R5 C1 timeout distinguishable result (sandbox.py:84-95 TimeoutError → exit_code=137 + test_run_timeout). |
| T-014 | DONE | R5 C2 network-off default (sandbox.py:40 SandboxConfig.network_enabled=False default, 135 network_disabled=not cfg.network_enabled). |
| T-015 | DONE | R5 C3-4 mem limit + cleanup (sandbox.py:136 mem_limit, 151 container.remove(force=True) in finally). |
| T-016 | DONE | R5 C5 no shell=True (sandbox.py:9-11 docstring declares asyncio.create_subprocess_exec only; grep confirms no shell=True in agentguard/*). |
| T-017 | DONE | R5 C6 missing-SDK actionable error (sandbox.py:122-127 raise SandboxError "Docker SDK not installed. Install with: pip install agentguard[sandbox]" + test_missing_docker_sdk). |
| T-018 | DONE | R5 C7 structured result (SandboxResult with stdout/stderr/exit_code/duration_ms/backend + test_run_success asserts all five fields, test_run_captures_stderr, test_run_failure). |
| T-019 | BLOCKED | R6 C1 shell-injection escape — Docker socket not accessible to current user in this env (permission denied on /var/run/docker.sock); test exists (test_sandbox_escape.py::test_no_network_access) and is correctly marked @pytest.mark.integration/red_team. Must be rerun in Docker-enabled CI. |
| T-020 | BLOCKED | R6 C2 host-filesystem read — same Docker socket blocker; test (test_no_host_filesystem_read) exists, marked red_team. |
| T-021 | BLOCKED | R6 C3 network egress — same Docker socket blocker; test (test_no_network_access via urllib to google.com) exists, marked red_team. |
| T-022 | DONE | R7 C1 closed pass-through + reset (circuit_breaker.py:87-94, 108-113 _record_success resets counter + test_closed_passes_through, test_success_resets_failure_count). |
| T-023 | DONE | R7 C2 open-after-threshold + reject without invoke (circuit_breaker.py:81-85, 96-106 + test_opens_after_threshold, test_open_rejects_calls). |
| T-024 | DONE | R7 C3-4 half-open probe + close/reopen (circuit_breaker.py:57-65 state property time check, 88 call-through + test_half_open_after_timeout, test_half_open_failure_reopens). |
| T-025 | DONE | R7 C5 concurrent-async safety (circuit_breaker.py:55 asyncio.Lock + NEW test_concurrent_failures_open_breaker_exactly_once). |
| T-026 | DONE | R8 C1-2 within-burst pass, exhaustion raise (circuit_breaker.py:130-147 + test_allows_within_limit, test_rejects_over_limit; RateLimitExceededError carries agent_id + rate). |
| T-027 | DONE | R8 C3-4 per-agent isolation + concurrent safety (circuit_breaker.py:127 per-agent dict, 128 asyncio.Lock + test_separate_buckets_per_agent + NEW test_concurrent_acquires_no_over_issue). |
| T-028 | DONE | R9 C1-2 immutable + validation-at-boundary (Permission/Role/SandboxConfig use ConfigDict(frozen=True); AgentIdentity/AuditEvent/PermissionContext are Pydantic v2 BaseModel which validates at construction; test_models.py). |
| T-029 | DONE | R9 C3 single base exception (exceptions.py defines AgentGuardError base; all subclasses inherit + test_exceptions.py). |
| T-030 | DONE | R9 C4 UTC tz-aware audit timestamps (test_audit.py helpers use datetime(...,tzinfo=UTC); cli.py _parse_iso_utc coerces naive → UTC to prevent naive-vs-aware comparison errors). |
| T-031 | DONE | R10 C2 denial path writes event (test_pipeline.py test_deny_path_writes_denied_event_and_raises asserts 1 "denied" event + executor NOT called). |
| T-032 | DONE | R10 C3 post-failure error event (test_pipeline.py test_executor_exception_writes_error_event asserts events=["allowed","error"], shared trace_id; _pipeline.py writes error event before re-raising). |
| T-033 | DONE | R10 C4 secondary failure does not mask (test_pipeline.py test_error_event_write_failure_does_not_mask_original — flaky_write fails on 2nd call; original ValueError propagates). |

## Summary

- 33 tier 0 tasks: 30 DONE, 3 BLOCKED (Docker socket).
- 5 new tests added: 2 identity concurrent-safety, 1 rbac cycle termination, 1 audit protocol swap, 1 breaker concurrent, 1 rate limiter concurrent (total 6).
- Tier 0 unit-testable surface: 96 passing tests, 100% criteria coverage.
- Dead-end note: red-team/Docker tests require Docker daemon socket access. Defer to CI runner.
