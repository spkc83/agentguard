---
created: "2026-04-22"
last_edited: "2026-04-22"
---

# Implementation Tracking: Observability (Layer 4)

Build site: context/plans/build-site.md

Brownfield strict-as-built verification.

## Tier 1 Observability — Tasks T-065..T-078

| Task | Status | Notes |
|------|--------|-------|
| T-065 | DONE | R1 C1-2 namespace prefix behavior (tracer.py ATTR_PREFIX logic prepends `agentguard.` for un-prefixed keys; leaves prefixed keys unchanged + test_tracer.py namespace tests). |
| T-066 | DONE | R1 C3 convenience helpers (tracer.py trace_rbac_check/trace_policy_evaluation/trace_tool_call + test_tracer.py verifies attributes populated). |
| T-067 | DONE | R2 C1-2 NoOp fallback on missing SDK or explicit disable (tracer.py lazy OTel import + `enabled` flag; `is_active` False in both cases + test_tracer.py). |
| T-068 | DONE | R2 C3-4 _NoOpSpan silent ops (tracer.py _NoOpSpan implements set_attribute/set_status/record_exception/end as no-op; span() CM yields it when inactive + test_tracer.py). |
| T-069 | DONE | R3 C1-2 no-set_tracer_provider (tracer.py imports trace.get_tracer only; ADR-021 honored + test_tracer.py verifies host-provider honored post-construction). |
| T-070 | DONE | R4 C1-5 replay load + filters (replay.py load reads all JSONL files sorted chronologically; filter supports agent_id exact / action substring / result / time range + test_replay.py). |
| T-071 | DONE | R4 C6 conjunctive composition (replay.py filter applies all supplied criteria + test_replay.py). |
| T-072 | DONE | R5 C1-6 timeline entries (replay.py timeline creates ReplayEntry per event with flags for denied/error/escalated/policy_violation, contiguous zero-based index + test_replay.py). |
| T-073 | DONE | R6 C1-3 summary counts (replay.py summarize returns total_events + by_result + by_agent + by_action + test_replay.py). |
| T-074 | DONE | R7 C1-3 empty-safe + per-result + denial rate (dashboard.py compute handles [] with zero-valued metrics; per-result counts via Counter; denied/total + test_dashboard.py). |
| T-075 | DONE | R7 C4-5 latency percentiles exclude non-positive duration; per-agent denial rate (dashboard.py compute + test_dashboard.py). |
| T-076 | DONE | R7 C6-8 top-actions cap 10, violation trends, time range (dashboard.py compute caps via sorted slice, PolicyViolationTrend carries rule/count/last_failure + test_dashboard.py). |
| T-077 | DONE | R8 C1 indented JSON (dashboard.py to_json uses model_dump_json(indent=2) + test_dashboard.py). |
| T-078 | DONE | R8 C2 Markdown sections (dashboard.py to_markdown renders headline + percentiles + time range + top actions + per-agent + violations + test_dashboard.py). |

## Summary

14/14 observability tasks DONE. 27 tests pass in tests/unit/observability/.
