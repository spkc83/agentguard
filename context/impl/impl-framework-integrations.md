---
created: "2026-04-22"
last_edited: "2026-04-22"
---

# Implementation Tracking: Framework Integrations

Build site: context/plans/build-site.md

Brownfield strict-as-built verification.

## Tier 2 Integrations — Tasks T-102..T-120

| Task | Status | Notes |
|------|--------|-------|
| T-102 | DONE | R1 C1 identity-not-found short-circuit with no event (_pipeline.py run_governed: registry.resolve raises before audit.write; test_pipeline.py + no-event path observable). |
| T-103 | DONE | R1 C2 RBAC-deny: denied event + PermissionDeniedError before executor (_pipeline.py + test_deny_path_writes_denied_event_and_raises). |
| T-104 | DONE | R1 C3 RBAC-grant: allowed event before executor (_pipeline.py + test_success_path_writes_one_allowed_event asserts 1 "allowed" event). |
| T-105 | DONE | R1 C4-5 executor exception: error event + re-raise; secondary failure does not mask original (_pipeline.py + test_executor_exception_writes_error_event, test_error_event_write_failure_does_not_mask_original). |
| T-106 | DONE | R1 C6-7 optional breaker + tracer (_pipeline.py run_governed accepts breaker=None and tracer=None defaults + test_tracer_invoked_when_provided). |
| T-107 | DONE | R1 C8 pre/post events share trace_id (test_pipeline.py test_executor_exception_writes_error_event asserts events[0].trace_id == events[1].trace_id). |
| T-108 | DONE | R2 C1-3 MCP duck-typed + forward + RBAC-deny (mcp_middleware.py GovernedMcpClient delegates call_tool; test_mcp_middleware.py). |
| T-109 | DONE | R2 C4 MCP session raise → error event (test_mcp_middleware.py covers error path through shared pipeline). |
| T-110 | DONE | R3 C1 A2A duck-typed transport (a2a_middleware.py + test_a2a_middleware.py). |
| T-111 | DONE | R3 C2 A2A action/resource encoding (a2a_middleware.py encodes `a2a:send:<target>` + `agent/<target>` + test_a2a_middleware.py). |
| T-112 | DONE | R3 C3-4 A2A denied send + transport failure (test_a2a_middleware.py). |
| T-113 | DONE | R4 C1-2 LangGraph duck-typed tools + unknown-tool KeyError (langgraph.py GovernedLangGraphToolNode dict lookup; test_langgraph.py). |
| T-114 | DONE | R4 C3-4 LangGraph success + failure paths (test_langgraph.py). |
| T-115 | DONE | R5 C1-2 CrewAI duck-typed sync tool + default/per-call resource (crewai.py GovernedCrewAITool; test_crewai.py). |
| T-116 | DONE | R5 C3-5 CrewAI args forwarding + name attribute + failure (test_crewai.py). |
| T-117 | DONE | R6 C1-4 ADK async run(args, tool_context) + resource override + ctx forwarding + failure (google_adk.py GovernedAdkTool; test_google_adk.py). |
| T-118 | DONE | R7 C1-2 tracer optional zero-overhead + single-span when supplied (_pipeline.py span_cm wrapper; test_tracer_invoked_when_provided asserts exactly one span_calls entry). |
| T-119 | DONE | R7 C3 span attributes (_pipeline.py passes agent_id/action/resource/trace_id; test_tracer_invoked_when_provided asserts attrs["action"]=="tool:test", attrs["resource"]=="allowed/x"). |
| T-120 | DONE | R8 C1-2 adapters importable without target framework + private pipeline helper (integrations/__init__.py re-exports 5 adapters; _pipeline.py leading-underscore; no framework import at module level — verified by running tests without LangGraph/CrewAI/ADK installed). |

## Summary

19/19 integration tasks DONE via existing tests in tests/unit/integrations/ + tests/unit/test_mcp_middleware.py (83 tests pass across Tier 2).
