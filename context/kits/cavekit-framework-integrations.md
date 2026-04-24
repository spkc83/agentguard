---
created: "2026-04-19"
last_edited: "2026-04-19"
complexity: quick
---

# Cavekit: Framework Integrations (Adapters)

## Scope
This kit covers the adapters that interpose AgentGuard's governance pipeline between the agent application and the tool/transport surfaces of the supported frameworks: Model Context Protocol (MCP), Agent-to-Agent (A2A), LangGraph, CrewAI, and Google Agent Development Kit (ADK). All adapters share one governance pipeline (per ADR-020) so behavior is identical regardless of framework. Adapters do not depend on their target frameworks at import time — protocols capture only the minimum surface needed (per ADR-017).

## Requirements

### R1: Shared Governance Pipeline for All Adapters
**Description:** Every adapter routes through one shared pipeline that applies, in order: agent identity resolution, RBAC permission check, pre-execution audit event, optional circuit breaker, optional OpenTelemetry span, executor invocation, and — on executor exception — a follow-up error audit event before the exception propagates (per ADR-004 and ADR-020). The pipeline is private and adapters cannot bypass it.
**Acceptance Criteria:**
- [ ] When the agent is not registered, the pipeline raises an identity-not-found error and writes no audit event.
- [ ] When RBAC denies the action, the pipeline writes a denial audit event and raises a permission-denied error before invoking the executor.
- [ ] When RBAC grants the action, the pipeline writes an "allowed" audit event before invoking the executor.
- [ ] When the executor raises, the pipeline writes an "error" audit event with a measured duration and re-raises the original exception.
- [ ] When writing the post-failure error event itself raises, the original execution exception still propagates (matching cavekit-security-runtime.md R10).
- [ ] When a circuit breaker is configured, the executor is invoked through it; when omitted, the executor is invoked directly.
- [ ] When a tracer is configured, the entire pipeline is wrapped in a single span; when omitted, no span is opened.
- [ ] Every audit event written by the pipeline shares a common trace identifier so pre and post events are correlatable.

### R2: MCP Tool Call Adapter
**Description:** A governed MCP client wraps any object exposing an asynchronous tool-call method and intercepts every call with the shared governance pipeline. The action is encoded as `tool:<tool_name>` for RBAC purposes, and an RBAC resource pattern can be supplied per call.
**Acceptance Criteria:**
- [ ] A governed MCP client accepts any session-like object with an asynchronous tool-call method (no hard dependency on the official MCP SDK at import time).
- [ ] An invocation with arguments is forwarded to the underlying session unchanged when RBAC grants the action.
- [ ] An invocation denied by RBAC produces a denial audit event and raises a permission-denied error without contacting the underlying session.
- [ ] An invocation that raises in the underlying session produces an error audit event before the exception propagates.

### R3: Agent-to-Agent Messaging Adapter
**Description:** A governed A2A client wraps any transport exposing an asynchronous send method. Inter-agent messages are governed at the send boundary; the action is encoded as `a2a:send:<target_agent>` and the resource as `agent/<target_agent>` so RBAC can express which agents may communicate with which.
**Acceptance Criteria:**
- [ ] A governed A2A client accepts any transport object with an asynchronous send method.
- [ ] The RBAC action and resource for a send call encode the target agent so policies can grant or deny specific agent-to-agent relationships.
- [ ] A denied send produces a denial audit event and raises a permission-denied error without invoking the transport.
- [ ] A transport-side failure produces an error audit event and re-raises.

### R4: LangGraph Tool Node Adapter
**Description:** A governed LangGraph tool node accepts a list of LangChain-style tools (each carrying a name and an asynchronous invoke method) and exposes an asynchronous invocation API that selects a tool by name and routes execution through the shared pipeline.
**Acceptance Criteria:**
- [ ] The node accepts any object with a name attribute and an asynchronous invoke method (no hard dependency on LangGraph or LangChain at import time).
- [ ] Calling the node with a tool name not present in its registry raises a key error before any pipeline activity.
- [ ] A successful invocation returns the underlying tool's result unchanged.
- [ ] A failing invocation produces an error audit event and re-raises.

### R5: CrewAI Tool Adapter
**Description:** A governed CrewAI tool wraps a CrewAI-style tool (carrying a name and a synchronous run method) and exposes an asynchronous run API. The adapter accepts a default RBAC resource at construction time and allows per-call override of the resource.
**Acceptance Criteria:**
- [ ] The adapter accepts any object with a name attribute and a synchronous run method (no hard dependency on the CrewAI package at import time).
- [ ] A default RBAC resource may be set at construction; per-call invocation may override it through a documented keyword.
- [ ] Positional and keyword arguments (other than the resource override) are forwarded to the underlying tool.
- [ ] The adapter exposes the wrapped tool's name as a public attribute.
- [ ] A failing tool invocation produces an error audit event and re-raises.

### R6: Google ADK Tool Adapter
**Description:** A governed Google ADK tool wraps an ADK-style tool (carrying a name and an asynchronous run method that takes args and a tool context) and exposes an asynchronous run API matching the ADK calling convention. The adapter accepts a default RBAC resource and allows per-call override.
**Acceptance Criteria:**
- [ ] The adapter accepts any object with a name attribute and an asynchronous run method taking keyword args and a tool context (no hard dependency on the ADK package at import time).
- [ ] A default RBAC resource may be set at construction; per-call invocation may override it.
- [ ] The ADK tool context object is forwarded to the underlying tool unchanged.
- [ ] A failing ADK tool invocation produces an error audit event and re-raises.

### R7: Optional OpenTelemetry Span Wrapping
**Description:** Every adapter accepts an optional tracer at construction. When supplied, the entire pipeline executes inside a single span named `agentguard.tool_call` with the agent identifier, action, resource, and trace identifier as span attributes (consistent with cavekit-observability.md R1). When the tracer is omitted, no span is opened.
**Acceptance Criteria:**
- [ ] When no tracer is supplied, the adapter performs no tracing-related operations and incurs no tracing overhead.
- [ ] When a tracer is supplied, every governed call produces exactly one span covering the full pipeline.
- [ ] The span attributes include the agent identifier, the action, the resource, and the pipeline trace identifier.

### R8: Stable Public Adapter API
**Description:** The five governed wrappers (MCP, A2A, LangGraph, CrewAI, ADK) and their constructor signatures are the stable public API of this layer (per the v1.0 stability contract in ARCHITECTURE.md). The shared pipeline helper is intentionally private and is not part of the public API.
**Acceptance Criteria:**
- [ ] Each adapter is importable from the package's integrations module without importing its target framework.
- [ ] The pipeline helper is named with a leading underscore to mark it private; user-facing documentation directs callers to the adapters, not the helper.

## Out of Scope
- The runtime primitives the adapters consume (identity registry, RBAC engine, audit log, circuit breaker) — see cavekit-security-runtime.md.
- Compliance evaluation, HITL escalation, and formal verification — see cavekit-compliance-engine.md.
- Domain-specific tools wrapped by adapters (e.g., a credit-decisioning tool exposed via LangGraph) — see cavekit-finance-credit-risk.md.
- Tracer construction, exporters, and dashboards — see cavekit-observability.md.
- Adapters for frameworks not yet supported (Autogen, Swarm, Atomic Agents are mentioned in ADR-020 as expected future work but not implemented in v1.0.0).
- TypeScript/JavaScript bindings (mentioned in ADR-001 as v1.1+ future work).

## Cross-References
- See also: cavekit-security-runtime.md (provides the identity registry, RBAC engine, audit log, and circuit breaker that the pipeline composes)
- See also: cavekit-observability.md (provides the optional tracer adapters accept)

## Source Traceability
- R1 satisfied by: agentguard/integrations/_pipeline.py (run_governed) + tests/unit/integrations/test_pipeline.py
- R2 satisfied by: agentguard/integrations/mcp_middleware.py + tests/unit/test_mcp_middleware.py
- R3 satisfied by: agentguard/integrations/a2a_middleware.py + tests/unit/integrations/test_a2a_middleware.py
- R4 satisfied by: agentguard/integrations/langgraph.py + tests/unit/integrations/test_langgraph.py
- R5 satisfied by: agentguard/integrations/crewai.py + tests/unit/integrations/test_crewai.py
- R6 satisfied by: agentguard/integrations/google_adk.py + tests/unit/integrations/test_google_adk.py
- R7 satisfied by: agentguard/integrations/_pipeline.py (tracer span_cm) + each adapter's tracer constructor parameter + tests/unit/integrations/test_pipeline.py
- R8 satisfied by: agentguard/integrations/_pipeline.py (private module) + agentguard/integrations/{mcp_middleware,a2a_middleware,langgraph,crewai,google_adk}.py (public wrappers)

## Changelog
- 2026-04-19: Initial draft, reverse-engineered from v1.0.0 codebase.
