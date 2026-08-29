"""Framework-shaped entry points for the optional first-party adapters."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, Mock

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations.a2a_middleware import GovernedA2AClient
from agentguard.integrations.crewai import GovernedCrewAITool
from agentguard.integrations.google_adk import GovernedAdkTool
from agentguard.integrations.langgraph import GovernedLangGraphToolNode
from agentguard.integrations.mcp_middleware import GovernedMcpClient

if TYPE_CHECKING:
    from pathlib import Path


class _LangTool:
    name = "lookup"

    def __init__(self) -> None:
        self.ainvoke = AsyncMock(return_value={"score": 720})


class _CrewTool:
    name = "lookup"
    description = "Look up a record"

    def __init__(self) -> None:
        self._run = Mock(return_value={"score": 720})


class _AdkTool:
    name = "lookup"

    def __init__(self) -> None:
        self.run_async = AsyncMock(return_value={"score": 720})


class _McpSession:
    def __init__(self) -> None:
        self.call_tool = AsyncMock(return_value={"score": 720})


class _A2AClient:
    def __init__(self) -> None:
        self.message_send = AsyncMock(return_value={"accepted": True})


@pytest.fixture
async def _runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "real-adapter-tests-padded-abcdef")
    registry = AgentRegistry()
    engine = RBACEngine(
        roles=[
            Role(
                name="adapter-user",
                permissions=[
                    Permission(action="tool:lookup", resource="public/data", effect="allow"),
                    Permission(action="a2a:send:peer", resource="agent/peer", effect="allow"),
                ],
            )
        ]
    )
    identity = await registry.register(name="Adapter User", roles=["adapter-user"])
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    return identity.agent_id, registry, engine, audit


def _legacy_identity(
    runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> dict[str, Any]:
    agent_id, registry, engine, audit = runtime
    return {
        "agent_id": agent_id,
        "registry": registry,
        "rbac_engine": engine,
        "audit_log": audit,
    }


def _field(message: Any, name: str) -> Any:
    return message[name] if isinstance(message, dict) else getattr(message, name)


def _has_module(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except (ImportError, ModuleNotFoundError):
        return False


async def test_langgraph_messages_state_returns_tool_messages_and_native_denial(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    tool = _LangTool()
    node = GovernedLangGraphToolNode(
        tools=[tool],
        resources={"lookup": "public/data"},
        **_legacy_identity(_runtime),
    )

    allowed = await node.ainvoke(
        {"messages": [{"tool_calls": [{"name": "lookup", "args": {"id": 7}, "id": "c1"}]}]}
    )
    denied = await node.ainvoke(
        {"messages": [{"tool_calls": [{"name": "missing", "args": {}, "id": "c2"}]}]}
    )

    assert set(allowed) == {"messages"}
    assert _field(allowed["messages"][0], "tool_call_id") == "c1"
    assert _field(allowed["messages"][0], "content") == '{"score":720}'
    assert _field(denied["messages"][0], "status") == "error"
    assert "Permission denied" in _field(denied["messages"][0], "content")
    tool.ainvoke.assert_awaited_once_with({"id": 7})


@pytest.mark.skipif(
    not (_has_module("langgraph") and _has_module("langchain_core")),
    reason="requires agentguard[langgraph]",
)
async def test_langgraph_adapter_runs_as_a_real_state_graph_node(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, MessagesState, StateGraph

    node = GovernedLangGraphToolNode(
        tools=[_LangTool()],
        resources={"lookup": "public/data"},
        **_legacy_identity(_runtime),
    )
    graph = StateGraph(MessagesState)
    graph.add_node("governed_tools", node)
    graph.add_edge(START, "governed_tools")
    graph.add_edge("governed_tools", END)
    compiled = graph.compile()

    result = await compiled.ainvoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[{"name": "lookup", "args": {"id": 7}, "id": "graph-call"}],
                )
            ]
        }
    )

    assert result["messages"][-1].tool_call_id == "graph-call"
    assert result["messages"][-1].content == '{"score":720}'


async def test_crewai_sync_run_bridges_from_an_active_event_loop(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    tool = _CrewTool()
    governed = GovernedCrewAITool(
        tool=tool,
        resource="public/data",
        **_legacy_identity(_runtime),
    )

    assert governed._run("applicant", limit=1) == {"score": 720}
    assert governed.description == "Look up a record"
    tool._run.assert_called_once_with("applicant", limit=1)


async def test_crewai_sync_denial_is_raised_before_tool_execution(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    tool = _CrewTool()
    governed = GovernedCrewAITool(
        tool=tool,
        resource="restricted/data",
        **_legacy_identity(_runtime),
    )

    with pytest.raises(PermissionDeniedError):
        governed._run("applicant")
    tool._run.assert_not_called()


async def test_adk_function_callable_uses_governed_arguments(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    tool = _AdkTool()
    governed = GovernedAdkTool(
        tool=tool,
        resource="public/data",
        **_legacy_identity(_runtime),
    )
    assert await governed(applicant_id="A-1") == {"score": 720}
    tool.run_async.assert_awaited_once_with(
        args={"applicant_id": "A-1"},
        tool_context=None,
    )


@pytest.mark.skipif(
    not _has_module("google.adk"),
    reason="requires agentguard[adk]",
)
async def test_adk_function_tool_executes_the_governed_callable(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    governed = GovernedAdkTool(
        tool=_AdkTool(),
        resource="public/data",
        **_legacy_identity(_runtime),
    )
    native = governed.as_function_tool()

    result = await native.run_async(args={"applicant_id": "A-1"}, tool_context=None)

    assert result == {"score": 720}


async def test_mcp_client_session_shape_forwards_runtime_options(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    session = _McpSession()
    client = GovernedMcpClient(
        session=session,
        resources={"lookup": "public/data"},
        **_legacy_identity(_runtime),
    )

    assert await client.call_tool(name="lookup", arguments={"id": 7}, read_timeout_seconds=2) == {
        "score": 720
    }
    session.call_tool.assert_awaited_once_with(
        "lookup",
        {"id": 7},
        read_timeout_seconds=2,
    )


@pytest.mark.skipif(
    not _has_module("mcp"),
    reason="requires agentguard[mcp]",
)
async def test_mcp_adapter_executes_against_real_in_memory_client_session(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    from mcp.server import Server
    from mcp.shared.memory import create_connected_server_and_client_session

    server = Server("agentguard-test")

    from mcp import types

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="lookup",
                description="Lookup",
                inputSchema={"type": "object"},
            )
        ]

    @server.call_tool()
    async def _call_tool(_name: str, _arguments: dict[str, Any]) -> list[types.TextContent]:
        return [types.TextContent(type="text", text="native-mcp-ok")]

    async with create_connected_server_and_client_session(server, raise_exceptions=True) as session:
        client = GovernedMcpClient(
            session=session,
            resources={"lookup": "public/data"},
            **_legacy_identity(_runtime),
        )
        result = await client.call_tool(name="lookup", arguments={"id": 7})

    content = _field(result, "content")
    assert _field(content[0], "text") == "native-mcp-ok"


@pytest.mark.skipif(
    not _has_module("mcp"),
    reason="requires agentguard[mcp]",
)
async def test_mcp_native_session_receives_denial_as_error_result(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    from mcp import types
    from mcp.server import Server
    from mcp.shared.memory import create_connected_server_and_client_session

    server = Server("agentguard-denial-test")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [types.Tool(name="lookup", inputSchema={"type": "object"})]

    @server.call_tool()
    async def _call_tool(_name: str, _arguments: dict[str, Any]) -> list[types.TextContent]:
        return [types.TextContent(type="text", text="must-not-run")]

    async with create_connected_server_and_client_session(server, raise_exceptions=True) as session:
        client = GovernedMcpClient(
            session=session,
            resources={"lookup": "restricted/data"},
            **_legacy_identity(_runtime),
        )
        result = await client.call_tool(name="lookup", arguments={})

    assert result.isError is True
    assert result.content[0].text.startswith("Permission denied")


async def test_a2a_message_send_uses_native_transport_boundary(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    transport = _A2AClient()
    client = GovernedA2AClient(transport=transport, **_legacy_identity(_runtime))

    assert await client.message_send("peer", {"task": "review"}) == {"accepted": True}
    transport.message_send.assert_awaited_once_with("peer", {"task": "review"})


@pytest.mark.skipif(
    not _has_module("langchain_core"),
    reason="requires agentguard[langgraph]",
)
async def test_langgraph_extra_returns_native_tool_message(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    from langchain_core.messages import ToolMessage

    node = GovernedLangGraphToolNode(
        tools=[_LangTool()],
        resources={"lookup": "public/data"},
        **_legacy_identity(_runtime),
    )
    result = await node.ainvoke(
        {"messages": [{"tool_calls": [{"name": "lookup", "args": {}, "id": "c1"}]}]}
    )

    assert isinstance(result["messages"][0], ToolMessage)


@pytest.mark.skipif(
    not _has_module("crewai"),
    reason="requires agentguard[crewai]",
)
def test_crewai_extra_exposes_native_base_tool(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    from crewai import Agent
    from crewai.tools import BaseTool

    governed = GovernedCrewAITool(
        tool=_CrewTool(),
        resource="public/data",
        **_legacy_identity(_runtime),
    )

    assert isinstance(governed, BaseTool)
    assert governed.to_structured_tool().name == "lookup"
    agent = Agent(
        role="deterministic test agent",
        goal="exercise a governed tool",
        backstory="no language model is used by this wiring check",
        tools=[governed],
        allow_delegation=False,
    )
    assert governed in agent.tools
    assert governed.run("applicant") == {"score": 720}


async def test_crewai_sync_run_rejects_resource_kwarg(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    """The sync bridge must hit the same ``_resource`` guard as ``arun``.

    ``_run`` is exactly what CrewAI's inherited native ``BaseTool.run()``
    delegates to, so this covers the native path without depending on how a
    given CrewAI release wraps exceptions.
    """
    tool = _CrewTool()
    governed = GovernedCrewAITool(
        tool=tool,
        resource="public/data",
        **_legacy_identity(_runtime),
    )

    with pytest.raises(TypeError, match="_resource"):
        governed._run("applicant", _resource="admin/secrets")
    tool._run.assert_not_called()


@pytest.mark.skipif(
    not _has_module("google.adk"),
    reason="requires agentguard[adk]",
)
def test_adk_extra_builds_native_function_tool(
    _runtime: tuple[str, AgentRegistry, RBACEngine, AppendOnlyAuditLog],
) -> None:
    from google.adk.tools import FunctionTool

    governed = GovernedAdkTool(
        tool=_AdkTool(),
        resource="public/data",
        **_legacy_identity(_runtime),
    )

    assert isinstance(governed.as_function_tool(), FunctionTool)
