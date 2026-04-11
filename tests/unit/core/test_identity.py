"""Tests for agentguard.core.identity — agent identity registry."""

from __future__ import annotations

import pytest

from agentguard.core.identity import AgentRegistry
from agentguard.exceptions import IdentityNotFoundError
from agentguard.models import AgentIdentity


class TestAgentRegistry:
    async def test_register_returns_identity(self) -> None:
        registry = AgentRegistry()
        identity = await registry.register(
            name="Credit Analyst Bot",
            roles=["credit-analyst"],
            metadata={"framework": "langgraph"},
        )
        assert isinstance(identity, AgentIdentity)
        assert identity.name == "Credit Analyst Bot"
        assert identity.roles == ["credit-analyst"]
        assert identity.agent_id

    async def test_register_generates_unique_ids(self) -> None:
        registry = AgentRegistry()
        id1 = await registry.register(name="A", roles=[])
        id2 = await registry.register(name="B", roles=[])
        assert id1.agent_id != id2.agent_id

    async def test_resolve_existing(self) -> None:
        registry = AgentRegistry()
        registered = await registry.register(name="Bot", roles=["readonly"])
        resolved = await registry.resolve(registered.agent_id)
        assert resolved.agent_id == registered.agent_id
        assert resolved.name == "Bot"

    async def test_resolve_not_found_raises(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(IdentityNotFoundError) as exc_info:
            await registry.resolve("nonexistent-id")
        assert exc_info.value.agent_id == "nonexistent-id"

    async def test_list_agents_empty(self) -> None:
        registry = AgentRegistry()
        agents = await registry.list_agents()
        assert agents == []

    async def test_list_agents(self) -> None:
        registry = AgentRegistry()
        await registry.register(name="A", roles=["readonly"])
        await registry.register(name="B", roles=["credit-analyst"])
        agents = await registry.list_agents()
        assert len(agents) == 2
        names = {a.name for a in agents}
        assert names == {"A", "B"}

    async def test_register_with_explicit_id(self) -> None:
        registry = AgentRegistry()
        identity = await registry.register(
            name="Explicit",
            roles=["readonly"],
            agent_id="my-custom-id",
        )
        assert identity.agent_id == "my-custom-id"
        resolved = await registry.resolve("my-custom-id")
        assert resolved.name == "Explicit"
