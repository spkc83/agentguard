"""Tests for agentguard.core.identity.FileBackedRegistry — persistent agent registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from agentguard.core.identity import FileBackedRegistry
from agentguard.exceptions import DuplicateAgentError, IdentityNotFoundError

if TYPE_CHECKING:
    from pathlib import Path


class TestFileBackedRegistry:
    async def test_register_persists_to_file(self, tmp_path: Path) -> None:
        registry = FileBackedRegistry(path=tmp_path / "agents.json")
        await registry.register(name="Bot A", roles=["readonly"])
        assert (tmp_path / "agents.json").exists()

    async def test_survives_restart(self, tmp_path: Path) -> None:
        path = tmp_path / "agents.json"
        r1 = FileBackedRegistry(path=path)
        identity = await r1.register(name="Bot", roles=["credit-analyst"])

        r2 = FileBackedRegistry(path=path)
        resolved = await r2.resolve(identity.agent_id)
        assert resolved.name == "Bot"
        assert resolved.roles == ["credit-analyst"]

    async def test_list_agents_after_restart(self, tmp_path: Path) -> None:
        path = tmp_path / "agents.json"
        r1 = FileBackedRegistry(path=path)
        await r1.register(name="A", roles=["readonly"])
        await r1.register(name="B", roles=["credit-analyst"])

        r2 = FileBackedRegistry(path=path)
        agents = await r2.list_agents()
        assert len(agents) == 2

    async def test_duplicate_raises(self, tmp_path: Path) -> None:
        registry = FileBackedRegistry(path=tmp_path / "agents.json")
        await registry.register(name="Bot", roles=[], agent_id="dup")
        with pytest.raises(DuplicateAgentError):
            await registry.register(name="Bot2", roles=[], agent_id="dup")

    async def test_resolve_not_found_raises(self, tmp_path: Path) -> None:
        registry = FileBackedRegistry(path=tmp_path / "agents.json")
        with pytest.raises(IdentityNotFoundError):
            await registry.resolve("nonexistent")

    async def test_empty_file_on_init(self, tmp_path: Path) -> None:
        registry = FileBackedRegistry(path=tmp_path / "agents.json")
        agents = await registry.list_agents()
        assert agents == []
