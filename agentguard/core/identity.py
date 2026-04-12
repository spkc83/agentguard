"""Agent identity registry.

Two registry implementations:
- AgentRegistry: in-memory only (fast, no persistence).
- FileBackedRegistry: persists to a JSON file with atomic writes.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path  # noqa: TC003 — used at runtime in FileBackedRegistry

import structlog

from agentguard.exceptions import DuplicateAgentError, IdentityNotFoundError
from agentguard.models import AgentIdentity

logger = structlog.get_logger()


class AgentRegistry:
    """In-memory agent identity registry."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        name: str,
        roles: list[str],
        metadata: dict[str, str] | None = None,
        agent_id: str | None = None,
    ) -> AgentIdentity:
        """Register a new agent identity.

        Args:
            name: Human-readable agent name.
            roles: List of role names to assign.
            metadata: Optional key-value metadata.
            agent_id: Optional explicit ID. If None, a UUID4 is generated.

        Returns:
            The created AgentIdentity.
        """
        if agent_id is None:
            agent_id = str(uuid.uuid4())

        identity = AgentIdentity(
            agent_id=agent_id,
            name=name,
            roles=roles,
            metadata=metadata or {},
        )

        async with self._lock:
            if agent_id in self._agents:
                raise DuplicateAgentError(agent_id)
            self._agents[agent_id] = identity

        logger.info("agent_registered", agent_id=agent_id, name=name, roles=roles)
        return identity

    async def resolve(self, agent_id: str) -> AgentIdentity:
        """Resolve an agent identity by ID.

        Raises:
            IdentityNotFoundError: If no agent with this ID is registered.
        """
        async with self._lock:
            identity = self._agents.get(agent_id)

        if identity is None:
            raise IdentityNotFoundError(agent_id)

        return identity

    async def list_agents(self) -> list[AgentIdentity]:
        """List all registered agent identities."""
        async with self._lock:
            return list(self._agents.values())


class FileBackedRegistry:
    """Agent identity registry backed by a JSON file.

    Persists agents atomically using write-to-temp + os.replace.
    Loads existing agents from file on construction.

    Args:
        path: Path to the JSON file for persistence.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._registry = AgentRegistry()
        self._lock = asyncio.Lock()
        self._load_sync()

    def _load_sync(self) -> None:
        """Load agents from file into the in-memory registry."""
        if not self._path.exists():
            return
        data = json.loads(self._path.read_text())
        for entry in data:
            identity = AgentIdentity.model_validate(entry)
            self._registry._agents[identity.agent_id] = identity

    async def _persist(self) -> None:
        """Atomically write all agents to the JSON file."""
        agents = await self._registry.list_agents()
        data = [a.model_dump() for a in agents]
        tmp_path = self._path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2, default=str))
        os.replace(tmp_path, self._path)

    async def register(
        self,
        name: str,
        roles: list[str],
        metadata: dict[str, str] | None = None,
        agent_id: str | None = None,
    ) -> AgentIdentity:
        """Register a new agent and persist to file."""
        async with self._lock:
            identity = await self._registry.register(
                name=name, roles=roles, metadata=metadata, agent_id=agent_id
            )
            await self._persist()
            return identity

    async def resolve(self, agent_id: str) -> AgentIdentity:
        """Resolve an agent identity by ID."""
        return await self._registry.resolve(agent_id)

    async def list_agents(self) -> list[AgentIdentity]:
        """List all registered agent identities."""
        return await self._registry.list_agents()
