"""Agent identity registry.

In-memory registry for v0.1. Stores AgentIdentity instances keyed by agent_id.
Thread-safe via asyncio.Lock. File-backed persistence planned for v0.2.
"""

from __future__ import annotations

import asyncio
import uuid

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
