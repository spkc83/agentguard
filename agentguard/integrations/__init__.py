"""AgentGuard framework integrations.

Public API:
    from agentguard.integrations import GovernedMcpClient
    from agentguard.integrations import GovernedLangGraphToolNode
    from agentguard.integrations import GovernedCrewAITool
    from agentguard.integrations import GovernedAdkTool
    from agentguard.integrations import GovernedA2AClient
    from agentguard.integrations import ResourceResolver, canonicalize_resource

Every adapter derives the RBAC resource from a :data:`ResourceResolver`
configured at construction time; none of them accept a resource from the
governed agent at call time. Each adapter delegates runtime enforcement to
:class:`agentguard.guardrails.GovernanceKernel`; the private
:mod:`agentguard.integrations._pipeline` module only preserves legacy imports
and constructor assembly.
"""

from agentguard.integrations._pipeline import (
    UNRESOLVED_RESOURCE,
    ResourceResolver,
    canonicalize_resource,
)
from agentguard.integrations.a2a_middleware import GovernedA2AClient
from agentguard.integrations.crewai import GovernedCrewAITool
from agentguard.integrations.google_adk import GovernedAdkTool
from agentguard.integrations.langgraph import GovernedLangGraphToolNode
from agentguard.integrations.mcp_middleware import GovernedMcpClient

__all__ = [
    "UNRESOLVED_RESOURCE",
    "GovernedA2AClient",
    "GovernedAdkTool",
    "GovernedCrewAITool",
    "GovernedLangGraphToolNode",
    "GovernedMcpClient",
    "ResourceResolver",
    "canonicalize_resource",
]
