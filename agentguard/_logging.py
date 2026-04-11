"""Structured logging configuration for AgentGuard.

Usage in any module:
    import structlog
    logger = structlog.get_logger()
    logger.info("event_name", key="value")
"""

from __future__ import annotations

import structlog


def configure_logging(*, json_output: bool = False) -> None:
    """Configure structlog for AgentGuard.

    Args:
        json_output: If True, output JSON lines. If False, output human-readable console format.
    """
    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(0),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
