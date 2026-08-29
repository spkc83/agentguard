"""Structured logging configuration for AgentGuard.

Usage in any module:
    import structlog
    logger = structlog.get_logger()
    logger.info("event_name", key="value")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from agentguard.guardrails import redact_evidence

if TYPE_CHECKING:
    from collections.abc import MutableMapping


def scrub_sensitive_data(
    _logger: Any,
    _method_name: str,
    event_dict: MutableMapping[str, Any],
) -> dict[str, Any]:
    """Mask PII and secrets without allowing an unusual log value to break logging."""

    return {
        key: value if key == "timestamp" else _scrub_value(value, field_name=key)
        for key, value in event_dict.items()
    }


def _scrub_value(value: Any, *, field_name: str = "") -> Any:
    if _is_secret_field(field_name):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {key: _scrub_value(item, field_name=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(item) for item in value)
    try:
        return redact_evidence(value)
    except (TypeError, ValueError):
        try:
            rendered = repr(value)
        except Exception:
            rendered = f"<{type(value).__name__}>"
        return redact_evidence(rendered)


def _is_secret_field(field_name: str) -> bool:
    if not field_name:
        return False
    probe = redact_evidence({field_name: "probe"})
    return isinstance(probe, dict) and probe.get(field_name) == "[REDACTED]"


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
        scrub_sensitive_data,
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
