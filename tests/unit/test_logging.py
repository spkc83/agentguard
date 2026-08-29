"""Tests for process-wide structured-log redaction."""

from __future__ import annotations

from typing import Any

from agentguard._logging import scrub_sensitive_data


def test_scrub_sensitive_data_masks_nested_pii_and_secrets() -> None:
    event = {
        "event": "tool_call",
        "customer": {
            "ssn": "123-45-6789",
            "contacts": ["person@example.com"],
        },
        "api_key": "sk_abcdefghijklmnop",
        "message": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    }

    scrubbed = scrub_sensitive_data(None, "info", event)

    assert scrubbed["customer"]["ssn"] == "XXX-XX-6789"
    assert scrubbed["customer"]["contacts"] == ["p***@example.com"]
    assert scrubbed["api_key"] == "[REDACTED]"
    assert scrubbed["message"] == "[REDACTED]"
    assert "123-45-6789" not in str(scrubbed)
    assert "abcdefghijklmnop" not in str(scrubbed)


def test_scrubber_redacts_non_json_repr_and_never_raises() -> None:
    class _Marker:
        def __repr__(self) -> str:
            return "Marker(ssn=123-45-6789, token=sk_abcdefghijklmnop)"

    marker = _Marker()
    event: dict[str, Any] = {
        "event": "diagnostic",
        "marker": marker,
        "details": "SSN 123-45-6789",
    }

    scrubbed = scrub_sensitive_data(None, "warning", event)

    assert "123-45-6789" not in scrubbed["marker"]
    assert "abcdefghijklmnop" not in scrubbed["marker"]
    assert scrubbed["details"] == "SSN XXX-XX-6789"


def test_scrubber_preserves_structlog_iso_timestamp() -> None:
    timestamp = "2026-08-26T10:55:04.123456Z"

    scrubbed = scrub_sensitive_data(
        None,
        "info",
        {"event": "test", "timestamp": timestamp, "dob": "1980-01-02"},
    )

    assert scrubbed["timestamp"] == timestamp
    assert scrubbed["dob"] == "XX/XX/XXXX"
