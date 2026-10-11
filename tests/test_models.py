from datetime import datetime, timezone

import pytest

from soc_sentinel.core.models import EventSeverity, SecurityEvent


def test_security_event_creation():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_failure",
        source_ip="192.168.1.50",
        username="admin",
        severity=EventSeverity.HIGH,
        message="Failed authentication attempt",
    )

    assert event.source == "authentication"
    assert event.event_type == "login_failure"
    assert event.source_ip == "192.168.1.50"
    assert event.username == "admin"
    assert event.severity == EventSeverity.HIGH
    assert event.message == "Failed authentication attempt"


def test_security_event_normalizes_ip_addresses_and_text():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="endpoint",
        event_type="process_start",
        source_ip="2001:0db8:0000:0000:0000:0000:0000:0001",
        protocol=" TCP ",
        action=" EXECUTE ",
        outcome=" SUCCESS ",
    )

    assert event.source_ip == "2001:db8::1"
    assert event.protocol == "tcp"
    assert event.action == "execute"
    assert event.outcome == "success"


def test_security_event_rejects_invalid_ip_address():
    with pytest.raises(ValueError):
        SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source="endpoint",
            event_type="connection_attempt",
            source_ip="not-an-ip",
        )


def test_security_event_rejects_metadata_over_100_fields():
    with pytest.raises(ValueError):
        SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            source="endpoint",
            event_type="process_start",
            metadata={f"field_{index}": index for index in range(101)},
        )


def test_security_event_allows_metadata_with_100_fields():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="endpoint",
        event_type="process_start",
        metadata={f"field_{index}": index for index in range(100)},
    )

    assert len(event.metadata) == 100


def test_security_event_trims_identifiers_without_changing_case():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="endpoint",
        event_type="process_start",
        username=" Alice ",
        host=" WorkStation-A ",
        process_name=" PowerShell.EXE ",
    )

    assert event.username == "Alice"
    assert event.host == "WorkStation-A"
    assert event.process_name == "PowerShell.EXE"


def test_security_event_converts_blank_optional_identifiers_to_none():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="endpoint",
        event_type="process_start",
        username="   ",
        host=" ",
        process_name="",
    )

    assert event.username is None
    assert event.host is None
    assert event.process_name is None
