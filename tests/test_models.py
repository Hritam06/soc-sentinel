from datetime import datetime, timezone

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


def test_security_event_serialization():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_failure",
        severity=EventSeverity.HIGH,
        message="Failed authentication attempt",
    )

    data = event.model_dump()

    assert data["source"] == "authentication"
    assert data["event_type"] == "login_failure"
    assert data["severity"] == EventSeverity.HIGH
