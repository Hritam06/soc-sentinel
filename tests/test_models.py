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

def test_security_event_extended_fields():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="endpoint",
        event_type="process_start",
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        source_port=443,
        destination_port=8443,
        protocol="tcp",
        username="admin",
        host="server-01",
        process_name="powershell.exe",
        action="execute",
        outcome="success",
        severity=EventSeverity.MEDIUM,
        message="Process started",
    )

    assert event.destination_ip == "10.0.0.20"
    assert event.source_port == 443
    assert event.destination_port == 8443
    assert event.protocol == "tcp"
    assert event.host == "server-01"
    assert event.process_name == "powershell.exe"
    assert event.action == "execute"
    assert event.outcome == "success"
