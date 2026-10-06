from datetime import datetime, timedelta, timezone

from soc_sentinel.core.models import EventSeverity, SecurityEvent
from soc_sentinel.detection.rules import detect, detect_alerts, detect_password_spray


def test_detect_high_severity_login_failure():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_failure",
        source_ip="192.168.1.50",
        username="admin",
        severity=EventSeverity.HIGH,
        message="Failed authentication attempt",
    )

    assert detect(event) == ["high_severity_login_failure"]


def test_ignore_low_severity_login_failure():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_failure",
        severity=EventSeverity.LOW,
    )

    assert detect(event) == []


def test_detect_suspicious_source_ip():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_success",
        source_ip="10.0.0.99",
        severity=EventSeverity.LOW,
    )

    assert detect(event) == ["suspicious_source_ip"]


def test_normal_source_ip_does_not_trigger_suspicious_ip():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_success",
        source_ip="192.168.1.50",
        severity=EventSeverity.LOW,
    )

    assert detect(event) == []


def test_detect_alerts_returns_structured_alert():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_failure",
        source_ip="10.0.0.99",
        severity=EventSeverity.HIGH,
    )

    alerts = detect_alerts(event)

    assert len(alerts) == 2

    rules = {alert.rule for alert in alerts}

    assert "high_severity_login_failure" in rules
    assert "suspicious_source_ip" in rules

    high_alert = next(
        alert for alert in alerts
        if alert.rule == "high_severity_login_failure"
    )

    assert high_alert.severity == "high"
    assert "authentication failure" in high_alert.message



def test_detect_password_spray():
    base = datetime.now(timezone.utc)
    events = [
        SecurityEvent(timestamp=base, source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="admin"),
        SecurityEvent(timestamp=base + timedelta(minutes=1), source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="alice"),
        SecurityEvent(timestamp=base + timedelta(minutes=2), source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="bob"),
    ]

    assert detect_password_spray(events) == ["password_spray_attempts"]


def test_password_spray_requires_distinct_usernames():
    base = datetime.now(timezone.utc)
    events = [
        SecurityEvent(timestamp=base, source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="admin"),
        SecurityEvent(timestamp=base + timedelta(minutes=1), source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="admin"),
        SecurityEvent(timestamp=base + timedelta(minutes=2), source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="admin"),
    ]

    assert detect_password_spray(events) == []


def test_password_spray_respects_time_window():
    base = datetime.now(timezone.utc)
    events = [
        SecurityEvent(timestamp=base, source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="admin"),
        SecurityEvent(timestamp=base + timedelta(minutes=6), source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="alice"),
        SecurityEvent(timestamp=base + timedelta(minutes=7), source="authentication", event_type="login_failure", source_ip="10.0.0.50", username="bob"),
    ]

    assert detect_password_spray(events) == []
