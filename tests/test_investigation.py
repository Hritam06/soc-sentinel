from datetime import datetime, timezone

from soc_sentinel.core.models import EventSeverity, SecurityEvent
from soc_sentinel.investigation.analyzer import analyze


def test_analyze_alert():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_failure",
        source_ip="192.168.1.50",
        username="admin",
        severity=EventSeverity.HIGH,
        message="Failed authentication attempt",
    )

    result = analyze(event, ["high_severity_login_failure"])

    assert result["risk"] == "high"
    assert result["source_ip"] == "192.168.1.50"
    assert "high_severity_login_failure" in result["alerts"]


def test_analyze_without_alert():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_success",
        severity=EventSeverity.LOW,
    )

    result = analyze(event, [])

    assert result["risk"] == "low"
    assert result["alerts"] == []

def test_analyze_preserves_event_evidence():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_failure",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.10",
        username="admin",
        host="server-01",
        process_name="sshd",
        action="login",
        outcome="failure",
        severity=EventSeverity.HIGH,
        message="Failed authentication attempt",
    )

    result = analyze(event, ["high_severity_login_failure"])
    evidence = result["evidence"]

    assert evidence["event_type"] == "login_failure"
    assert evidence["source_ip"] == "192.168.1.50"
    assert evidence["destination_ip"] == "10.0.0.10"
    assert evidence["username"] == "admin"
    assert evidence["host"] == "server-01"
    assert evidence["process_name"] == "sshd"
    assert evidence["action"] == "login"
    assert evidence["outcome"] == "failure"
    assert evidence["message"] == "Failed authentication attempt"


# Risk scoring regression tests
import pytest

from soc_sentinel.investigation.analyzer import calculate_risk_score, risk_level


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (EventSeverity.LOW, 10),
        (EventSeverity.MEDIUM, 30),
        (EventSeverity.HIGH, 60),
        (EventSeverity.CRITICAL, 90),
    ],
)
def test_calculate_risk_score_without_alerts(severity, expected):
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="test",
        event_type="test_event",
        severity=severity,
    )
    assert calculate_risk_score(event, []) == expected


@pytest.mark.parametrize(
    ("severity", "alert_count", "expected"),
    [
        (EventSeverity.LOW, 2, 30),
        (EventSeverity.MEDIUM, 1, 40),
        (EventSeverity.HIGH, 2, 80),
        (EventSeverity.CRITICAL, 1, 100),
        (EventSeverity.CRITICAL, 10, 100),
        (EventSeverity.LOW, 10, 50),
    ],
)
def test_calculate_risk_score_alert_bonus_and_cap(severity, alert_count, expected):
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="test",
        event_type="test_event",
        severity=severity,
    )
    assert calculate_risk_score(event, ["test_alert"] * alert_count) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "low"),
        (29, "low"),
        (30, "medium"),
        (59, "medium"),
        (60, "high"),
        (79, "high"),
        (80, "critical"),
        (100, "critical"),
    ],
)
def test_risk_level_boundaries(score, expected):
    assert risk_level(score) == expected
