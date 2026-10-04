from datetime import datetime, timezone

from soc_sentinel.core.models import EventSeverity, SecurityEvent
from soc_sentinel.reporting.report import build_report


def test_build_incident_report():
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source="authentication",
        event_type="login_failure",
        source_ip="192.168.1.50",
        username="admin",
        severity=EventSeverity.HIGH,
        message="Failed authentication attempt",
    )

    investigation = {
        "risk": "high",
        "alerts": ["high_severity_login_failure"],
        "recommendation": "Investigate repeated authentication failures and verify the account.",
    }

    report = build_report(event, investigation)

    assert "SOC INCIDENT REPORT" in report
    assert "login_failure" in report
    assert "192.168.1.50" in report
    assert "high_severity_login_failure" in report
    assert "Risk: high" in report
