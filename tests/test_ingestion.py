from datetime import datetime, timezone

from soc_sentinel.core.models import EventSeverity
from soc_sentinel.ingestion.loader import load_event


def test_load_event():
    raw_event = {
        "timestamp": datetime.now(timezone.utc),
        "source": "authentication",
        "event_type": "login_failure",
        "source_ip": "192.168.1.50",
        "username": "admin",
        "severity": "high",
        "message": "Failed authentication attempt",
    }

    event = load_event(raw_event)

    assert event.source == "authentication"
    assert event.event_type == "login_failure"
    assert event.source_ip == "192.168.1.50"
    assert event.username == "admin"
    assert event.severity == EventSeverity.HIGH
