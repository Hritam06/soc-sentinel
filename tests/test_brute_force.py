from datetime import datetime, timedelta, timezone

from soc_sentinel.core.models import EventSeverity, SecurityEvent
from soc_sentinel.detection.rules import detect_brute_force


def make_event(source_ip: str, offset_minutes: int = 0) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc) + timedelta(minutes=offset_minutes),
        source="authentication",
        event_type="login_failure",
        source_ip=source_ip,
        username="admin",
        severity=EventSeverity.HIGH,
        message="Failed authentication attempt",
    )


def test_detect_brute_force():
    events = [
        make_event("192.168.1.50", 0),
        make_event("192.168.1.50", 1),
        make_event("192.168.1.50", 2),
    ]

    alerts = detect_brute_force(events, threshold=3)

    assert alerts == ["brute_force_login_attempts"]


def test_no_brute_force_below_threshold():
    events = [
        make_event("192.168.1.50", 0),
        make_event("192.168.1.50", 1),
    ]

    alerts = detect_brute_force(events, threshold=3)

    assert alerts == []


def test_no_brute_force_outside_window():
    events = [
        make_event("192.168.1.50", 0),
        make_event("192.168.1.50", 6),
        make_event("192.168.1.50", 12),
    ]

    alerts = detect_brute_force(events, threshold=3)

    assert alerts == []


def test_different_ips_do_not_trigger():
    events = [
        make_event("192.168.1.50", 0),
        make_event("192.168.1.51", 1),
        make_event("192.168.1.52", 2),
    ]

    alerts = detect_brute_force(events, threshold=3)

    assert alerts == []
