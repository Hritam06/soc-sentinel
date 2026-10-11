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


def test_brute_force_includes_exact_window_boundary():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        SecurityEvent(
            timestamp=base + timedelta(minutes=offset),
            source="authentication",
            event_type="login_failure",
            source_ip="192.168.1.50",
            username="admin",
            severity=EventSeverity.HIGH,
        )
        for offset in (0, 2, 5)
    ]

    assert detect_brute_force(events, threshold=3, window_minutes=5) == [
        "brute_force_login_attempts"
    ]


def test_brute_force_rejects_invalid_threshold_or_window():
    events = [
        make_event("192.168.1.50", 0),
        make_event("192.168.1.50", 1),
        make_event("192.168.1.50", 2),
    ]

    assert detect_brute_force(events, threshold=0) == []
    assert detect_brute_force(events, window_minutes=0) == []


def test_brute_force_ignores_events_without_source_ip():
    events = [
        make_event("192.168.1.50", 0),
        make_event("192.168.1.50", 1),
        SecurityEvent(
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=2),
            source="authentication",
            event_type="login_failure",
            username="admin",
            severity=EventSeverity.HIGH,
        ),
    ]

    assert detect_brute_force(events, threshold=3) == []


def test_brute_force_handles_unsorted_events():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        SecurityEvent(
            timestamp=base + timedelta(minutes=offset),
            source="authentication",
            event_type="login_failure",
            source_ip="192.168.1.50",
            username="admin",
            severity=EventSeverity.HIGH,
        )
        for offset in (2, 0, 1)
    ]

    assert detect_brute_force(events, threshold=3, window_minutes=5) == [
        "brute_force_login_attempts"
    ]


def test_non_login_events_do_not_count_toward_brute_force():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        SecurityEvent(
            timestamp=base + timedelta(minutes=offset),
            source="authentication",
            event_type=event_type,
            source_ip="192.168.1.50",
            username="admin",
            severity=EventSeverity.HIGH,
        )
        for offset, event_type in (
            (0, "login_failure"),
            (1, "login_success"),
            (2, "login_failure"),
        )
    ]

    assert detect_brute_force(events, threshold=3, window_minutes=5) == []
