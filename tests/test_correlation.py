from datetime import datetime, timedelta, timezone

from soc_sentinel.core.models import SecurityEvent
from soc_sentinel.investigation.correlation import correlate_login_failures


def make_event(
    offset_minutes: int,
    source_ip: str = "192.168.1.50",
    event_id: str | None = None,
    event_type: str = "login_failure",
    username: str = "admin",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc)
        + timedelta(minutes=offset_minutes),
        source="authentication",
        event_type=event_type,
        source_ip=source_ip,
        username=username,
    )


def test_correlates_login_failures_and_preserves_evidence():
    events = [
        make_event(2, event_id="event-2"),
        make_event(0, event_id="event-1"),
        make_event(5, event_id="event-3"),
    ]

    groups = correlate_login_failures(events, threshold=3, window_minutes=5)

    assert len(groups) == 1
    group = groups[0]
    assert group["correlation_type"] == "brute_force_login_attempts"
    assert group["source_ip"] == "192.168.1.50"
    assert group["event_count"] == 3
    assert [event["event_id"] for event in group["events"]] == [
        "event-1",
        "event-2",
        "event-3",
    ]
    assert group["start_time"] == "2026-01-01T00:00:00+00:00"
    assert group["end_time"] == "2026-01-01T00:05:00+00:00"


def test_correlates_multiple_source_ips_separately():
    events = [
        make_event(0, "192.168.1.50"),
        make_event(1, "192.168.1.50"),
        make_event(2, "192.168.1.50"),
        make_event(0, "192.168.1.51"),
        make_event(1, "192.168.1.51"),
        make_event(2, "192.168.1.51"),
    ]

    groups = correlate_login_failures(events, threshold=3)

    assert len(groups) == 2
    assert {group["source_ip"] for group in groups} == {
        "192.168.1.50",
        "192.168.1.51",
    }


def test_missing_event_ids_remain_none():
    groups = correlate_login_failures([make_event(i) for i in range(3)])

    assert groups
    assert all(event["event_id"] is None for event in groups[0]["events"])


def test_non_login_events_do_not_count():
    events = [
        make_event(0),
        make_event(1, event_type="login_success"),
        make_event(2),
    ]

    assert correlate_login_failures(events, threshold=3) == []


def test_events_outside_window_do_not_correlate():
    events = [make_event(0), make_event(6), make_event(12)]

    assert correlate_login_failures(events, threshold=3, window_minutes=5) == []


def test_events_without_source_ip_are_ignored():
    events = [
        make_event(0, source_ip="192.168.1.50"),
        make_event(1, source_ip="192.168.1.50"),
        SecurityEvent(
            timestamp=datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc),
            source="authentication",
            event_type="login_failure",
            username="admin",
        ),
    ]

    assert correlate_login_failures(events, threshold=3) == []


def test_invalid_threshold_or_window_returns_no_groups():
    events = [make_event(i) for i in range(3)]

    assert correlate_login_failures(events, threshold=0) == []
    assert correlate_login_failures(events, window_minutes=0) == []


def test_overlapping_windows_are_returned_deterministically():
    events = [make_event(i, event_id=f"event-{i}") for i in range(4)]

    groups = correlate_login_failures(events, threshold=3, window_minutes=2)

    assert len(groups) == 2
    assert [group["event_count"] for group in groups] == [3, 3]
    assert [
        [event["event_id"] for event in group["events"]]
        for group in groups
    ] == [
        ["event-0", "event-1", "event-2"],
        ["event-1", "event-2", "event-3"],
    ]
