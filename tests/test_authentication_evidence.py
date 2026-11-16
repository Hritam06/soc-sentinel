"""Evidence and compatibility tests for structured authentication detections."""

from datetime import datetime, timedelta, timezone

import pytest

from soc_sentinel.core.models import SecurityEvent
from soc_sentinel.detection.rules import (
    detect_authentication,
    detect_authentication_alerts,
)


BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_event(offset, *, source_ip=None, username=None, event_type="login_failure"):
    return SecurityEvent(
        timestamp=BASE + timedelta(minutes=offset),
        source="authentication",
        event_type=event_type,
        source_ip=source_ip,
        username=username,
    )


@pytest.mark.parametrize(
    ("rule_name", "events", "settings"),
    [
        (
            "brute_force_login_attempts",
            [
                make_event(0, source_ip="192.0.2.10"),
                make_event(1, source_ip="192.0.2.10"),
                make_event(2, source_ip="192.0.2.10"),
            ],
            {"brute_force_threshold": 3},
        ),
        (
            "password_spray_attempts",
            [
                make_event(0, source_ip="192.0.2.20", username="admin"),
                make_event(1, source_ip="192.0.2.20", username="alice"),
                make_event(2, source_ip="192.0.2.20", username="bob"),
            ],
            {"password_spray_threshold": 3},
        ),
        (
            "failure_then_success",
            [
                make_event(0, username="operator"),
                make_event(3, username="operator", event_type="login_success"),
            ],
            {},
        ),
        (
            "multi_source_account_targeting",
            [
                make_event(0, source_ip="192.0.2.31", username="admin"),
                make_event(1, source_ip="192.0.2.32", username="admin"),
                make_event(2, source_ip="192.0.2.33", username="admin"),
            ],
            {"multi_source_threshold": 3},
        ),
        (
            "authentication_failure_burst",
            [
                make_event(0, source_ip="192.0.2.41"),
                make_event(0.2, source_ip="192.0.2.42"),
                make_event(0.4, source_ip="192.0.2.43"),
            ],
            {"burst_threshold": 3},
        ),
    ],
)
def test_structured_authentication_detection_has_accurate_evidence(
    rule_name, events, settings
):
    parameters = {
        "brute_force_threshold": 99,
        "password_spray_threshold": 99,
        "multi_source_threshold": 99,
        "burst_threshold": 99,
        "window_minutes": 5,
        "burst_window_minutes": 1,
    }
    parameters.update(settings)

    legacy = detect_authentication(events, **parameters)
    structured = detect_authentication_alerts(events, **parameters)

    assert legacy == [rule_name]
    assert [alert.rule for alert in structured] == legacy

    alert = structured[0]
    assert alert.event_ids
    assert set(alert.event_ids).issubset(
        {event.event_id for event in events}
    )
    assert len(alert.event_ids) == len(set(alert.event_ids))
    assert alert.evidence
    assert all(isinstance(condition, str) and condition for condition in alert.evidence)


def test_structured_authentication_detection_respects_thresholds():
    events = [
        make_event(0, source_ip="192.0.2.50", username="admin"),
        make_event(1, source_ip="192.0.2.50", username="alice"),
    ]

    parameters = {
        "brute_force_threshold": 99,
        "password_spray_threshold": 3,
        "multi_source_threshold": 99,
        "burst_threshold": 99,
        "window_minutes": 5,
        "burst_window_minutes": 1,
    }

    assert detect_authentication(events, **parameters) == []
    assert detect_authentication_alerts(events, **parameters) == []
