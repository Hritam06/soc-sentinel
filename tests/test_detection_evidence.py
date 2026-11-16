from soc_sentinel.detection.models import DetectionAlert


def test_alert_defaults_to_empty_evidence():
    alert = DetectionAlert(
        rule="test_rule",
        severity="high",
        message="Test alert",
    )
    assert alert.evidence == ()
    assert alert.event_ids == ()


def test_alert_preserves_investigation_evidence():
    alert = DetectionAlert(
        rule="brute_force_login_attempts",
        severity="high",
        message="Repeated login failures detected.",
        evidence=("5 failed logins from 10.0.0.5",),
        event_ids=("event-001", "event-002"),
    )
    assert alert.evidence == ("5 failed logins from 10.0.0.5",)
    assert alert.event_ids == ("event-001", "event-002")
    assert alert.risk_score == 75

def test_alert_manager_merges_structured_evidence_without_duplicates():
    from datetime import datetime, timedelta, timezone

    from soc_sentinel.alerts.manager import AlertManager
    from soc_sentinel.alerts.models import SecurityAlert

    now = datetime.now(timezone.utc)
    evidence_one = {
        "event_id": "event-001",
        "raw_event": {"message": "first source record"},
    }
    evidence_two = {
        "event_id": "event-002",
        "raw_event": {"message": "second source record"},
    }

    manager = AlertManager(window_minutes=15)
    first = SecurityAlert(
        rule_id="AUTH-001",
        rule_name="Brute force",
        severity="high",
        confidence=0.75,
        explanation="Repeated login failures",
        event_ids=("event-001",),
        evidence=(evidence_one,),
        first_seen=now,
        last_seen=now,
    )
    second = SecurityAlert(
        rule_id="AUTH-001",
        rule_name="Brute force",
        severity="high",
        confidence=0.75,
        explanation="Repeated login failures",
        event_ids=("event-002",),
        evidence=(evidence_one, evidence_two),
        first_seen=now + timedelta(minutes=1),
        last_seen=now + timedelta(minutes=1),
    )

    manager.add(first)
    merged = manager.add(second)

    assert merged is first
    assert set(merged.event_ids) == {"event-001", "event-002"}
    assert merged.evidence == (evidence_one, evidence_two)


def test_alert_manager_handles_out_of_order_alert_intervals():
    from datetime import datetime, timedelta, timezone

    from soc_sentinel.alerts.manager import AlertManager
    from soc_sentinel.alerts.models import SecurityAlert

    now = datetime.now(timezone.utc)

    def make_alert(start, end, event_id):
        return SecurityAlert(
            rule_id="AUTH-001",
            rule_name="Brute force",
            severity="high",
            confidence=0.75,
            explanation="Repeated login failures",
            event_ids=(event_id,),
            first_seen=start,
            last_seen=end,
        )

    manager = AlertManager(window_minutes=15)
    later = make_alert(
        now + timedelta(minutes=10),
        now + timedelta(minutes=12),
        "event-later",
    )
    earlier = make_alert(
        now,
        now + timedelta(minutes=2),
        "event-earlier",
    )

    manager.add(later)
    merged = manager.add(earlier)

    assert merged is later
    assert merged.first_seen == now
    assert merged.last_seen == now + timedelta(minutes=12)
    assert set(merged.event_ids) == {"event-earlier", "event-later"}
