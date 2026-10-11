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
