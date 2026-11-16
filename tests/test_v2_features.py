import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from soc_sentinel.core.models import SecurityEvent, EventCategory
from soc_sentinel.ingestion.loader import load_event, load_events
from soc_sentinel.detection.rules import (
    detect_authentication,
    detect_port_scan,
    detect_connection_fanout,
    detect_suspicious_dns,
)
from soc_sentinel.investigation.correlation import correlate_security_events
from soc_sentinel.alerts.models import SecurityAlert, AlertStatus
from soc_sentinel.alerts.manager import AlertManager
from soc_sentinel.investigation.risk import assess_risk
from soc_sentinel.reporting.v2_report import build_json_report, build_html_report
from soc_sentinel.evaluation.metrics import calculate_metrics, evaluate_rules


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(event_id, event_type, **kwargs):
    return SecurityEvent(
        event_id=event_id,
        timestamp=NOW + timedelta(seconds=kwargs.pop("seconds", 0)),
        source="test",
        event_type=event_type,
        **kwargs,
    )


def test_ingestion_preserves_original_event_and_assigns_id():
    raw = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "auth",
        "event_type": "login_failure",
        "username": "alice",
    }
    loaded = load_event(raw)
    assert loaded.event_id
    assert loaded.raw_event["username"] == "alice"


def test_ingestion_preserves_source_provenance():
    raw = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "auth",
        "event_type": "login_failure",
        "source_event_id": "vendor-event-42",
        "original_event_reference": "auth-log:line:42",
        "username": "alice",
    }

    loaded = load_event(raw)

    assert loaded.event_id
    assert loaded.original_source_id == "vendor-event-42"
    assert loaded.original_event_reference == "auth-log:line:42"
    assert loaded.raw_event == raw
    assert loaded.parser_version == "1.0.0"
    assert loaded.schema_version == "1.0.0"
    assert loaded.ingestion_timestamp.tzinfo == timezone.utc


def test_ingestion_preserves_canonical_source_reference():
    raw = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "auth",
        "event_type": "login_failure",
        "source_event_id": "vendor-event-42",
        "original_source_id": "canonical-source-99",
        "original_event_reference": "auth-log:line:99",
    }

    loaded = load_event(raw)

    assert loaded.original_source_id == "canonical-source-99"
    assert loaded.original_event_reference == "auth-log:line:99"
    assert loaded.raw_event == raw


def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        event("bad-ip", "connection", source_ip="999.999.999.999")


def test_naive_timestamp_is_normalized_to_utc():
    loaded = load_event({
        "timestamp": "2026-01-01T00:00:00",
        "source": "auth",
        "event_type": "login_failure",
    })
    assert loaded.timestamp.tzinfo == timezone.utc


def test_load_events_rejects_non_object_entries():
    with pytest.raises((TypeError, ValueError, ValidationError)):
        load_events([{"timestamp": "2026-01-01T00:00:00Z",
                      "source": "auth", "event_type": "login_failure"}, 42])


def test_authentication_brute_force_detection():
    events = [
        event(str(i), "login_failure", category=EventCategory.AUTHENTICATION,
              username="alice", source_ip="192.0.2.10", seconds=i)
        for i in range(5)
    ]
    assert "brute_force_login_attempts" in detect_authentication(
        events, brute_force_threshold=5
    )


def test_authentication_failure_then_success_detection():
    events = [
        event("f1", "login_failure", category=EventCategory.AUTHENTICATION,
              username="alice", seconds=0),
        event("s1", "login_success", category=EventCategory.AUTHENTICATION,
              username="alice", seconds=30),
    ]
    assert "failure_then_success" in detect_authentication(events)


def test_port_scan_detection():
    events = [
        event(str(port), "connection", category=EventCategory.NETWORK,
              source_ip="192.0.2.1", destination_ip="198.51.100.1",
              destination_port=port, seconds=port)
        for port in range(20, 30)
    ]
    assert detect_port_scan(events, threshold=10)


def test_connection_fanout_detection():
    events = [
        event(str(i), "connection", category=EventCategory.NETWORK,
              source_ip="192.0.2.1",
              destination_ip=f"198.51.100.{i}", seconds=i)
        for i in range(1, 11)
    ]
    assert detect_connection_fanout(events, threshold=10)


def test_suspicious_long_dns_detection():
    dns = event(
        "dns1", "dns_query", category=EventCategory.DNS,
        dns_query="a" * 55 + ".example"
    )
    assert detect_suspicious_dns([dns], minimum_length=50)


def test_cross_event_correlation_preserves_event_ids():
    events = [
        event("f1", "login_failure",
              category=EventCategory.AUTHENTICATION,
              username="alice", source_ip="192.0.2.1"),
        event("s1", "login_success",
              category=EventCategory.AUTHENTICATION,
              username="alice", source_ip="192.0.2.1", seconds=10),
    ]
    results = correlate_security_events(events)
    assert any(
        "f1" in result.get("event_ids", [])
        and "s1" in result.get("event_ids", [])
        for result in results
    )


def test_failure_then_success_correlation_includes_source_provenance():
    events = [
        event(
            "f1", "login_failure",
            category=EventCategory.AUTHENTICATION,
            username="alice",
            original_source_id="auth-source-1",
            original_event_reference="auth.log:10",
        ),
        event(
            "s1", "login_success",
            category=EventCategory.AUTHENTICATION,
            username="alice",
            seconds=10,
            original_source_id="auth-source-2",
            original_event_reference="auth.log:11",
        ),
    ]

    result = next(
        item for item in correlate_security_events(events)
        if item["correlation_type"] == "authentication_failure_then_success"
    )

    assert result["source_provenance"] == [
        {
            "event_id": "f1",
            "original_source_id": "auth-source-1",
            "original_event_reference": "auth.log:10",
        },
        {
            "event_id": "s1",
            "original_source_id": "auth-source-2",
            "original_event_reference": "auth.log:11",
        },
    ]


def test_authentication_network_correlation_includes_source_provenance():
    events = [
        event(
            "f1", "login_failure",
            category=EventCategory.AUTHENTICATION,
            source_ip="192.0.2.10",
            original_source_id="auth-source",
            original_event_reference="auth.log:20",
        ),
        event(
            "n1", "connection",
            category=EventCategory.NETWORK,
            source_ip="192.0.2.10",
            destination_ip="198.51.100.10",
            seconds=10,
            original_source_id="firewall-source",
            original_event_reference="firewall.log:30",
        ),
    ]

    result = next(
        item for item in correlate_security_events(events)
        if item["correlation_type"] == "authentication_with_network_activity"
    )

    assert {item["event_id"] for item in result["source_provenance"]} == {"f1", "n1"}
    assert {item["original_source_id"] for item in result["source_provenance"]} == {
        "auth-source", "firewall-source"
    }


def test_multiple_accounts_correlation_includes_source_provenance():
    events = [
        event(
            "f1", "login_failure",
            category=EventCategory.AUTHENTICATION,
            username="alice",
            source_ip="192.0.2.20",
            original_source_id="auth-source",
            original_event_reference="auth.log:40",
        ),
        event(
            "f2", "login_failure",
            category=EventCategory.AUTHENTICATION,
            username="bob",
            source_ip="192.0.2.20",
            seconds=10,
            original_source_id="auth-source",
            original_event_reference="auth.log:41",
        ),
    ]

    result = next(
        item for item in correlate_security_events(events)
        if item["correlation_type"] == "multiple_accounts_from_source"
    )

    assert {item["event_id"] for item in result["source_provenance"]} == {"f1", "f2"}
    assert {item["original_event_reference"] for item in result["source_provenance"]} == {
        "auth.log:40", "auth.log:41"
    }


def test_network_fanout_correlation_includes_source_provenance():
    events = [
        event(
            "f1", "login_failure",
            category=EventCategory.AUTHENTICATION,
            source_ip="192.0.2.30",
            original_source_id="auth-source",
            original_event_reference="auth.log:50",
        ),
        event(
            "n1", "connection",
            category=EventCategory.NETWORK,
            source_ip="192.0.2.30",
            destination_ip="198.51.100.1",
            seconds=10,
            original_source_id="firewall-source",
            original_event_reference="firewall.log:51",
        ),
        event(
            "n2", "connection",
            category=EventCategory.NETWORK,
            source_ip="192.0.2.30",
            destination_ip="198.51.100.2",
            seconds=20,
            original_source_id="firewall-source",
            original_event_reference="firewall.log:52",
        ),
    ]

    result = next(
        item for item in correlate_security_events(events)
        if item["correlation_type"] == "authentication_then_network_fanout"
    )

    assert {item["event_id"] for item in result["source_provenance"]} == {
        "f1", "n1", "n2"
    }
    assert {item["original_event_reference"] for item in result["source_provenance"]} == {
        "auth.log:50", "firewall.log:51", "firewall.log:52"
    }


def make_alert(rule_id="AUTH-001", event_ids=("e1",)):
    return SecurityAlert(
        rule_id=rule_id,
        rule_name="Test detection",
        severity="high",
        confidence=0.8,
        explanation="Test evidence",
        event_ids=event_ids,
        first_seen=NOW,
        last_seen=NOW,
    )


def test_alert_status_transitions():
    alert = make_alert()
    alert.update_status(AlertStatus.INVESTIGATING)
    alert.update_status(AlertStatus.RESOLVED)
    assert alert.status == AlertStatus.RESOLVED


def test_alert_manager_suppresses_duplicates():
    manager = AlertManager(window_minutes=15)
    first = manager.add(make_alert())
    second = manager.add(make_alert(event_ids=("e2",)))
    assert first.alert_id == second.alert_id
    assert len(manager.list_alerts()) == 1
    assert set(second.event_ids) == {"e1", "e2"}


def test_risk_assessment_is_bounded():
    result = assess_risk([make_alert()], event_count=1)
    assert 0 <= result["risk_score"] <= 100


def test_json_and_html_reports_are_generated():
    alert = make_alert()
    correlations = [
        {
            "correlation_type": "authentication_failure_then_success",
            "event_ids": ["event-1", "event-2"],
            "source_provenance": [
                {
                    "event_id": "event-1",
                    "original_source_id": "source-record-001",
                    "original_event_reference": "Security.evtx:record-001",
                },
                {
                    "event_id": "event-2",
                    "original_source_id": "source-record-002",
                    "original_event_reference": "Security.evtx:record-002",
                },
            ],
        }
    ]
    report = build_json_report([], [alert], correlations)
    assert report["report_version"] == "2.0"
    serialized = json.loads(json.dumps(report))
    provenance = serialized["correlations"][0]["source_provenance"]
    assert provenance[0]["original_source_id"] == "source-record-001"
    assert provenance[0]["original_event_reference"] == (
        "Security.evtx:record-001"
    )
    assert provenance[1]["original_source_id"] == "source-record-002"
    assert provenance[1]["original_event_reference"] == (
        "Security.evtx:record-002"
    )
    html = build_html_report(report)
    assert "<html" in html.lower()
    assert "Test detection" in html
    assert "Security.evtx:record-001" in html
    assert "Security.evtx:record-002" in html


def test_evaluation_metrics():
    metrics = calculate_metrics({"a", "b"}, {"b", "c"})
    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5


def test_per_rule_evaluation():
    result = evaluate_rules(
        {"AUTH-001": {"e1", "e2"}},
        {"AUTH-001": {"e2", "e3"}},
    )
    assert result["per_rule"]["AUTH-001"]["tp"] == 1
