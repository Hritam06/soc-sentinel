from datetime import datetime, timedelta, timezone

from soc_sentinel.core.models import EventCategory, SecurityEvent
from soc_sentinel.detection.findings import detect_findings


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_event(event_id, event_type, seconds=0, **kwargs):
    return SecurityEvent(
        event_id=event_id,
        timestamp=NOW + timedelta(seconds=seconds),
        source="test",
        event_type=event_type,
        **kwargs,
    )


def test_brute_force_finding_contains_exact_event_provenance():
    events = [
        make_event(
            f"failure-{index}",
            "login_failure",
            seconds=index,
            category=EventCategory.AUTHENTICATION,
            source_ip="192.0.2.10",
            username="alice",
        )
        for index in range(5)
    ]

    findings = detect_findings(events, brute_force_threshold=5)

    finding = next(item for item in findings if item.rule_id == "AUTH-001")
    assert finding.event_ids == tuple(f"failure-{index}" for index in range(5))
    assert finding.first_seen == NOW
    assert finding.last_seen == NOW + timedelta(seconds=4)
    assert "ip:192.0.2.10" in finding.source_entities
    assert "user:alice" in finding.target_entities
    assert finding.evidence
    assert finding.triggering_conditions


def test_password_spray_finding_links_all_targeted_accounts():
    events = [
        make_event(
            f"spray-{index}",
            "login_failure",
            seconds=index,
            category=EventCategory.AUTHENTICATION,
            source_ip="192.0.2.20",
            username=username,
        )
        for index, username in enumerate(("alice", "bob", "carol"))
    ]

    findings = detect_findings(events, password_spray_threshold=3)

    finding = next(item for item in findings if item.rule_id == "AUTH-002")
    assert set(finding.event_ids) == {"spray-0", "spray-1", "spray-2"}
    assert {"user:alice", "user:bob", "user:carol"} <= set(finding.target_entities)


def test_failure_then_success_finding_links_both_events():
    events = [
        make_event(
            "failed",
            "login_failure",
            category=EventCategory.AUTHENTICATION,
            username="alice",
        ),
        make_event(
            "success",
            "login_success",
            seconds=30,
            category=EventCategory.AUTHENTICATION,
            username="alice",
        ),
    ]

    findings = detect_findings(events)

    finding = next(item for item in findings if item.rule_id == "AUTH-003")
    assert set(finding.event_ids) == {"failed", "success"}


def test_port_scan_finding_links_distinct_destination_ports():
    events = [
        make_event(
            f"port-{port}",
            "connection",
            seconds=port,
            category=EventCategory.NETWORK,
            source_ip="192.0.2.30",
            destination_ip="198.51.100.10",
            destination_port=port,
        )
        for port in range(10, 12)
    ]

    findings = detect_findings(events, port_scan_threshold=2)

    finding = next(item for item in findings if item.rule_id == "NET-001")
    assert set(finding.event_ids) == {"port-10", "port-11"}
    assert "ip:198.51.100.10" in finding.target_entities


def test_dns_finding_links_the_query_event():
    event = make_event(
        "dns-1",
        "dns_query",
        category=EventCategory.DNS,
        dns_query=("a" * 55) + ".example",
    )

    findings = detect_findings([event], dns_minimum_length=50)

    finding = next(item for item in findings if item.rule_id == "DNS-001")
    assert finding.event_ids == ("dns-1",)
    assert finding.first_seen == event.timestamp
