from datetime import datetime, timedelta, timezone

from soc_sentinel.core.models import EventCategory, SecurityEvent
from soc_sentinel.detection.rules import (
    detect_network_alerts,
    detect_suspicious_dns_alerts,
)


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_event(event_id, event_type, category, seconds=0, **kwargs):
    return SecurityEvent(
        event_id=event_id,
        timestamp=NOW + timedelta(seconds=seconds),
        source="test",
        event_type=event_type,
        category=category,
        **kwargs,
    )


def test_structured_port_scan_preserves_contributing_event_ids_and_conditions():
    events = [
        make_event(
            f"port-{port}",
            "connection",
            EventCategory.NETWORK,
            seconds=index,
            source_ip="192.0.2.10",
            destination_ip="198.51.100.20",
            destination_port=port,
        )
        for index, port in enumerate((22, 80, 443))
    ]

    detections = detect_network_alerts(
        events, port_scan_threshold=3, fanout_threshold=99
    )

    assert len(detections) == 1
    alert = detections[0]
    assert alert.rule == "port_scan"
    assert set(alert.event_ids) == {event.event_id for event in events}
    assert "distinct_destination_ports=3" in alert.evidence
    assert "threshold=3" in alert.evidence
    assert "source_ip=192.0.2.10" in alert.evidence
    assert "destination_ip=198.51.100.20" in alert.evidence


def test_structured_fanout_preserves_contributing_event_ids_and_conditions():
    events = [
        make_event(
            f"host-{index}",
            "connection",
            EventCategory.NETWORK,
            seconds=index,
            source_ip="192.0.2.11",
            destination_ip=f"198.51.100.{index}",
        )
        for index in (1, 2, 3)
    ]

    detections = detect_network_alerts(
        events, port_scan_threshold=99, fanout_threshold=3
    )

    assert len(detections) == 1
    alert = detections[0]
    assert alert.rule == "connection_fanout"
    assert set(alert.event_ids) == {event.event_id for event in events}
    assert "distinct_destination_ips=3" in alert.evidence
    assert "threshold=3" in alert.evidence
    assert "source_ip=192.0.2.11" in alert.evidence


def test_structured_dns_detection_preserves_event_id_and_matched_conditions():
    dns = make_event(
        "dns-suspicious",
        "dns_query",
        EventCategory.DNS,
        dns_query="a" * 55 + ".example",
    )

    detections = detect_suspicious_dns_alerts([dns], minimum_length=50)

    assert len(detections) == 1
    alert = detections[0]
    assert alert.rule == "suspicious_dns_query"
    assert alert.event_ids == ("dns-suspicious",)
    assert "dns_query_length=63" in alert.evidence
    assert "minimum_length=50" in alert.evidence
    assert "long_query_match=True" in alert.evidence


def test_structured_detectors_do_not_alert_on_non_matching_events():
    network = make_event(
        "ordinary-network",
        "connection",
        EventCategory.NETWORK,
        source_ip="192.0.2.12",
        destination_ip="198.51.100.30",
        destination_port=443,
    )
    dns = make_event(
        "ordinary-dns",
        "dns_query",
        EventCategory.DNS,
        dns_query="example.com",
    )

    assert detect_network_alerts(
        [network], port_scan_threshold=2, fanout_threshold=2
    ) == []
    assert detect_suspicious_dns_alerts([dns]) == []


def test_network_detection_thresholds_are_validated_independently():
    events = [
        make_event(
            f"fanout-{index}",
            "connection",
            EventCategory.NETWORK,
            seconds=index,
            source_ip="192.0.2.13",
            destination_ip=f"198.51.100.{index}",
        )
        for index in (1, 2, 3)
    ]

    detections = detect_network_alerts(
        events, port_scan_threshold=1, fanout_threshold=3
    )

    assert [alert.rule for alert in detections] == ["connection_fanout"]
