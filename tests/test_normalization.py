from datetime import datetime, timezone

from soc_sentinel.normalization.normalizer import normalize_event


def test_normalize_common_field_aliases():
    raw_event = {
        "timestamp": datetime.now(timezone.utc),
        "source": "firewall",
        "event": "connection_attempt",
        "src_ip": "10.0.0.15",
        "dst_ip": "10.0.0.20",
        "severity": "medium",
        "message": "Connection attempt observed",
    }

    event = normalize_event(raw_event)

    assert event.event_type == "connection_attempt"
    assert event.source_ip == "10.0.0.15"
    assert event.destination_ip == "10.0.0.20"
