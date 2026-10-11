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


def test_normalize_extended_telemetry_aliases():
    raw_event = {
        "timestamp": datetime.now(timezone.utc),
        "source": "endpoint",
        "event": "process_start",
        "src": "10.0.0.10",
        "dst": "10.0.0.20",
        "user.name": "admin",
        "host.name": "server-01",
        "process.name": "powershell.exe",
        "event.action": "execute",
        "network.transport": "tcp",
        "severity": "medium",
        "message": "Process started",
    }

    event = normalize_event(raw_event)

    assert event.event_type == "process_start"
    assert event.source_ip == "10.0.0.10"
    assert event.destination_ip == "10.0.0.20"
    assert event.username == "admin"
    assert event.host == "server-01"
    assert event.process_name == "powershell.exe"
    assert event.action == "execute"
    assert event.protocol == "tcp"


def test_normalize_preserves_canonical_fields():
    raw_event = {
        "timestamp": datetime.now(timezone.utc),
        "source": "firewall",
        "event_type": "canonical_event",
        "event": "alias_event",
        "source_ip": "10.0.0.1",
        "src_ip": "10.0.0.99",
        "severity": "low",
    }

    event = normalize_event(raw_event)

    assert event.event_type == "canonical_event"
    assert event.source_ip == "10.0.0.1"
