from typing import Any

from soc_sentinel.core.models import SecurityEvent


FIELD_ALIASES = {
    "src_ip": "source_ip",
    "src": "source_ip",
    "source.address": "source_ip",
    "dst_ip": "destination_ip",
    "dest_ip": "destination_ip",
    "dst": "destination_ip",
    "destination.address": "destination_ip",
    "event": "event_type",
    "event.action": "action",
    "user.name": "username",
    "host.name": "host",
    "process.name": "process_name",
    "network.transport": "protocol",
}


def normalize_event(data: dict[str, Any]) -> SecurityEvent:
    """Normalize common telemetry aliases into the canonical event schema."""
    normalized = dict(data)

    for source_field, canonical_field in FIELD_ALIASES.items():
        if source_field in normalized:
            if canonical_field not in normalized:
                normalized[canonical_field] = normalized[source_field]
            normalized.pop(source_field)

    return SecurityEvent.model_validate(normalized)
