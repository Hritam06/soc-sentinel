from typing import Any

from soc_sentinel.core.models import SecurityEvent


FIELD_ALIASES = {
    "src_ip": "source_ip",
    "dst_ip": "destination_ip",
    "event": "event_type",
}


def normalize_event(data: dict[str, Any]) -> SecurityEvent:
    """
    Normalize common telemetry field aliases into the canonical event schema.
    """

    normalized = dict(data)

    for source_field, canonical_field in FIELD_ALIASES.items():
        if canonical_field not in normalized and source_field in normalized:
            normalized[canonical_field] = normalized[source_field]

        normalized.pop(source_field, None)

    return SecurityEvent.model_validate(normalized)
