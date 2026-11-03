from typing import Any

from soc_sentinel.core.models import EventCategory, SecurityEvent


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
    "destination.domain": "destination_hostname",
    "destination.hostname": "destination_hostname",
    "process.name": "process_name",
    "network.transport": "protocol",
    "dns.question.name": "dns_query",
    "dns.question.type": "dns_record_type",
    "query": "dns_query",
    "query_type": "dns_record_type",
}


def infer_category(source: str, event_type: str) -> EventCategory:
    value = f"{source} {event_type}".lower()

    if any(term in value for term in ("dns", "domain_query", "name_resolution")):
        return EventCategory.DNS
    if any(term in value for term in ("auth", "login", "logon", "password")):
        return EventCategory.AUTHENTICATION
    if any(term in value for term in ("network", "firewall", "connection", "flow", "port_scan")):
        return EventCategory.NETWORK
    if any(term in value for term in ("endpoint", "process", "host", "file", "malware")):
        return EventCategory.ENDPOINT
    return EventCategory.OTHER


def normalize_event(data: dict[str, Any]) -> SecurityEvent:
    """Normalize common telemetry aliases and preserve the original event."""
    if not isinstance(data, dict):
        raise TypeError("Event input must be a dictionary.")

    normalized = dict(data)

    for source_field, canonical_field in FIELD_ALIASES.items():
        if source_field in normalized:
            if canonical_field not in normalized:
                normalized[canonical_field] = normalized[source_field]
            normalized.pop(source_field)

    if "category" not in normalized:
        normalized["category"] = infer_category(
            str(normalized.get("source", "")),
            str(normalized.get("event_type", "")),
        )

    normalized["raw_event"] = dict(data)

    return SecurityEvent.model_validate(normalized)
