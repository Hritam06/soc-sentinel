"""Evidence-bearing batch detection findings.

This module keeps the legacy rule-name detector interfaces intact while
providing structured findings for the v2 investigation pipeline.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from soc_sentinel.core.models import SecurityEvent
from soc_sentinel.detection.rules import _dns_entropy

RULE_IDS = {
    "brute_force_login_attempts": "AUTH-001",
    "password_spray_attempts": "AUTH-002",
    "failure_then_success": "AUTH-003",
    "multi_source_account_targeting": "AUTH-004",
    "authentication_failure_burst": "AUTH-005",
    "port_scan": "NET-001",
    "connection_fanout": "NET-002",
    "suspicious_dns_query": "DNS-001",
}


@dataclass(frozen=True)
class DetectionFinding:
    """One detection result with the exact source events that support it."""

    rule_id: str
    rule_name: str
    event_ids: tuple[str, ...]
    evidence: tuple[str, ...]
    source_entities: tuple[str, ...]
    target_entities: tuple[str, ...]
    triggering_conditions: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    explanation: str
    confidence: float = 0.55


def _event_id(event: SecurityEvent) -> str:
    return event.event_id or f"{event.source}:{event.timestamp.isoformat()}"


def _make_finding(
    rule_name: str,
    events: list[SecurityEvent],
    explanation: str,
    conditions: tuple[str, ...],
) -> DetectionFinding:
    ordered = sorted(events, key=lambda item: (item.timestamp, _event_id(item)))
    unique = {_event_id(item): item for item in ordered}
    selected = sorted(unique.values(), key=lambda item: (item.timestamp, _event_id(item)))
    source_entities = {
        *(f"ip:{item.source_ip}" for item in selected if item.source_ip),
        *(f"host:{item.host}" for item in selected if item.host),
    }
    target_entities = {
        *(f"ip:{item.destination_ip}" for item in selected if item.destination_ip),
        *(f"host:{item.destination_hostname}" for item in selected if item.destination_hostname),
        *(f"user:{item.username}" for item in selected if item.username),
    }
    evidence = tuple(
        f"{_event_id(item)} | {item.timestamp.isoformat()} | "
        f"{item.event_type} | source_ip={item.source_ip or 'N/A'} | "
        f"username={item.username or 'N/A'} | "
        f"destination_ip={item.destination_ip or 'N/A'} | "
        f"destination_port={item.destination_port if item.destination_port is not None else 'N/A'}"
        for item in selected
    )
    return DetectionFinding(
        rule_id=RULE_IDS[rule_name],
        rule_name=rule_name,
        event_ids=tuple(_event_id(item) for item in selected),
        evidence=evidence,
        source_entities=tuple(sorted(source_entities)),
        target_entities=tuple(sorted(target_entities)),
        triggering_conditions=conditions,
        first_seen=selected[0].timestamp,
        last_seen=selected[-1].timestamp,
        explanation=explanation,
    )


def detect_findings(
    events: list[SecurityEvent],
    *,
    brute_force_threshold: int = 5,
    password_spray_threshold: int = 5,
    multi_source_threshold: int = 3,
    burst_threshold: int = 10,
    authentication_window_minutes: int = 5,
    burst_window_minutes: int = 1,
    port_scan_threshold: int = 10,
    connection_fanout_threshold: int = 10,
    network_window_minutes: int = 5,
    dns_minimum_length: int = 50,
    dns_minimum_entropy: float = 3.5,
) -> list[DetectionFinding]:
    """Run batch detections and return findings with event-level provenance."""
    findings: list[DetectionFinding] = []
    failures = [
        item for item in events
        if item.event_type == "login_failure" and item.source_ip
    ]
    window = timedelta(minutes=authentication_window_minutes)

    def collect(rule_name, matched, explanation, conditions):
        if matched:
            findings.append(_make_finding(rule_name, matched, explanation, conditions))

    brute = {}
    for event in failures:
        group = [
            item for item in failures
            if item.source_ip == event.source_ip
            and event.timestamp <= item.timestamp <= event.timestamp + window
        ]
        if len(group) >= brute_force_threshold:
            brute.update({_event_id(item): item for item in group})
    collect(
        "brute_force_login_attempts", list(brute.values()),
        "Repeated authentication failures from the same source IP were observed.",
        (f"At least {brute_force_threshold} login failures from one source IP within {authentication_window_minutes} minutes.",),
    )

    spray = {}
    for event in failures:
        group = [
            item for item in failures
            if item.source_ip == event.source_ip and item.username
            and event.timestamp <= item.timestamp <= event.timestamp + window
        ]
        if len({item.username for item in group}) >= password_spray_threshold:
            spray.update({_event_id(item): item for item in group})
    collect(
        "password_spray_attempts", list(spray.values()),
        "One source IP generated login failures against multiple accounts.",
        (f"At least {password_spray_threshold} distinct usernames targeted from one source IP within {authentication_window_minutes} minutes.",),
    )

    failure_success = {}
    ordered = sorted(events, key=lambda item: item.timestamp)
    for failure in ordered:
        if failure.event_type != "login_failure" or not failure.username:
            continue
        group = [
            item for item in ordered
            if item.event_type == "login_success"
            and item.username == failure.username
            and failure.timestamp <= item.timestamp <= failure.timestamp + window
        ]
        if group:
            failure_success[_event_id(failure)] = failure
            failure_success.update({_event_id(item): item for item in group})
    collect(
        "failure_then_success", list(failure_success.values()),
        "A successful login followed one or more recent failures for the same account.",
        (f"A login_success for the same username occurred within {authentication_window_minutes} minutes after a login_failure.",),
    )

    multi_source = {}
    failures_with_user = [item for item in failures if item.username]
    for event in failures_with_user:
        group = [
            item for item in failures_with_user
            if item.username == event.username
            and event.timestamp <= item.timestamp <= event.timestamp + window
        ]
        if len({item.source_ip for item in group}) >= multi_source_threshold:
            multi_source.update({_event_id(item): item for item in group})
    collect(
        "multi_source_account_targeting", list(multi_source.values()),
        "The same account received authentication failures from multiple source IPs.",
        (f"At least {multi_source_threshold} distinct source IPs targeted one username within {authentication_window_minutes} minutes.",),
    )

    burst = {}
    failure_events = [item for item in events if item.event_type == "login_failure"]
    burst_window = timedelta(minutes=burst_window_minutes)
    for event in failure_events:
        group = [
            item for item in failure_events
            if event.timestamp <= item.timestamp <= event.timestamp + burst_window
        ]
        if len(group) >= burst_threshold:
            burst.update({_event_id(item): item for item in group})
    collect(
        "authentication_failure_burst", list(burst.values()),
        "A high volume of authentication failures occurred in a short time window.",
        (f"At least {burst_threshold} login failures within {burst_window_minutes} minute(s).",),
    )

    network = [
        item for item in events
        if item.category.value == "network" and item.source_ip and item.destination_ip
    ]
    network_delta = timedelta(minutes=network_window_minutes)
    port_scan = {}
    for event in network:
        group = [
            item for item in network
            if item.source_ip == event.source_ip
            and item.destination_ip == event.destination_ip
            and item.destination_port is not None
            and event.timestamp <= item.timestamp <= event.timestamp + network_delta
        ]
        if len({item.destination_port for item in group}) >= port_scan_threshold:
            port_scan.update({_event_id(item): item for item in group})
    collect(
        "port_scan", list(port_scan.values()),
        "One source contacted multiple destination ports on the same destination host.",
        (f"At least {port_scan_threshold} distinct destination ports within {network_window_minutes} minutes.",),
    )

    fanout = {}
    for event in network:
        group = [
            item for item in network
            if item.source_ip == event.source_ip
            and event.timestamp <= item.timestamp <= event.timestamp + network_delta
        ]
        if len({item.destination_ip for item in group}) >= connection_fanout_threshold:
            fanout.update({_event_id(item): item for item in group})
    collect(
        "connection_fanout", list(fanout.values()),
        "One source connected to multiple destination hosts in a short time window.",
        (f"At least {connection_fanout_threshold} distinct destination IPs within {network_window_minutes} minutes.",),
    )

    suspicious_dns = []
    for event in events:
        if event.category.value != "dns" or not event.dns_query:
            continue
        query = event.dns_query.rstrip(".")
        labels = query.split(".")
        if len(query) >= dns_minimum_length or any(
            len(label) >= 20 and _dns_entropy(label) >= dns_minimum_entropy
            for label in labels
        ):
            suspicious_dns.append(event)
    collect(
        "suspicious_dns_query", suspicious_dns,
        "A DNS query met the configured length or entropy heuristic.",
        (f"DNS query length >= {dns_minimum_length}, or a label of length >= 20 with entropy >= {dns_minimum_entropy}.",),
    )

    return sorted(findings, key=lambda item: (item.first_seen, item.rule_id))
