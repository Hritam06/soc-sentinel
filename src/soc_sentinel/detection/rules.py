"""Authentication and legacy security detection rules."""

from collections import defaultdict
from datetime import timedelta

from soc_sentinel.core.models import EventSeverity, SecurityEvent
from soc_sentinel.detection.models import DetectionAlert

SUSPICIOUS_IPS = {"10.0.0.99", "192.168.100.99"}


def _failures(events, window_minutes):
    ordered = sorted(events, key=lambda event: event.timestamp)
    return [
        event for event in ordered
        if event.event_type == "login_failure" and event.source_ip
    ]


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[str]:
    if not events or threshold < 1 or window_minutes < 1:
        return []
    failures = _failures(events, window_minutes)
    for event in failures:
        end = event.timestamp + timedelta(minutes=window_minutes)
        count = sum(
            candidate.source_ip == event.source_ip
            and event.timestamp <= candidate.timestamp <= end
            for candidate in failures
        )
        if count >= threshold:
            return ["brute_force_login_attempts"]
    return []


def detect_password_spray(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[str]:
    if not events or threshold < 1 or window_minutes < 1:
        return []
    failures = _failures(events, window_minutes)
    for event in failures:
        end = event.timestamp + timedelta(minutes=window_minutes)
        usernames = {
            candidate.username
            for candidate in failures
            if candidate.source_ip == event.source_ip
            and candidate.username
            and event.timestamp <= candidate.timestamp <= end
        }
        if len(usernames) >= threshold:
            return ["password_spray_attempts"]
    return []


def detect_failure_then_success(
    events: list[SecurityEvent],
    window_minutes: int = 10,
) -> list[str]:
    if not events or window_minutes < 1:
        return []
    ordered = sorted(events, key=lambda event: event.timestamp)
    for failure in ordered:
        if failure.event_type != "login_failure" or not failure.username:
            continue
        end = failure.timestamp + timedelta(minutes=window_minutes)
        if any(
            success.event_type == "login_success"
            and success.username == failure.username
            and failure.timestamp <= success.timestamp <= end
            for success in ordered
        ):
            return ["failure_then_success"]
    return []


def detect_multi_source_account_targeting(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 10,
) -> list[str]:
    if not events or threshold < 2 or window_minutes < 1:
        return []
    failures = sorted(
        (event for event in events
         if event.event_type == "login_failure" and event.username and event.source_ip),
        key=lambda event: event.timestamp,
    )
    for event in failures:
        end = event.timestamp + timedelta(minutes=window_minutes)
        sources = {
            candidate.source_ip for candidate in failures
            if candidate.username == event.username
            and event.timestamp <= candidate.timestamp <= end
        }
        if len(sources) >= threshold:
            return ["multi_source_account_targeting"]
    return []


def detect_authentication_burst(
    events: list[SecurityEvent],
    threshold: int = 10,
    window_minutes: int = 1,
) -> list[str]:
    if not events or threshold < 1 or window_minutes < 1:
        return []
    failures = sorted(
        (event for event in events if event.event_type == "login_failure"),
        key=lambda event: event.timestamp,
    )
    for event in failures:
        end = event.timestamp + timedelta(minutes=window_minutes)
        count = sum(
            event.timestamp <= candidate.timestamp <= end
            for candidate in failures
        )
        if count >= threshold:
            return ["authentication_failure_burst"]
    return []


def detect_authentication(
    events: list[SecurityEvent],
    *,
    brute_force_threshold: int = 5,
    password_spray_threshold: int = 5,
    multi_source_threshold: int = 3,
    burst_threshold: int = 10,
    window_minutes: int = 5,
    burst_window_minutes: int = 1,
) -> list[str]:
    """Run authentication detections with caller-supplied thresholds."""
    detections = []
    checks = (
        detect_brute_force(events, brute_force_threshold, window_minutes),
        detect_password_spray(events, password_spray_threshold, window_minutes),
        detect_failure_then_success(events, window_minutes),
        detect_multi_source_account_targeting(events, multi_source_threshold, window_minutes),
        detect_authentication_burst(events, burst_threshold, burst_window_minutes),
    )
    for result in checks:
        detections.extend(result)
    return detections


def detect(event: SecurityEvent) -> list[str]:
    return [alert.rule for alert in detect_alerts(event)]


def detect_alerts(event: SecurityEvent) -> list[DetectionAlert]:
    alerts: list[DetectionAlert] = []
    if event.event_type == "login_failure" and event.severity in {
        EventSeverity.HIGH, EventSeverity.CRITICAL
    }:
        alerts.append(DetectionAlert(
            rule="high_severity_login_failure",
            severity=event.severity.value,
            message="High-severity authentication failure detected.",
        ))
    if event.source_ip in SUSPICIOUS_IPS:
        alerts.append(DetectionAlert(
            rule="suspicious_source_ip",
            severity="high",
            message="Event originated from a suspicious source IP.",
        ))
    return alerts



def detect_port_scan(
    events: list[SecurityEvent],
    threshold: int = 10,
    window_minutes: int = 5,
) -> list[str]:
    """Detect one source contacting many ports on the same destination."""
    if not events or threshold < 2 or window_minutes < 1:
        return []
    candidates = sorted(
        (e for e in events if e.source_ip and e.destination_ip
         and e.destination_port is not None
         and e.category.value == "network"),
        key=lambda e: e.timestamp,
    )
    for event in candidates:
        end = event.timestamp + timedelta(minutes=window_minutes)
        ports = {
            item.destination_port for item in candidates
            if item.source_ip == event.source_ip
            and item.destination_ip == event.destination_ip
            and event.timestamp <= item.timestamp <= end
        }
        if len(ports) >= threshold:
            return ["port_scan"]
    return []


def detect_connection_fanout(
    events: list[SecurityEvent],
    threshold: int = 10,
    window_minutes: int = 5,
) -> list[str]:
    """Detect one source connecting to many destination hosts."""
    if not events or threshold < 2 or window_minutes < 1:
        return []
    candidates = sorted(
        (e for e in events if e.source_ip and e.destination_ip
         and e.category.value == "network"),
        key=lambda e: e.timestamp,
    )
    for event in candidates:
        end = event.timestamp + timedelta(minutes=window_minutes)
        destinations = {
            item.destination_ip for item in candidates
            if item.source_ip == event.source_ip
            and event.timestamp <= item.timestamp <= end
        }
        if len(destinations) >= threshold:
            return ["connection_fanout"]
    return []


def detect_network(
    events: list[SecurityEvent],
    *,
    port_scan_threshold: int = 10,
    fanout_threshold: int = 10,
    window_minutes: int = 5,
) -> list[str]:
    """Run network detections using caller-supplied thresholds."""
    return (
        detect_port_scan(events, port_scan_threshold, window_minutes)
        + detect_connection_fanout(events, fanout_threshold, window_minutes)
    )



def _dns_entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    import math
    from collections import Counter

    if not value:
        return 0.0
    counts = Counter(value.lower())
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def detect_suspicious_dns(
    events: list[SecurityEvent],
    minimum_length: int = 50,
    minimum_entropy: float = 3.5,
) -> list[str]:
    """Flag long or high-entropy DNS queries as investigation heuristics."""
    if minimum_length < 1 or not 0 <= minimum_entropy <= 8:
        return []
    for event in events:
        if event.category.value != "dns" or not event.dns_query:
            continue
        query = event.dns_query.rstrip(".")
        labels = query.split(".")
        if (
            len(query) >= minimum_length
            or any(
                len(label) >= 20 and _dns_entropy(label) >= minimum_entropy
                for label in labels
            )
        ):
            return ["suspicious_dns_query"]
    return []
