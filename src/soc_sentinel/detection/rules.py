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



def detect_authentication_alerts(
    events: list[SecurityEvent],
    *,
    brute_force_threshold: int = 5,
    password_spray_threshold: int = 5,
    multi_source_threshold: int = 3,
    burst_threshold: int = 10,
    window_minutes: int = 5,
    burst_window_minutes: int = 1,
) -> list[DetectionAlert]:
    """Return authentication detections with traceable event evidence.

    Detection ordering, first-match behaviour, and threshold semantics mirror
    detect_authentication() so existing detection behaviour remains stable.
    """
    alerts: list[DetectionAlert] = []

    def add(
        rule: str,
        matched_events: list[SecurityEvent],
        conditions: tuple[str, ...],
        severity: str = "high",
    ) -> None:
        unique_events = list({
            event.event_id: event for event in matched_events
        }.values())
        alerts.append(DetectionAlert(
            rule=rule,
            severity=severity,
            message=f"{rule.replace('_', ' ').capitalize()} detected.",
            evidence=conditions,
            event_ids=tuple(event.event_id for event in unique_events),
        ))

    if events and brute_force_threshold >= 1 and window_minutes >= 1:
        failures = _failures(events, window_minutes)
        for event in failures:
            end = event.timestamp + timedelta(minutes=window_minutes)
            matched = [
                candidate for candidate in failures
                if candidate.source_ip == event.source_ip
                and event.timestamp <= candidate.timestamp <= end
            ]
            if len(matched) >= brute_force_threshold:
                add(
                    "brute_force_login_attempts",
                    matched,
                    (
                        f"Source IP: {event.source_ip}",
                        f"Failed login count: {len(matched)}",
                        f"Required threshold: {brute_force_threshold}",
                        f"Window: {window_minutes} minutes",
                    ),
                )
                break

    if events and password_spray_threshold >= 1 and window_minutes >= 1:
        failures = _failures(events, window_minutes)
        for event in failures:
            end = event.timestamp + timedelta(minutes=window_minutes)
            matched = [
                candidate for candidate in failures
                if candidate.source_ip == event.source_ip
                and candidate.username
                and event.timestamp <= candidate.timestamp <= end
            ]
            usernames = {candidate.username for candidate in matched}
            if len(usernames) >= password_spray_threshold:
                add(
                    "password_spray_attempts",
                    matched,
                    (
                        f"Source IP: {event.source_ip}",
                        f"Distinct targeted accounts: {len(usernames)}",
                        f"Required threshold: {password_spray_threshold}",
                        f"Window: {window_minutes} minutes",
                    ),
                )
                break

    if events and window_minutes >= 1:
        ordered = sorted(events, key=lambda item: item.timestamp)
        for failure in ordered:
            if failure.event_type != "login_failure" or not failure.username:
                continue
            end = failure.timestamp + timedelta(minutes=window_minutes)
            successes = [
                success for success in ordered
                if success.event_type == "login_success"
                and success.username == failure.username
                and failure.timestamp <= success.timestamp <= end
            ]
            if successes:
                add(
                    "failure_then_success",
                    [failure, *successes],
                    (
                        f"Account: {failure.username}",
                        "A successful login followed a failed login",
                        f"Window: {window_minutes} minutes",
                    ),
                    severity="medium",
                )
                break

    if events and multi_source_threshold >= 2 and window_minutes >= 1:
        failures = sorted(
            (
                event for event in events
                if event.event_type == "login_failure"
                and event.username and event.source_ip
            ),
            key=lambda item: item.timestamp,
        )
        for event in failures:
            end = event.timestamp + timedelta(minutes=window_minutes)
            matched = [
                candidate for candidate in failures
                if candidate.username == event.username
                and event.timestamp <= candidate.timestamp <= end
            ]
            sources = {candidate.source_ip for candidate in matched}
            if len(sources) >= multi_source_threshold:
                add(
                    "multi_source_account_targeting",
                    matched,
                    (
                        f"Target account: {event.username}",
                        f"Distinct source IPs: {len(sources)}",
                        f"Required threshold: {multi_source_threshold}",
                        f"Window: {window_minutes} minutes",
                    ),
                )
                break

    if events and burst_threshold >= 1 and burst_window_minutes >= 1:
        failures = sorted(
            (event for event in events if event.event_type == "login_failure"),
            key=lambda item: item.timestamp,
        )
        for event in failures:
            end = event.timestamp + timedelta(minutes=burst_window_minutes)
            matched = [
                candidate for candidate in failures
                if event.timestamp <= candidate.timestamp <= end
            ]
            if len(matched) >= burst_threshold:
                add(
                    "authentication_failure_burst",
                    matched,
                    (
                        f"Failed login count: {len(matched)}",
                        f"Required threshold: {burst_threshold}",
                        f"Window: {burst_window_minutes} minutes",
                    ),
                )
                break

    return alerts


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


def detect_network_alerts(
    events: list[SecurityEvent],
    *,
    port_scan_threshold: int = 10,
    fanout_threshold: int = 10,
    window_minutes: int = 5,
) -> list[DetectionAlert]:
    """Return network detections with exact contributing event IDs and conditions."""
    if not events or window_minutes < 1:
        return []

    candidates = sorted(
        (
            event for event in events
            if event.source_ip
            and event.destination_ip
            and event.category.value == "network"
        ),
        key=lambda event: (event.timestamp, event.event_id),
    )
    detections: list[DetectionAlert] = []

    if port_scan_threshold >= 2:
        for anchor in candidates:
            if anchor.destination_port is None:
                continue
            end = anchor.timestamp + timedelta(minutes=window_minutes)
            matched = [
                item for item in candidates
                if item.source_ip == anchor.source_ip
                and item.destination_ip == anchor.destination_ip
                and item.destination_port is not None
                and anchor.timestamp <= item.timestamp <= end
            ]
            ports = {item.destination_port for item in matched}
            if len(ports) >= port_scan_threshold:
                event_ids = tuple(dict.fromkeys(item.event_id for item in matched))
                detections.append(DetectionAlert(
                    rule="port_scan",
                    severity="high",
                    message=(
                        f"Source {anchor.source_ip} contacted "
                        f"{len(ports)} distinct ports on {anchor.destination_ip}."
                    ),
                    event_ids=event_ids,
                    evidence=(
                        f"source_ip={anchor.source_ip}",
                        f"destination_ip={anchor.destination_ip}",
                        f"distinct_destination_ports={len(ports)}",
                        f"threshold={port_scan_threshold}",
                        f"window_minutes={window_minutes}",
                        f"window_start={anchor.timestamp.isoformat()}",
                        f"window_end={end.isoformat()}",
                    ),
                ))
                break

    if fanout_threshold >= 2:
        for anchor in candidates:
            end = anchor.timestamp + timedelta(minutes=window_minutes)
            matched = [
                item for item in candidates
                if item.source_ip == anchor.source_ip
                and anchor.timestamp <= item.timestamp <= end
            ]
            destinations = {item.destination_ip for item in matched}
            if len(destinations) >= fanout_threshold:
                event_ids = tuple(dict.fromkeys(item.event_id for item in matched))
                detections.append(DetectionAlert(
                    rule="connection_fanout",
                    severity="medium",
                    message=(
                        f"Source {anchor.source_ip} connected to "
                        f"{len(destinations)} distinct destination hosts."
                    ),
                    event_ids=event_ids,
                    evidence=(
                        f"source_ip={anchor.source_ip}",
                        f"distinct_destination_ips={len(destinations)}",
                        f"threshold={fanout_threshold}",
                        f"window_minutes={window_minutes}",
                        f"window_start={anchor.timestamp.isoformat()}",
                        f"window_end={end.isoformat()}",
                    ),
                ))
                break

    return detections


def detect_suspicious_dns_alerts(
    events: list[SecurityEvent],
    minimum_length: int = 50,
    minimum_entropy: float = 3.5,
) -> list[DetectionAlert]:
    """Return suspicious DNS detections with event-level provenance."""
    if minimum_length < 1 or not 0 <= minimum_entropy <= 8:
        return []

    for event in events:
        if event.category.value != "dns" or not event.dns_query:
            continue

        query = event.dns_query.rstrip(".")
        labels = query.split(".")
        long_query = len(query) >= minimum_length
        high_entropy_labels = [
            (label, _dns_entropy(label))
            for label in labels
            if len(label) >= 20 and _dns_entropy(label) >= minimum_entropy
        ]

        if long_query or high_entropy_labels:
            conditions = [
                f"dns_query_length={len(query)}",
                f"minimum_length={minimum_length}",
                f"long_query_match={long_query}",
                f"minimum_entropy={minimum_entropy}",
            ]
            conditions.extend(
                f"high_entropy_label={label!r};entropy={entropy:.4f}"
                for label, entropy in high_entropy_labels
            )
            return [DetectionAlert(
                rule="suspicious_dns_query",
                severity="medium",
                message=(
                    f"Suspicious DNS query detected: {query!r} "
                    f"(length={len(query)})."
                ),
                event_ids=(event.event_id,),
                evidence=tuple(conditions),
            )]

    return []
