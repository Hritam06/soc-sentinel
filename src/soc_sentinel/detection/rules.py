from datetime import timedelta

from soc_sentinel.core.models import EventSeverity, SecurityEvent


SUSPICIOUS_IPS = {
    "10.0.0.99",
    "192.168.100.99",
}


def detect(event: SecurityEvent) -> list[str]:
    alerts: list[str] = []

    if event.event_type == "login_failure" and event.severity in {
        EventSeverity.HIGH,
        EventSeverity.CRITICAL,
    }:
        alerts.append("high_severity_login_failure")

    if event.source_ip in SUSPICIOUS_IPS:
        alerts.append("suspicious_source_ip")

    return alerts


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[str]:
    if not events:
        return []

    events = sorted(events, key=lambda event: event.timestamp)

    for event in events:
        if event.event_type != "login_failure":
            continue

        window_end = event.timestamp + timedelta(minutes=window_minutes)

        matching_events = [
            candidate
            for candidate in events
            if candidate.event_type == "login_failure"
            and candidate.source_ip == event.source_ip
            and event.timestamp <= candidate.timestamp <= window_end
        ]

        if len(matching_events) >= threshold:
            return ["brute_force_login_attempts"]

    return []


from soc_sentinel.detection.models import DetectionAlert


def detect_alerts(event: SecurityEvent) -> list[DetectionAlert]:
    alerts: list[DetectionAlert] = []

    if event.event_type == "login_failure" and event.severity in {
        EventSeverity.HIGH,
        EventSeverity.CRITICAL,
    }:
        alerts.append(
            DetectionAlert(
                rule="high_severity_login_failure",
                severity=event.severity.value,
                message="High-severity authentication failure detected.",
            )
        )

    if event.source_ip in SUSPICIOUS_IPS:
        alerts.append(
            DetectionAlert(
                rule="suspicious_source_ip",
                severity="high",
                message="Event originated from a suspicious source IP.",
            )
        )

    return alerts
