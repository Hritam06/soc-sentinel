"""Deterministic correlation of related security events."""

from datetime import timedelta
from typing import Any

from soc_sentinel.core.models import SecurityEvent


def correlate_login_failures(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[dict[str, Any]]:
    """Return evidence groups for qualifying login-failure windows.

    Each group is anchored at a login failure and includes login failures
    from the same source IP within the inclusive time window. Groups may
    overlap. Event IDs are preserved when supplied; missing IDs remain None.
    """
    if threshold < 1 or window_minutes < 1 or not events:
        return []

    ordered_events = sorted(events, key=lambda event: event.timestamp)
    groups: list[dict[str, Any]] = []
    window = timedelta(minutes=window_minutes)

    for start_event in ordered_events:
        if start_event.event_type != "login_failure" or not start_event.source_ip:
            continue

        end_time = start_event.timestamp + window
        matching_events = [
            candidate
            for candidate in ordered_events
            if candidate.event_type == "login_failure"
            and candidate.source_ip == start_event.source_ip
            and start_event.timestamp <= candidate.timestamp <= end_time
        ]

        if len(matching_events) < threshold:
            continue

        groups.append(
            {
                "correlation_type": "brute_force_login_attempts",
                "source_ip": start_event.source_ip,
                "start_time": start_event.timestamp.isoformat(),
                "end_time": matching_events[-1].timestamp.isoformat(),
                "event_count": len(matching_events),
                "events": [
                    {
                        "event_id": event.event_id,
                        "timestamp": event.timestamp.isoformat(),
                        "username": event.username,
                        "event_type": event.event_type,
                    }
                    for event in matching_events
                ],
            }
        )

    return groups
