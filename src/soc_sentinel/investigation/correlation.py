"""Cross-event security correlation."""

from collections import defaultdict
from datetime import timedelta

from soc_sentinel.core.models import SecurityEvent


def _event_reference(event: SecurityEvent) -> str:
    return event.event_id or f"{event.source}:{event.timestamp.isoformat()}"


def correlate_security_events(
    events: list[SecurityEvent],
    window_minutes: int = 10,
) -> list[dict]:
    """Correlate suspicious authentication, network and DNS activity."""
    if window_minutes < 1 or not events:
        return []

    ordered = sorted(events, key=lambda event: event.timestamp)
    results: list[dict] = []
    window = timedelta(minutes=window_minutes)

    failures_by_user = defaultdict(list)
    failures_by_source = defaultdict(list)

    for event in ordered:
        if event.event_type == "login_failure":
            if event.username:
                failures_by_user[event.username].append(event)
            if event.source_ip:
                failures_by_source[event.source_ip].append(event)

    emitted = set()

    for event in ordered:
        if event.event_type != "login_success" or not event.username:
            continue
        previous = [
            failure for failure in failures_by_user[event.username]
            if event.timestamp - window <= failure.timestamp <= event.timestamp
        ]
        if previous:
            refs = tuple(sorted({_event_reference(item) for item in previous + [event]}))
            key = ("authentication_failure_then_success", refs)
            if key not in emitted:
                emitted.add(key)
                results.append({
                    "correlation_type": "authentication_failure_then_success",
                    "username": event.username,
                    "start_time": min(item.timestamp for item in previous).isoformat(),
                    "end_time": event.timestamp.isoformat(),
                    "event_ids": list(refs),
                    "explanation": "A successful login followed recent failures for the same account.",
                })

    for source_ip, failures in sorted(failures_by_source.items()):
        for failure in failures:
            related = [
                item for item in ordered
                if failure.timestamp <= item.timestamp <= failure.timestamp + window
                and item.source_ip == source_ip
                and (
                    item.category.value in {"network", "dns"}
                    or item.event_type in {"login_failure", "login_success"}
                )
            ]
            network_or_dns = [
                item for item in related
                if item.category.value in {"network", "dns"}
            ]
            if not network_or_dns:
                continue
            refs = tuple(sorted({_event_reference(item) for item in [failure] + network_or_dns}))
            key = ("authentication_with_network_activity", refs)
            if key not in emitted:
                emitted.add(key)
                results.append({
                    "correlation_type": "authentication_with_network_activity",
                    "source_ip": source_ip,
                    "start_time": failure.timestamp.isoformat(),
                    "end_time": max(item.timestamp for item in network_or_dns).isoformat(),
                    "event_ids": list(refs),
                    "explanation": "Authentication failures were followed by network or DNS activity from the same source.",
                })

    for source_ip, failures in sorted(failures_by_source.items()):
        for failure in failures:
            accounts = {
                item.username for item in failures
                if item.username
                and failure.timestamp <= item.timestamp <= failure.timestamp + window
            }
            if len(accounts) < 2:
                continue
            related = [
                item for item in failures
                if item.username in accounts
                and failure.timestamp <= item.timestamp <= failure.timestamp + window
            ]
            refs = tuple(sorted({_event_reference(item) for item in related}))
            key = ("multiple_accounts_from_source", refs)
            if key not in emitted:
                emitted.add(key)
                results.append({
                    "correlation_type": "multiple_accounts_from_source",
                    "source_ip": source_ip,
                    "accounts": sorted(accounts),
                    "start_time": failure.timestamp.isoformat(),
                    "end_time": max(item.timestamp for item in related).isoformat(),
                    "event_ids": list(refs),
                    "explanation": "One source IP generated authentication failures for multiple accounts.",
                })

    for failure in ordered:
        if failure.event_type != "login_failure" or not failure.source_ip:
            continue
        related = [
            item for item in ordered
            if item.source_ip == failure.source_ip
            and item.category.value == "network"
            and item.destination_ip
            and failure.timestamp <= item.timestamp <= failure.timestamp + window
        ]
        destinations = {item.destination_ip for item in related}
        if len(destinations) < 2:
            continue
        refs = tuple(sorted({_event_reference(item) for item in [failure] + related}))
        key = ("authentication_then_network_fanout", refs)
        if key not in emitted:
            emitted.add(key)
            results.append({
                "correlation_type": "authentication_then_network_fanout",
                "source_ip": failure.source_ip,
                "destinations": sorted(destinations),
                "start_time": failure.timestamp.isoformat(),
                "end_time": max(item.timestamp for item in related).isoformat(),
                "event_ids": list(refs),
                "explanation": "Authentication failure was followed by connections to multiple destination hosts.",
            })

    return sorted(
        results,
        key=lambda result: (result["start_time"], result["correlation_type"]),
    )



def correlate_login_failures(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[dict]:
    """Preserve the v1 login-failure correlation interface and output."""
    if threshold < 1 or window_minutes < 1 or not events:
        return []

    ordered = sorted(events, key=lambda event: event.timestamp)
    results = []
    window = timedelta(minutes=window_minutes)

    for event in ordered:
        if event.event_type != "login_failure" or not event.source_ip:
            continue

        matching = [
            candidate for candidate in ordered
            if candidate.event_type == "login_failure"
            and candidate.source_ip == event.source_ip
            and event.timestamp <= candidate.timestamp <= event.timestamp + window
        ]

        if len(matching) < threshold:
            continue

        results.append({
            "correlation_type": "brute_force_login_attempts",
            "source_ip": event.source_ip,
            "start_time": event.timestamp.isoformat(),
            "end_time": matching[-1].timestamp.isoformat(),
            "count": len(matching),
            "event_count": len(matching),
            "events": [
                {
                    "event_id": item.event_id,
                    "timestamp": item.timestamp.isoformat(),
                    "username": item.username,
                    "event_type": item.event_type,
                }
                for item in matching
            ],
        })

    return results
