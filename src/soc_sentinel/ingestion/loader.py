from typing import Any
from uuid import uuid4

from soc_sentinel.core.models import SecurityEvent
from soc_sentinel.normalization.normalizer import normalize_event


def load_event(data: dict[str, Any]) -> SecurityEvent:
    """Normalize, identify and validate one raw security event."""
    if not isinstance(data, dict):
        raise TypeError("Event input must be a dictionary.")

    event_data = dict(data)
    if not event_data.get("event_id"):
        event_data["event_id"] = str(uuid4())

    return normalize_event(event_data)


def load_events(data: list[dict[str, Any]]) -> list[SecurityEvent]:
    """Normalize and validate a batch without silently dropping invalid events."""
    if not isinstance(data, list):
        raise TypeError("Event batch input must be a list.")

    return [load_event(item) for item in data]
