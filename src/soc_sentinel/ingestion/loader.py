from typing import Any

from soc_sentinel.core.models import SecurityEvent
from soc_sentinel.normalization.normalizer import normalize_event


def load_event(data: dict[str, Any]) -> SecurityEvent:
    """Normalize and validate a raw event dictionary."""
    return normalize_event(data)


def load_events(data: list[dict[str, Any]]) -> list[SecurityEvent]:
    """Normalize and validate a batch of raw event dictionaries."""
    return [load_event(item) for item in data]
