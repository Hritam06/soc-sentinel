from typing import Any

from soc_sentinel.core.models import SecurityEvent


def load_event(data: dict[str, Any]) -> SecurityEvent:
    """
    Convert a raw event dictionary into a validated SecurityEvent.

    Validation is delegated to the SecurityEvent Pydantic model.
    """

    return SecurityEvent.model_validate(data)
