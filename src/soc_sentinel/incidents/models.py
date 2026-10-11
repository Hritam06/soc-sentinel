"""In-memory incident lifecycle model."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


ALLOWED_TRANSITIONS = {
    IncidentStatus.NEW: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.RESOLVED: set(),
    IncidentStatus.FALSE_POSITIVE: set(),
}


@dataclass
class Incident:
    """Represent an incident and validate its lifecycle transitions.

    This model is in-memory only; it does not persist state between runs.
    """

    title: str
    incident_id: str = field(default_factory=lambda: str(uuid4()))
    status: IncidentStatus = IncidentStatus.NEW
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.title or not self.title.strip():
            raise ValueError("Incident title must not be empty.")
        if not self.incident_id or not self.incident_id.strip():
            raise ValueError("Incident ID must not be empty.")
        if not isinstance(self.status, IncidentStatus):
            try:
                self.status = IncidentStatus(self.status)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Unsupported incident status: {self.status!r}") from exc

    def transition_to(self, new_status: IncidentStatus) -> None:
        """Transition to an allowed status or raise ValueError."""
        if not isinstance(new_status, IncidentStatus):
            try:
                new_status = IncidentStatus(new_status)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Unsupported incident status: {new_status!r}") from exc

        if new_status not in ALLOWED_TRANSITIONS[self.status]:
            raise ValueError(
                f"Invalid incident transition: {self.status.value} -> {new_status.value}"
            )

        self.status = new_status
        self.updated_at = datetime.now(timezone.utc)
