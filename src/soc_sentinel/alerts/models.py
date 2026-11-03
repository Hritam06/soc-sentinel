"""Structured security alert models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class AlertStatus(str, Enum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"


@dataclass
class SecurityAlert:
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    explanation: str
    event_ids: tuple[str, ...] = ()
    source_entities: tuple[str, ...] = ()
    target_entities: tuple[str, ...] = ()
    triggering_conditions: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    status: AlertStatus = AlertStatus.NEW

    def __post_init__(self):
        self.severity = self.severity.lower()
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("Unsupported alert severity")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if self.first_seen.tzinfo is None or self.last_seen.tzinfo is None:
            raise ValueError("Alert timestamps must be timezone-aware")
        self.first_seen = self.first_seen.astimezone(timezone.utc)
        self.last_seen = self.last_seen.astimezone(timezone.utc)
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")

    def update_status(self, status: AlertStatus) -> None:
        if not isinstance(status, AlertStatus):
            status = AlertStatus(status)
        allowed = {
            AlertStatus.NEW: {AlertStatus.INVESTIGATING, AlertStatus.FALSE_POSITIVE},
            AlertStatus.INVESTIGATING: {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
            AlertStatus.RESOLVED: set(),
            AlertStatus.FALSE_POSITIVE: set(),
        }
        if status not in allowed[self.status]:
            raise ValueError(f"Invalid alert status transition: {self.status.value} -> {status.value}")
        self.status = status
