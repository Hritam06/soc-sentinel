from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EventSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    severity: EventSeverity = EventSeverity.LOW
    message: str | None = None
