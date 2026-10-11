
from datetime import datetime
from enum import Enum
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent(BaseModel):
    """Validated, normalized representation of a security event."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str | None = Field(default=None, min_length=1)
    timestamp: datetime
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)

    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None

    username: str | None = None
    host: str | None = None
    process_name: str | None = None
    action: str | None = None
    outcome: str | None = None

    severity: EventSeverity = EventSeverity.LOW
    message: str | None = None

    # Additional structured telemetry from the originating security tool.
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ip_address(value))
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc

    @field_validator("protocol", "outcome", "action")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        return normalized or None

    @field_validator("username", "host", "process_name")
    @classmethod
    def trim_optional_identifiers(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 100:
            raise ValueError("metadata cannot contain more than 100 top-level fields")
        return value
