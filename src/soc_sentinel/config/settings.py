"""Validated YAML and JSON configuration for SOC Sentinel."""

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class DetectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    brute_force_threshold: int = Field(default=5, ge=2)
    password_spray_threshold: int = Field(default=5, ge=2)
    port_scan_threshold: int = Field(default=10, ge=2)
    connection_fanout_threshold: int = Field(default=10, ge=2)
    authentication_window_minutes: int = Field(default=5, ge=1)
    network_window_minutes: int = Field(default=5, ge=1)
    dns_minimum_length: int = Field(default=50, ge=10)


class AllowlistSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ips: list[str] = Field(default_factory=list)
    accounts: list[str] = Field(default_factory=list)


class SuppressionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    window_minutes: int = Field(default=15, ge=1)


class SentinelConfig(BaseModel):
    """Central configuration with safe defaults and strict validation."""

    model_config = ConfigDict(extra="forbid")

    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    allowlists: AllowlistSettings = Field(default_factory=AllowlistSettings)
    suppression: SuppressionSettings = Field(default_factory=SuppressionSettings)
    severity: dict[str, str] = Field(default_factory=lambda: {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
    })

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: dict[str, str]) -> dict[str, str]:
        allowed = {"low", "medium", "high", "critical"}
        if any(item not in allowed for item in value.values()):
            raise ValueError("Severity values must be low, medium, high or critical.")
        return value


def load_config(path: str | Path) -> SentinelConfig:
    """Load and validate a YAML or JSON configuration file."""
    config_path = Path(path)
    try:
        content = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Cannot read configuration file: {config_path}") from exc

    suffix = config_path.suffix.lower()
    try:
        if suffix == ".json":
            data: Any = json.loads(content)
        elif suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(content)
        else:
            raise ValueError("Configuration file must use .json, .yaml or .yml.")
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Invalid configuration syntax in {config_path}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("Configuration root must be an object or mapping.")

    return SentinelConfig.model_validate(data)
