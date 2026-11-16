"""Validated YAML and JSON configuration for SOC Sentinel."""

import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Mapping

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

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            try:
                address = str(ipaddress.ip_address(value.strip()))
            except (ValueError, AttributeError) as exc:
                raise ValueError(f"Invalid allowlisted IP address: {value!r}") from exc
            if address not in normalized:
                normalized.append(address)
        return normalized

    @field_validator("accounts")
    @classmethod
    def validate_accounts(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Allowlisted accounts must be non-empty strings")
            account = value.strip()
            if account not in normalized:
                normalized.append(account)
        return normalized


class SuppressionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    window_minutes: int = Field(default=15, ge=1)


class InvestigationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_window_minutes: int = Field(default=10, ge=1)
    high_asset_bonus: int = Field(default=10, ge=0, le=20)
    critical_asset_bonus: int = Field(default=20, ge=0, le=20)
    progression_bonus_max: int = Field(default=20, ge=0, le=20)


class SentinelConfig(BaseModel):
    """Central configuration with strict validation and safe defaults."""

    model_config = ConfigDict(extra="forbid")

    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    allowlists: AllowlistSettings = Field(default_factory=AllowlistSettings)
    suppression: SuppressionSettings = Field(default_factory=SuppressionSettings)
    investigation: InvestigationSettings = Field(
        default_factory=InvestigationSettings
    )
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
            raise ValueError(
                "Severity values must be low, medium, high or critical."
            )
        return value


def _environment_overrides(
    environ: Mapping[str, str],
) -> dict[str, Any]:
    """Convert SOC_SENTINEL__A__B variables into nested config values."""
    overrides: dict[str, Any] = {}
    prefix = "SOC_SENTINEL__"

    for name, raw_value in environ.items():
        if not name.startswith(prefix):
            continue
        parts = [part.lower() for part in name[len(prefix):].split("__")]
        if not parts or any(not part for part in parts):
            raise ValueError(f"Invalid configuration environment variable: {name}")

        try:
            value = json.loads(raw_value)
        except json.JSONDecodeError:
            value = raw_value

        current = overrides
        for part in parts[:-1]:
            existing = current.get(part)
            if existing is None:
                current[part] = {}
            elif not isinstance(existing, dict):
                raise ValueError(f"Conflicting environment override: {name}")
            current = current[part]

        leaf = parts[-1]
        if leaf in current:
            raise ValueError(f"Duplicate environment override: {name}")
        current[leaf] = value

    return overrides


def _merge_config(
    base: dict[str, Any],
    overrides: dict[str, Any],
) -> dict[str, Any]:
    """Merge nested overrides without mutating the input dictionaries."""
    merged = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_config(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(
    path: str | Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> SentinelConfig:
    """Load YAML or JSON, apply optional environment overrides, validate."""
    config_path = Path(path)
    try:
        content = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(
            f"Cannot read configuration file: {config_path}"
        ) from exc

    suffix = config_path.suffix.lower()
    try:
        if suffix == ".json":
            data: Any = json.loads(content)
        elif suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(content)
        else:
            raise ValueError(
                "Configuration file must use .json, .yaml or .yml."
            )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(
            f"Invalid configuration syntax in {config_path}"
        ) from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("Configuration root must be an object or mapping.")

    source = os.environ if environ is None else environ
    overrides = _environment_overrides(source)
    merged = _merge_config(data, overrides)
    return SentinelConfig.model_validate(merged)
