"""Validated, configurable detection rule catalogue."""

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class RuleDefinition(BaseModel):
    """Metadata and configuration for one detection rule."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    rule_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    category: str = Field(min_length=1)
    enabled: bool = True
    severity: str = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    threshold: int = Field(default=1, ge=1)
    window_minutes: int = Field(default=5, ge=1)
    mitre_attack: list[str] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        value = value.lower()
        if value not in {"low", "medium", "high", "critical"}:
            raise ValueError("severity must be low, medium, high, or critical")
        return value


BUILTIN_RULES = (
    RuleDefinition(
        rule_id="AUTH-001",
        name="Brute-force login attempts",
        description="Repeated login failures from one source within a time window.",
        category="authentication",
        severity="high",
        confidence=0.75,
        threshold=5,
        window_minutes=5,
        mitre_attack=["T1110"],
    ),
    RuleDefinition(
        rule_id="AUTH-002",
        name="Password spraying",
        description="Login failures against multiple accounts from one source.",
        category="authentication",
        severity="high",
        confidence=0.8,
        threshold=5,
        window_minutes=5,
        mitre_attack=["T1110.003"],
    ),
    RuleDefinition(
        rule_id="AUTH-003",
        name="Failure followed by success",
        description="A successful login follows one or more failures.",
        category="authentication",
        severity="medium",
        confidence=0.6,
        threshold=1,
        window_minutes=10,
        mitre_attack=["T1078"],
    ),
    RuleDefinition(
        rule_id="AUTH-004",
        name="Account targeted from multiple sources",
        description="Multiple source IP addresses target the same account.",
        category="authentication",
        severity="medium",
        confidence=0.6,
        threshold=3,
        window_minutes=10,
        mitre_attack=["T1110"],
    ),
    RuleDefinition(
        rule_id="AUTH-005",
        name="Authentication failure burst",
        description="A burst of authentication failures occurs in a short window.",
        category="authentication",
        severity="high",
        confidence=0.7,
        threshold=10,
        window_minutes=1,
        mitre_attack=["T1110"],
    ),
    RuleDefinition(
        rule_id="NET-001",
        name="Port scan",
        description="One source contacts multiple destination ports on one target.",
        category="network",
        severity="medium",
        confidence=0.7,
        threshold=10,
        window_minutes=5,
        mitre_attack=["T1046"],
    ),
    RuleDefinition(
        rule_id="NET-002",
        name="Connection fan-out",
        description="One source connects to multiple destination hosts.",
        category="network",
        severity="medium",
        confidence=0.65,
        threshold=10,
        window_minutes=5,
        mitre_attack=["T1046"],
    ),
    RuleDefinition(
        rule_id="DNS-001",
        name="Unusually long DNS query",
        description="A DNS query exceeds the configured length heuristic.",
        category="dns",
        severity="low",
        confidence=0.4,
        threshold=50,
        window_minutes=5,
        mitre_attack=["T1071.004"],
    ),
)


class RuleCatalogue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[RuleDefinition] = Field(default_factory=list)

    @field_validator("rules")
    @classmethod
    def unique_rule_ids(cls, rules: list[RuleDefinition]) -> list[RuleDefinition]:
        ids = [rule.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule_id values must be unique")
        return rules


def load_rule_catalog(path: str | Path | None = None) -> RuleCatalogue:
    """Load a validated rule catalogue, or return built-in defaults."""
    if path is None:
        return RuleCatalogue(rules=list(BUILTIN_RULES))

    config_path = Path(path)
    try:
        content = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Unable to read rule catalogue: {exc}") from exc

    try:
        if config_path.suffix.lower() == ".json":
            data: Any = json.loads(content)
        elif config_path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(content)
        else:
            raise ValueError("Rule catalogue must use .json, .yaml, or .yml")
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Invalid rule catalogue syntax: {exc}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("Rule catalogue root must be an object")
    return RuleCatalogue.model_validate(data)
