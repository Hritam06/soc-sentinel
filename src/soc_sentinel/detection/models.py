from dataclasses import dataclass, field


SEVERITY_RISK_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


@dataclass(frozen=True)
class DetectionAlert:
    rule: str
    severity: str
    message: str
    evidence: tuple[str, ...] = field(default_factory=tuple)
    event_ids: tuple[str, ...] = field(default_factory=tuple)

    @property
    def risk_score(self) -> int:
        """Return a deterministic risk score based on alert severity."""
        try:
            return SEVERITY_RISK_SCORES[self.severity.lower()]
        except (AttributeError, KeyError) as exc:
            raise ValueError(
                f"Unsupported alert severity: {self.severity!r}"
            ) from exc
