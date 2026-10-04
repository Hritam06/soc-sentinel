from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionAlert:
    rule: str
    severity: str
    message: str
