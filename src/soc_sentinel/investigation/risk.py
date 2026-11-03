"""Explainable risk assessment and MITRE ATT&CK mappings."""

SEVERITY_WEIGHTS = {
    "low": 10,
    "medium": 30,
    "high": 60,
    "critical": 80,
}

MITRE_ATTACK = {
    "AUTH-001": ["T1110"],
    "AUTH-002": ["T1110.003"],
    "AUTH-003": ["T1078"],
    "AUTH-004": ["T1110"],
    "AUTH-005": ["T1110"],
    "NET-001": ["T1046"],
    "NET-002": ["T1046"],
    "DNS-001": ["T1071.004"],
}


def assess_risk(alerts: list, event_count: int = 0) -> dict:
    """Return a reproducible score and an explanation of its contributors."""
    if event_count < 0:
        raise ValueError("event_count cannot be negative")

    contributions = []
    for alert in alerts:
        severity = str(alert.severity).lower()
        if severity not in SEVERITY_WEIGHTS:
            raise ValueError(f"Unsupported severity: {severity}")
        confidence = float(alert.confidence)
        if not 0 <= confidence <= 1:
            raise ValueError("Alert confidence must be between 0 and 1")
        weight = SEVERITY_WEIGHTS[severity]
        contribution = round(weight * confidence)
        contributions.append({
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "severity": severity,
            "confidence": confidence,
            "contribution": contribution,
            "mitre_attack": MITRE_ATTACK.get(alert.rule_id, []),
        })

    score = min(100, sum(item["contribution"] for item in contributions))
    level = (
        "critical" if score >= 80 else
        "high" if score >= 60 else
        "medium" if score >= 30 else
        "low"
    )

    return {
        "risk_score": score,
        "risk_level": level,
        "event_count": event_count,
        "contributors": contributions,
        "explanation": (
            "Risk score is the capped sum of severity weights multiplied "
            "by independent alert confidence. It is an investigative "
            "prioritization aid, not a probability or proof of compromise."
        ),
    }
