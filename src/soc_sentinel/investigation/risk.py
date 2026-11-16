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

ASSET_CRITICALITY_BONUS = {
    "normal": 0,
    "high": 10,
    "critical": 20,
}


def assess_risk(
    alerts: list,
    event_count: int = 0,
    *,
    asset_criticality: str = "normal",
    progression_score: int = 0,
    high_asset_bonus: int = 10,
    critical_asset_bonus: int = 20,
    progression_bonus_max: int = 20,
) -> dict:
    """Return a deterministic, explainable investigation priority score.

    Alert contribution = severity weight multiplied by confidence.
    Asset criticality and attack progression are explicit additive bonuses.
    The final score is capped at 100 and is not a probability.
    """
    if event_count < 0:
        raise ValueError("event_count cannot be negative")
    if asset_criticality not in ASSET_CRITICALITY_BONUS:
        raise ValueError(
            "asset_criticality must be normal, high or critical"
        )
    for name, value in (
        ("high_asset_bonus", high_asset_bonus),
        ("critical_asset_bonus", critical_asset_bonus),
        ("progression_bonus_max", progression_bonus_max),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if not 0 <= value <= 20:
            raise ValueError(f"{name} must be between 0 and 20")
    if isinstance(progression_score, bool) or not isinstance(
        progression_score, int
    ):
        raise ValueError("progression_score must be an integer")
    if not 0 <= progression_score <= progression_bonus_max:
        raise ValueError(
            "progression_score must be between 0 and progression_bonus_max"
        )

    contributions = []
    for alert in alerts:
        severity = str(alert.severity).lower()
        if severity not in SEVERITY_WEIGHTS:
            raise ValueError(f"Unsupported severity: {severity}")

        confidence = float(alert.confidence)
        if not 0 <= confidence <= 1:
            raise ValueError("Alert confidence must be between 0 and 1")

        contribution = round(SEVERITY_WEIGHTS[severity] * confidence)
        contributions.append({
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "severity": severity,
            "confidence": confidence,
            "contribution": contribution,
            "mitre_attack": MITRE_ATTACK.get(alert.rule_id, []),
        })

    alert_score = sum(item["contribution"] for item in contributions)
    asset_bonus = {
        "normal": 0,
        "high": high_asset_bonus,
        "critical": critical_asset_bonus,
    }[asset_criticality]
    uncapped_score = alert_score + asset_bonus + progression_score
    score = min(100, uncapped_score)

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
        "score_breakdown": {
            "alert_contributions": alert_score,
            "asset_criticality": asset_criticality,
            "asset_criticality_bonus": asset_bonus,
            "progression_score": progression_score,
            "uncapped_total": uncapped_score,
            "cap": 100,
        },
        "explanation": (
            "Risk score is the capped sum of severity weights multiplied "
            "by alert confidence, an explicit asset-criticality bonus, "
            "and an explicit attack-progression score. The score supports "
            "investigative prioritization; it is not a probability or "
            "proof of compromise. Defaults add no contextual bonus."
        ),
    }
