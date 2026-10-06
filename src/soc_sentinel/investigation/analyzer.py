from soc_sentinel.core.models import EventSeverity, SecurityEvent


SEVERITY_SCORES = {
    EventSeverity.LOW: 10,
    EventSeverity.MEDIUM: 30,
    EventSeverity.HIGH: 60,
    EventSeverity.CRITICAL: 90,
}


def calculate_risk_score(event: SecurityEvent, alerts: list[str]) -> int:
    base_score = SEVERITY_SCORES[event.severity]
    alert_score = min(len(alerts) * 10, 40)
    return min(base_score + alert_score, 100)


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def analyze(event: SecurityEvent, alerts: list[str]) -> dict:
    score = calculate_risk_score(event, alerts)
    level = risk_level(score)

    evidence = {
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "source": event.source,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "username": event.username,
        "host": event.host,
        "process_name": event.process_name,
        "action": event.action,
        "outcome": event.outcome,
        "message": event.message,
    }

    return {
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "username": event.username,
        "alerts": alerts,
        "risk_score": score,
        "risk": level,
        "evidence": evidence,
        "recommendation": (
            "Investigate the detected activity and verify the affected account or host."
            if alerts
            else "No immediate investigation required."
        ),
    }
