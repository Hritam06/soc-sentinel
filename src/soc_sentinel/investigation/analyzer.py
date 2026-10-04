from soc_sentinel.core.models import SecurityEvent


def analyze(event: SecurityEvent, alerts: list[str]) -> dict:
    return {
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "username": event.username,
        "alerts": alerts,
        "risk": "high" if alerts else "low",
        "recommendation": (
            "Investigate repeated authentication failures and verify the account."
            if alerts
            else "No immediate investigation required."
        ),
    }
