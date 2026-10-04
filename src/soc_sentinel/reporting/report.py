from soc_sentinel.core.models import SecurityEvent


def build_report(event: SecurityEvent, investigation: dict) -> str:
    return "\n".join(
        [
            "SOC INCIDENT REPORT",
            "===================",
            f"Event Type: {event.event_type}",
            f"Source: {event.source}",
            f"Source IP: {event.source_ip or 'N/A'}",
            f"Username: {event.username or 'N/A'}",
            f"Risk: {investigation['risk']}",
            f"Alerts: {', '.join(investigation['alerts']) or 'None'}",
            f"Recommendation: {investigation['recommendation']}",
        ]
    )
