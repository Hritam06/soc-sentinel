from soc_sentinel.core.models import SecurityEvent


def build_report(event: SecurityEvent, investigation: dict) -> str:
    evidence = investigation.get("evidence", {})
    alerts = investigation.get("alerts", [])

    return "\n".join(
        [
            "SOC INCIDENT REPORT",
            "===================",
            f"Event Type: {event.event_type}",
            f"Source: {event.source}",
            f"Source IP: {event.source_ip or 'N/A'}",
            f"Destination IP: {event.destination_ip or 'N/A'}",
            f"Username: {event.username or 'N/A'}",
            f"Host: {event.host or 'N/A'}",
            f"Process: {event.process_name or 'N/A'}",
            f"Action: {event.action or 'N/A'}",
            f"Outcome: {event.outcome or 'N/A'}",
            f"Severity: {event.severity.value}",
            f"Risk: {investigation.get('risk', 'N/A')}",
            f"Risk Score: {investigation.get('risk_score', 'N/A')}",
            f"Alerts: {', '.join(alerts) or 'None'}",
            f"Recommendation: {investigation['recommendation']}",
            "Evidence:",
            f"  Timestamp: {evidence.get('timestamp', event.timestamp.isoformat())}",
            f"  Message: {evidence.get('message', event.message or 'N/A')}",
        ]
    )
