from soc_sentinel.core.models import SecurityEvent
from soc_sentinel.detection.rules import detect
from soc_sentinel.investigation.analyzer import analyze
from soc_sentinel.normalization.normalizer import normalize_event
from soc_sentinel.reporting.report import build_report


def process_event(raw_event: dict) -> str:
    event: SecurityEvent = normalize_event(raw_event)
    alerts = detect(event)
    investigation = analyze(event, alerts)
    return build_report(event, investigation)


if __name__ == "__main__":
    raw_event = {
        "timestamp": "2026-10-05T03:20:00+00:00",
        "source": "authentication",
        "event": "login_failure",
        "src_ip": "192.168.1.50",
        "username": "admin",
        "severity": "high",
        "message": "Failed authentication attempt",
    }

    print(process_event(raw_event))
