import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from soc_sentinel.main import process_event
from soc_sentinel.investigation.correlation import correlate_login_failures
from soc_sentinel.normalization.normalizer import normalize_event
from soc_sentinel.ingestion.loader import load_events
from soc_sentinel.detection.rules import (
    detect_authentication, detect_network, detect_suspicious_dns,
)
from soc_sentinel.investigation.correlation import correlate_security_events
from soc_sentinel.reporting.v2_report import build_json_report
from soc_sentinel.alerts.models import SecurityAlert
from soc_sentinel.alerts.manager import AlertManager
from soc_sentinel.config.settings import SentinelConfig, load_config
from soc_sentinel.investigation.risk import assess_risk


def _load_jsonl(text: str) -> list[dict]:
    events = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON on line {line_number}: {exc.msg}"
            ) from exc
        if not isinstance(event, dict):
            raise ValueError(
                f"Line {line_number} must contain a JSON object"
            )
        events.append(event)
    return events


def _load_input(args: argparse.Namespace) -> list[dict]:
    if args.event is not None:
        try:
            event = json.loads(args.event)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON supplied to --event: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise ValueError("--event must contain a JSON object")
        return [event]

    if args.file:
        path = Path(args.file)
        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".jsonl":
            return _load_jsonl(content)

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc.msg}") from exc

        if isinstance(data, dict):
            return [data]
        if isinstance(data, list) and all(isinstance(item, dict) for item in data):
            return data
        raise ValueError("JSON input must be an event object or an array of event objects")

    if not sys.stdin.isatty():
        return _load_jsonl(sys.stdin.read())

    raise ValueError("Provide --event, --file, or JSON through stdin")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Sentinel security event processor"
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--event", help="JSON security event")
    input_group.add_argument(
        "--file",
        help="Path to a JSON or JSONL security event file",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--v2", action="store_true",
        help="Use the v2 detection and investigation pipeline",
    )
    parser.add_argument("--config", help="Optional JSON or YAML v2 configuration")
    args = parser.parse_args()

    try:
        raw_events = _load_input(args)
        if args.v2:
            events = load_events(raw_events)
            config = load_config(args.config) if args.config else SentinelConfig()

            allowed_ips = set(config.allowlists.ips)
            allowed_accounts = set(config.allowlists.accounts)
            eligible = [
                event for event in events
                if event.source_ip not in allowed_ips
                and event.username not in allowed_accounts
            ]

            settings = config.detection
            detections = (
                detect_authentication(
                    eligible,
                    brute_force_threshold=settings.brute_force_threshold,
                    password_spray_threshold=settings.password_spray_threshold,
                    window_minutes=settings.authentication_window_minutes,
                )
                + detect_network(
                    eligible,
                    port_scan_threshold=settings.port_scan_threshold,
                    fanout_threshold=settings.connection_fanout_threshold,
                    window_minutes=settings.network_window_minutes,
                )
                + detect_suspicious_dns(
                    eligible,
                    minimum_length=settings.dns_minimum_length,
                )
            )

            rule_ids = {
                "brute_force_login_attempts": "AUTH-001",
                "password_spray_attempts": "AUTH-002",
                "failure_then_success": "AUTH-003",
                "multi_source_account_targeting": "AUTH-004",
                "authentication_failure_burst": "AUTH-005",
                "port_scan": "NET-001",
                "connection_fanout": "NET-002",
                "suspicious_dns_query": "DNS-001",
            }
            manager = AlertManager(
                window_minutes=config.suppression.window_minutes,
                enabled=config.suppression.enabled,
            )
            for name in detections:
                rule_id = rule_ids.get(name, name.upper())
                severity = config.severity.get(rule_id, "medium")
                manager.add(SecurityAlert(
                    rule_id=rule_id,
                    rule_name=name,
                    severity=severity,
                    confidence=0.55,
                    explanation=(
                        "A detection heuristic matched the supplied event batch. "
                        "The current detector does not expose triggering event IDs; "
                        "investigate source evidence before drawing conclusions."
                    ),
                    recommended_actions=(
                        "Review the relevant source events.",
                        "Validate the activity with the system owner.",
                    ),
                ))

            alerts = list(manager.alerts) if hasattr(manager, "alerts") else []
            if not alerts:
                alerts = list(getattr(manager, "_alerts", {}).values())
            correlations_v2 = correlate_security_events(eligible)
            risk = assess_risk(alerts, event_count=len(events))
            report = build_json_report(events, alerts, correlations_v2, risk)
            print(json.dumps(report, indent=2, sort_keys=True))
            return

        reports = [process_event(event) for event in raw_events]
        normalized_events = [normalize_event(event) for event in raw_events]
        correlations = correlate_login_failures(normalized_events)
    except (OSError, ValueError, TypeError, ValidationError) as exc:
        parser.exit(2, f"{parser.prog}: error: {exc}\n")

    if args.format == "json":
        print(json.dumps({"reports": reports, "correlations": correlations}, indent=2))
    else:
        print("\n\n".join(reports))


if __name__ == "__main__":
    main()
