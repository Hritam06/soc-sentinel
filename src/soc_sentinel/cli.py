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
    detect_authentication_alerts,
    detect_network_alerts,
    detect_suspicious_dns_alerts,
)
from soc_sentinel.detection.catalog import BUILTIN_RULES
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
            authentication_detections = detect_authentication_alerts(
                eligible,
                brute_force_threshold=settings.brute_force_threshold,
                password_spray_threshold=settings.password_spray_threshold,
                window_minutes=settings.authentication_window_minutes,
            )
            network_detections = detect_network_alerts(
                eligible,
                port_scan_threshold=settings.port_scan_threshold,
                fanout_threshold=settings.connection_fanout_threshold,
                window_minutes=settings.network_window_minutes,
            )
            dns_detections = detect_suspicious_dns_alerts(
                eligible,
                minimum_length=settings.dns_minimum_length,
            )
            detections = (
                authentication_detections
                + network_detections
                + dns_detections
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
            catalogue = {rule.rule_id: rule for rule in BUILTIN_RULES}
            events_by_id = {event.event_id: event for event in eligible}

            manager = AlertManager(
                window_minutes=config.suppression.window_minutes,
                enabled=config.suppression.enabled,
            )

            for detection in detections:
                rule_id = rule_ids[detection.rule]
                definition = catalogue[rule_id]
                matched_events = [
                    events_by_id[event_id]
                    for event_id in detection.event_ids
                    if event_id in events_by_id
                ]
                source_entities = tuple(sorted({
                    value
                    for event in matched_events
                    for value in (event.source_ip, event.host)
                    if value
                }))
                target_entities = tuple(sorted({
                    value
                    for event in matched_events
                    for value in (
                        event.username,
                        event.destination_ip,
                        event.destination_hostname,
                        event.dns_query,
                    )
                    if value
                }))
                manager.add(SecurityAlert(
                    rule_id=rule_id,
                    rule_name=definition.name,
                    severity=config.severity.get(
                        definition.severity, definition.severity
                    ),
                    confidence=definition.confidence,
                    explanation=detection.message,
                    event_ids=detection.event_ids,
                    source_entities=source_entities,
                    target_entities=target_entities,
                    triggering_conditions=detection.evidence,
                    evidence=tuple(
                        {
                            "event_id": event.event_id,
                            "original_source_id": event.original_source_id,
                            "original_event_reference": event.original_event_reference,
                            "event_timestamp": event.timestamp.isoformat(),
                            "ingestion_timestamp": event.ingestion_timestamp.isoformat(),
                            "parser_version": event.parser_version,
                            "schema_version": event.schema_version,
                            "raw_event": dict(event.raw_event),
                        }
                        for event in matched_events
                    ),
                    recommended_actions=(
                        "Review the triggering source events and validate the activity.",
                        "Investigate the involved accounts, hosts and network indicators.",
                    ),
                ))

            alerts = list(manager.alerts) if hasattr(manager, "alerts") else []
            if not alerts:
                alerts = list(getattr(manager, "_alerts", {}).values())
            correlations_v2 = correlate_security_events(
                eligible,
                window_minutes=config.investigation.correlation_window_minutes,
            )
            risk = assess_risk(
                alerts,
                event_count=len(events),
                high_asset_bonus=config.investigation.high_asset_bonus,
                critical_asset_bonus=config.investigation.critical_asset_bonus,
                progression_bonus_max=config.investigation.progression_bonus_max,
            )
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
