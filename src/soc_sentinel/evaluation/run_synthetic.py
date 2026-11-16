"""Reproducible event-level synthetic detection evaluation."""

import json
import time
from pathlib import Path

from soc_sentinel.detection.rules import (
    detect_authentication_alerts,
    detect_network_alerts,
    detect_suspicious_dns_alerts,
)
from soc_sentinel.evaluation.metrics import (
    evaluate_rules,
    format_evaluation_text,
    write_evaluation_json,
)
from soc_sentinel.ingestion.loader import load_events


ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "datasets" / "synthetic"
EVENTS_FILE = DATA / "events.jsonl"
LABELS_FILE = DATA / "ground_truth.json"
REPORT_FILE = DATA / "evaluation-results.json"

LABEL_TO_RULE = {
    "brute_force": "brute_force_login_attempts",
    "password_spray": "password_spray_attempts",
    "failure_then_success": "failure_then_success",
    "port_scan": "port_scan",
    "connection_fanout": "connection_fanout",
    "suspicious_dns": "suspicious_dns",
}
ALIASES = {
    "brute_force": "brute_force_login_attempts",
    "brute_force_login_attempts": "brute_force_login_attempts",
    "password_spray": "password_spray_attempts",
    "password_spray_attempts": "password_spray_attempts",
    "failure_then_success": "failure_then_success",
    "port_scan": "port_scan",
    "connection_fanout": "connection_fanout",
    "suspicious_dns": "suspicious_dns",
    "suspicious_dns_query": "suspicious_dns",
}


def _read_json(path):
    content = path.read_text(encoding="utf-8").strip()
    while content.endswith("\\n"):
        content = content[:-2].rstrip()
    return json.loads(content)


def _read_jsonl(path):
    content = path.read_text(encoding="utf-8")
    try:
        return [json.loads(line) for line in content.splitlines() if line.strip()]
    except json.JSONDecodeError:
        parts = [p.strip() for p in content.split("\\n") if p.strip()]
        return [json.loads(part) for part in parts]


def _rule(alert, family):
    raw = str(getattr(alert, "rule", "")).strip()
    key = raw.lower().replace(" ", "_").replace("-", "_")
    if key in ALIASES:
        return ALIASES[key]
    if family == "dns":
        return "suspicious_dns"
    if raw:
        return raw
    raise ValueError(f"{family} alert has no rule identifier")


def run_evaluation():
    raw_events = _read_jsonl(EVENTS_FILE)
    labels_data = _read_json(LABELS_FILE)

    raw_ids = [str(item["event_id"]) for item in raw_events]
    if len(raw_ids) != len(set(raw_ids)):
        raise ValueError("Duplicate event IDs in dataset")

    events = load_events(raw_events)
    event_ids = {
        str(event.event_id)
        for event in events
        if getattr(event, "event_id", None) is not None
    }
    if len(event_ids) != len(events):
        raise ValueError("Loaded events have missing or duplicate IDs")

    labels = labels_data.get("labels", [])
    label_ids = [str(item["event_id"]) for item in labels]
    if len(label_ids) != len(set(label_ids)):
        raise ValueError("Duplicate ground-truth event IDs")
    if set(label_ids) != event_ids:
        raise ValueError("Dataset and ground-truth event IDs do not match")

    expected = {}
    for item in labels:
        label = str(item.get("ground_truth", "")).strip().lower()
        if label == "benign":
            continue
        rule = LABEL_TO_RULE.get(label)
        if rule is None:
            raise ValueError(f"Unsupported ground-truth label: {label}")
        expected.setdefault(rule, set()).add(str(item["event_id"]))

    predictions = {}
    latency = {}
    detectors = (
        ("authentication", detect_authentication_alerts,
         {"password_spray_threshold": 4}),
        ("network", detect_network_alerts, {}),
        ("dns", detect_suspicious_dns_alerts, {}),
    )

    for family, detector, kwargs in detectors:
        started = time.perf_counter()
        alerts = detector(events, **kwargs)
        latency[family] = round((time.perf_counter() - started) * 1000, 3)
        for alert in alerts:
            rule = _rule(alert, family)
            ids = getattr(alert, "event_ids", None)
            if ids is None:
                raise ValueError(f"{family} alert has no event_ids")
            ids = {str(value) for value in ids}
            unknown = ids - event_ids
            if unknown:
                raise ValueError(f"Detector returned unknown event IDs: {unknown}")
            predictions.setdefault(rule, set()).update(ids)

    result = evaluate_rules(
        expected, predictions, total_population=len(event_ids)
    )
    result["dataset"] = {
        "version": labels_data.get("dataset_version"),
        "events": len(event_ids),
        "labelled_events": len(label_ids),
    }
    result["matching_policy"] = (
        "Per-rule event-ID matching: intersection of ground-truth "
        "positive IDs and alert event_ids is TP; predicted IDs outside "
        "that rule's positive set are FP; missed positive IDs are FN; "
        "remaining events are TN."
    )
    result["latency_ms"] = latency
    result["limitations"].extend([
        "Latency is local detector execution time only.",
        "Only explicitly labelled positive scenarios are evaluated.",
        "Synthetic results do not establish production effectiveness.",
    ])
    write_evaluation_json(result, REPORT_FILE)
    return result


def main():
    result = run_evaluation()
    print(format_evaluation_text(result))
    print(f"Dataset events: {result['dataset']['events']}")
    print(f"Latency (ms): {result['latency_ms']}")
    print(f"JSON report: {REPORT_FILE}")


if __name__ == "__main__":
    main()
