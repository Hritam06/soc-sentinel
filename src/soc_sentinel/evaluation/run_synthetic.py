"""Run reproducible rule-level evaluation on the synthetic dataset."""
import json
from pathlib import Path
from soc_sentinel.ingestion.loader import load_events
from soc_sentinel.detection.rules import (
    detect_brute_force, detect_password_spray, detect_failure_then_success,
    detect_multi_source_account_targeting, detect_authentication_burst,
    detect_port_scan, detect_connection_fanout, detect_suspicious_dns,
)

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "datasets" / "synthetic"
events = [json.loads(line) for line in (DATA / "events.jsonl").read_text().splitlines() if line.strip()]
labels = json.loads((DATA / "ground_truth.json").read_text())["labels"]
loaded = load_events(events)
expected = {}
for item in labels:
    if item["ground_truth"] != "benign":
        expected.setdefault(item["ground_truth"], set()).add(item["event_id"])

checks = {
    "brute_force": detect_brute_force(loaded, threshold=5),
    "password_spray": detect_password_spray(loaded, threshold=4),
    "failure_then_success": detect_failure_then_success(loaded),
    "multi_source_account_targeting": detect_multi_source_account_targeting(loaded),
    "authentication_failure_burst": detect_authentication_burst(loaded),
    "port_scan": detect_port_scan(loaded),
    "connection_fanout": detect_connection_fanout(loaded),
    "suspicious_dns": detect_suspicious_dns(loaded),
}
results = {
    "evaluation_version": "1.0",
    "dataset_events": len(loaded),
    "labelled_events": len(labels),
    "rule_presence": {
        rule: {"expected_scenario_present": bool(expected.get(rule)), "detector_fired": bool(fired)}
        for rule, fired in checks.items()
    },
    "limitations": [
        "This is rule-presence evaluation, not event-level classification.",
        "Detection functions currently return rule names rather than triggering event IDs.",
        "No event-level TP, FP, TN, FN, precision, recall or F1 is claimed.",
        "The password-spray evaluation threshold is four to match the four-event synthetic scenario.",
        "Synthetic results do not establish production effectiveness."
    ]
}
out = DATA / "evaluation-results.json"
out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\\n")
print(json.dumps(results, indent=2))
