"""Deterministic binary and per-rule detection evaluation."""

import json
from pathlib import Path


def calculate_metrics(expected: set[str], predicted: set[str]) -> dict:
    """Calculate binary classification metrics for a set of event IDs."""
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    tn = 0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def evaluate_rules(ground_truth: dict, predictions: dict) -> dict:
    """Evaluate each rule and aggregate event-level predictions.

    ground_truth maps rule names to sets of labelled-positive event IDs.
    predictions maps rule names to sets of detected event IDs.
    """
    rules = sorted(set(ground_truth) | set(predictions))
    per_rule = {}
    all_expected = set()
    all_predicted = set()

    for rule in rules:
        expected = set(ground_truth.get(rule, set()))
        predicted = set(predictions.get(rule, set()))
        per_rule[rule] = calculate_metrics(expected, predicted)
        all_expected.update(expected)
        all_predicted.update(predicted)

    return {
        "evaluation_version": "1.0",
        "per_rule": per_rule,
        "overall": calculate_metrics(all_expected, all_predicted),
        "limitations": [
            "TN is reported as zero because an explicit negative population is not supplied.",
            "Metrics depend on the completeness and correctness of ground-truth labels.",
            "Synthetic evaluation does not establish production detection effectiveness.",
        ],
    }


def write_evaluation_json(results: dict, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(results, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return destination


def format_evaluation_text(results: dict) -> str:
    lines = ["SOC Sentinel Detection Evaluation", "=" * 34]
    for rule, metrics in sorted(results["per_rule"].items()):
        lines.append(
            f"{rule}: TP={metrics['tp']} FP={metrics['fp']} "
            f"TN={metrics['tn']} FN={metrics['fn']} "
            f"Precision={metrics['precision']:.4f} "
            f"Recall={metrics['recall']:.4f} F1={metrics['f1']:.4f}"
        )
    overall = results["overall"]
    lines.extend([
        "",
        "Overall",
        f"TP={overall['tp']} FP={overall['fp']} "
        f"TN={overall['tn']} FN={overall['fn']}",
        f"Precision={overall['precision']:.4f} "
        f"Recall={overall['recall']:.4f} F1={overall['f1']:.4f}",
        "",
        "Limitations:",
        *[f"- {item}" for item in results["limitations"]],
    ])
    return "\n".join(lines)
