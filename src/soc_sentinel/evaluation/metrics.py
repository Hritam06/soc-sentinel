"""Deterministic event-level binary and per-rule evaluation."""

import json
from pathlib import Path
from typing import Iterable


def calculate_metrics(
    expected: Iterable[str],
    predicted: Iterable[str],
    total_population: int | None = None,
) -> dict:
    """Calculate classification metrics using event identifiers.

    TN is zero when the complete negative population is not supplied.
    """
    expected = set(expected)
    predicted = set(predicted)

    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)

    if total_population is None:
        tn = 0
    else:
        if total_population < 0:
            raise ValueError("total_population cannot be negative")
        classified = len(expected | predicted)
        if classified > total_population:
            raise ValueError(
                "Classified event IDs exceed total evaluation population"
            )
        tn = total_population - classified

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def evaluate_rules(
    ground_truth: dict,
    predictions: dict,
    total_population: int | None = None,
) -> dict:
    """Evaluate labelled-positive event IDs independently for each rule."""
    rules = sorted(set(ground_truth) | set(predictions))
    per_rule = {
        rule: calculate_metrics(
            ground_truth.get(rule, set()),
            predictions.get(rule, set()),
            total_population,
        )
        for rule in rules
    }

    if total_population is None:
        expected = set().union(
            *(set(v) for v in ground_truth.values())
        ) if ground_truth else set()
        predicted = set().union(
            *(set(v) for v in predictions.values())
        ) if predictions else set()
        overall = calculate_metrics(expected, predicted)
    else:
        counts = {
            key: sum(item[key] for item in per_rule.values())
            for key in ("tp", "fp", "tn", "fn")
        }
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall else 0.0
        )
        overall = {
            **counts,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        }

    return {
        "evaluation_version": "2.0",
        "per_rule": per_rule,
        "overall": overall,
        "limitations": [
            "Metrics depend on the completeness and correctness of labels.",
            "Synthetic results do not establish production effectiveness.",
            "TN is zero when no complete evaluation population is supplied.",
            "Overall metrics are micro-averaged across rule/event classifications.",
        ],
    }


def write_evaluation_json(results: dict, path: str | Path) -> Path:
    """Write a deterministic machine-readable JSON report."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def format_evaluation_text(results: dict) -> str:
    """Format per-rule and aggregate metrics for terminal output."""
    lines = ["SOC Sentinel Detection Evaluation", "=" * 34]
    for rule, item in sorted(results["per_rule"].items()):
        lines.append(
            f"{rule}: TP={item['tp']} FP={item['fp']} "
            f"TN={item['tn']} FN={item['fn']} "
            f"Precision={item['precision']:.4f} "
            f"Recall={item['recall']:.4f} F1={item['f1']:.4f}"
        )
    overall = results["overall"]
    lines.extend([
        "",
        "Overall micro-average",
        f"TP={overall['tp']} FP={overall['fp']} "
        f"TN={overall['tn']} FN={overall['fn']}",
        f"Precision={overall['precision']:.4f} "
        f"Recall={overall['recall']:.4f} F1={overall['f1']:.4f}",
    ])
    return "\n".join(lines)
