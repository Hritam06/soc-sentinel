"""Tests for event-level synthetic evaluation."""

from soc_sentinel.evaluation.metrics import calculate_metrics
from soc_sentinel.evaluation.run_synthetic import run_evaluation


def test_metrics_calculate_true_negatives():
    result = calculate_metrics({"a", "b"}, {"b", "c"}, 5)
    assert (result["tp"], result["fp"], result["fn"], result["tn"]) == (
        1, 1, 1, 2
    )


def test_metrics_reject_impossible_population():
    try:
        calculate_metrics({"a", "b"}, {"b", "c"}, 2)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_synthetic_evaluation_reports_event_level_metrics_and_latency():
    result = run_evaluation()
    assert result["dataset"]["events"] == 46
    assert result["dataset"]["labelled_events"] == 46
    assert result["evaluation_version"] == "2.0"
    assert set(result["latency_ms"]) == {"authentication", "network", "dns"}
    assert all(value >= 0 for value in result["latency_ms"].values())
    assert result["per_rule"]
    assert "event-ID" in result["matching_policy"]
