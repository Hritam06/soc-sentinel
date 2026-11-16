# Detection Evaluation Methodology

## Purpose and scope

SOC Sentinel includes a reproducible evaluation runner for measuring its supported detection rules against a labelled synthetic event dataset. The evaluation is intended to make the project's detection behaviour measurable and repeatable. It is not an independent benchmark, a production SOC trial, or evidence of real-world detection effectiveness.

## Dataset

The supplied dataset is located in `datasets/synthetic/`:

- `events.jsonl` contains the synthetic security events.
- `ground_truth.json` contains the event identifiers and their labels.
- `evaluation-results.json` contains the generated evaluation report.

The report identifies dataset version **1.1**, with **46 events** and **46 labelled events**. The runner verifies that event identifiers are unique and that the event IDs in the dataset and ground-truth labels match.

## Evaluated detection rules

The evaluation maps labelled scenarios to six detection rules:

| Evaluated rule | Ground-truth scenario |
|---|---|
| `brute_force_login_attempts` | Brute-force login attempts |
| `password_spray_attempts` | Password-spray attempts |
| `failure_then_success` | Authentication failure followed by success |
| `port_scan` | Port scanning |
| `connection_fanout` | Connection fan-out |
| `suspicious_dns` | Suspicious DNS activity |

The runner invokes the authentication, network and suspicious-DNS detectors against the loaded dataset. Alert event IDs are used to associate predictions with the labelled events.

## Matching and classification methodology

Matching is performed independently for each rule using event identifiers:

- **True positive (TP):** an event ID is present in both that rule's labelled-positive set and its predicted event IDs.
- **False positive (FP):** a predicted event ID is outside that rule's labelled-positive set.
- **False negative (FN):** a labelled-positive event ID is not predicted for that rule.
- **True negative (TN):** an event in the supplied evaluation population that is neither labelled positive nor predicted for that rule.

The runner supplies the complete dataset population size (46) to each rule-level calculation. Consequently, each rule is evaluated against the same 46-event population.

## Metrics

For each rule, the implementation calculates:

- **Precision:** TP / (TP + FP)
- **Recall:** TP / (TP + FN)
- **F1:** 2 × precision × recall / (precision + recall)

A metric whose denominator is zero is reported as 0.0.

The overall metrics are micro-averaged across rule/event classifications. The implementation sums the rule-level TP, FP, TN and FN counts before calculating overall precision, recall and F1.

**Important interpretation of TN:** the reported overall TN value of 240 is the sum of six rule-level TN counts. It represents 6 × 46 rule/event classifications less the 36 labelled positive rule/event cases. It does not represent 240 distinct benign events. The same dataset event can contribute to the negative population of multiple rules.

## Reproducing the evaluation

From the repository root, install the project and run the evaluation:

```bash
python -m pip install .
python -m soc_sentinel.evaluation.run_synthetic
```

The runner prints per-rule and overall metrics and writes the machine-readable report to:

`datasets/synthetic/evaluation-results.json`

Run the regression suite with:

```bash
python -m pytest -q tests/ --import-mode=importlib
```

The evaluation runner measures local detector execution time for the authentication, network and DNS detector calls. These timings are environment-dependent and are not end-to-end SOC response times.

## Results in the supplied report

The committed evaluation report records:

- Dataset: 46 events, all 46 labelled.
- Evaluated rules: six.
- Overall TP: 36.
- Overall FP: 0.
- Overall FN: 0.
- Overall TN: 240 rule/event classifications.
- Overall precision, recall and F1: 1.0 each.

Each of the six rules also records precision, recall and F1 of 1.0 in this supplied synthetic evaluation.

These values describe the tested dataset and scenarios only. They must not be interpreted as a claim of 100% detection accuracy in real environments.

## Limitations

- Metrics depend on the completeness and correctness of the ground-truth labels.
- The dataset is synthetic and does not represent the diversity or noise of production telemetry.
- Only explicitly labelled positive scenarios are evaluated; the results do not establish performance across all possible benign and malicious activity.
- A prediction outside a rule's labelled-positive set is counted as a false positive under this evaluation's matching policy. The result is therefore dependent on the scope and quality of the labels.
- Overall metrics are micro-averaged across rule/event classifications, not unique events across the entire system.
- Overall TN is the sum of six rule-level populations, not a count of distinct benign events.
- Reported latency measures local detector execution only. It excludes ingestion, external data collection, analyst review and response time.
- The evaluation does not measure production false-positive rates, analyst workload, alert fatigue, or operational effectiveness.
- Synthetic results do not establish production detection effectiveness.

## Interpretation

The evaluation demonstrates that the implemented rules reproduce the expected outcomes for the supplied labelled synthetic scenarios under the documented matching policy. It provides a repeatable baseline for future testing; broader validation requires representative, independently labelled telemetry and evaluation in realistic environments.
