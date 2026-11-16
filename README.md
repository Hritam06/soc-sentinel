<!--
  SOC Sentinel
  Project documentation: https://github.com/Hritam06/soc-sentinel
-->

<div align="center">
  <h1>SOC Sentinel</h1>
  <p><strong>A Python toolkit for security-event detection, correlation, and investigation.</strong></p>
  <p>
    Turn normalized security events into actionable investigative signals —
    with a lightweight CLI, configurable heuristics, structured alerts, and reports.
  </p>
  <p>
    <a href="https://github.com/Hritam06/soc-sentinel/releases/tag/v3.0.0">
      <img src="https://img.shields.io/badge/release-v3.0.0-216e39" alt="Latest release v3.0.0">
    </a>
    <a href="https://github.com/Hritam06/soc-sentinel/actions/workflows/tests.yml">
      <img src="https://github.com/Hritam06/soc-sentinel/actions/workflows/tests.yml/badge.svg" alt="Tests">
    </a>
    <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB" alt="Python 3.11 or later">
    <a href="LICENSE">
      <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License">
    </a>
  </p>
  <p>
    <a href="#quick-start">Quick start</a> ·
    <a href="#detection-coverage">Detection coverage</a> ·
    <a href="#configuration">Configuration</a> ·
    <a href="https://github.com/Hritam06/soc-sentinel/releases/tag/v3.0.0">Download v3.0.0</a>
  </p>
</div>

---

## Overview


Version 3.0.0 extends the existing SOC Sentinel pipeline with event-level alert provenance and traceability, labelled synthetic detection evaluation, and integrated configuration and investigation controls. The existing command-line compatibility path is retained. Evaluation results are based on controlled synthetic scenarios and do not establish production detection performance.

SOC Sentinel is a defensive security-monitoring project for ingesting event data, identifying suspicious patterns, correlating related activity, and producing investigation reports.

Version **3.0.0** builds on the structured event and investigation pipeline with event-level alert provenance, traceable evidence, labelled synthetic evaluation, and integrated configuration and investigation controls. The original v1-compatible command-line path and the existing `--v2` option name are retained for compatibility.

### What it provides

- **Event ingestion and normalization** — accept JSON and JSONL events, validate known fields, normalize IP addresses and timestamps, and retain the raw event.
- **Authentication analytics** — identify repeated login failures, password spraying, failure-then-success sequences, multi-source account targeting, and authentication bursts.
- **Network and DNS heuristics** — flag port-scan-like activity, connection fan-out, and suspiciously long or high-entropy DNS queries.
- **Correlation and alert management** — group related events, create structured alerts, and suppress duplicates within a process-local time window.
- **Investigation context** — calculate a heuristic risk assessment and include relevant MITRE ATT&CK technique mappings.
- **Reporting** — produce structured JSON reports and render reports as self-contained HTML.
- **Configuration** — load validated JSON or YAML settings for thresholds, allowlists, suppression, and severity overrides.

> **Important:** SOC Sentinel produces investigative signals, not a verdict that an event is malicious. Validate findings against source telemetry and your environment before taking response actions.

## Quick start

### Requirements

- Python **3.11 or later**
- Pydantic **2.x**
- PyYAML **6.x**

### Install from the v3.0.0 source

```bash
git clone https://github.com/Hritam06/soc-sentinel.git
cd soc-sentinel
git checkout v3.0.0

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install .
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Confirm the command is available:

```bash
soc-sentinel --help
```

### Process a single event

The default CLI path preserves the v1-compatible reporting behavior:

```bash
soc-sentinel \
  --event '{"timestamp":"2026-11-04T10:30:00Z","source":"linux-auth","event_type":"login_failure","source_ip":"192.0.2.25","username":"analyst","outcome":"failure","severity":"high"}' \
  --format json
```

### Process an event file

SOC Sentinel accepts a JSON event, a JSON array of events, or a JSONL file containing one event object per line:

```bash
# Original v1-compatible path
soc-sentinel --file sample_events.jsonl

# Structured investigation report (existing --v2 option)
soc-sentinel --file sample_events.jsonl --v2
```

The structured mode, invoked using the retained `--v2` option, emits a JSON report containing event, alert, correlation, and risk-assessment sections.

You can also pipe JSONL events through standard input:

```bash
cat sample_events.jsonl | soc-sentinel --v2
```

## CLI compatibility and the structured investigation pipeline

SOC Sentinel keeps the original v1-compatible CLI path as the default. Add the existing `--v2` option to invoke the structured event-validation, detection, correlation, alert-management, and reporting pipeline. The option name is retained for backward compatibility; the current project release is V3.0.0.

| Mode | Invocation | Output |
|---|---|---|
| v1-compatible | `soc-sentinel --file events.jsonl` | Human-readable text |
| v1-compatible JSON | `soc-sentinel --file events.jsonl --format json` | JSON with reports and login-failure correlations |
| Structured investigation | `soc-sentinel --file events.jsonl --v2` | Structured JSON investigation report |

The existing **v1.0.0** GitHub release remains available. See the [V3.0.0 release notes](https://github.com/Hritam06/soc-sentinel/releases/tag/v3.0.0).

## Detection coverage

The V3.0.0 detection catalogue includes these heuristic rules:

| Rule | Area | Detection intent |
|---|---|---|
| **AUTH-001** | Authentication | Repeated login failures (brute-force-like activity) |
| **AUTH-002** | Authentication | Password spraying across accounts |
| **AUTH-003** | Authentication | Login failure followed by a successful login |
| **AUTH-004** | Authentication | Multiple source IPs targeting one account |
| **AUTH-005** | Authentication | Authentication failure bursts |
| **NET-001** | Network | One source contacting many destination ports on a target |
| **NET-002** | Network | One source connecting to many destination hosts |
| **DNS-001** | DNS | Unusually long or high-entropy DNS queries |

Rules use thresholds, time windows, and event fields to identify patterns worth investigating. Their output depends on event quality, the selected settings, and the behavior of the source systems.

See [Detection Rules](docs/DETECTION_RULES.md) for the catalogue and [Architecture](docs/ARCHITECTURE.md) for the processing components.

## Configuration

The structured CLI pipeline accepts optional JSON or YAML configuration through `--config`. For example, create `config.yaml`:

```yaml
detection:
  brute_force_threshold: 5
  password_spray_threshold: 5
  port_scan_threshold: 10
  connection_fanout_threshold: 10
  authentication_window_minutes: 5
  network_window_minutes: 5
  dns_minimum_length: 50

allowlists:
  ips:
    - "192.0.2.10"
  accounts:
    - "service-account"

suppression:
  enabled: true
  window_minutes: 15

severity:
  low: low
  medium: medium
  high: critical
  critical: critical
```

Run the structured pipeline with that configuration:

```bash
soc-sentinel --file sample_events.jsonl --v2 --config config.yaml
```

Configuration is validated when loaded. Unknown keys and invalid values are rejected rather than silently accepted. The CLI applies allowlists, suppression, severity-category overrides, configured authentication and network thresholds/windows, DNS minimum length, and investigation settings through their supported processing paths. Severity overrides are keyed by severity category (`low`, `medium`, `high`, or `critical`), not by detection rule ID. Standalone helpers do not necessarily accept every configuration setting.

## Reports and investigation context

The structured JSON report includes:

- Report version and generation timestamp
- Normalized events and event count
- Structured alerts and alert count
- Cross-event correlations
- A risk-assessment summary and score breakdown
- Event-level alert identifiers and supported evidence context
- Source and target entities, triggering conditions, and recommended actions where supplied
- A reminder that detections are investigative indicators

The reporting module also provides helpers to build and write JSON and HTML reports:

- `soc_sentinel.reporting.v2_report.build_json_report`
- `soc_sentinel.reporting.v2_report.write_json_report`
- `soc_sentinel.reporting.v2_report.build_html_report`
- `soc_sentinel.reporting.v2_report.write_html_report`

HTML report data is escaped before rendering.

V3.0.0 adds event identifiers and evidence context to supported alert results, together with source and target entity context, triggering conditions, and recommended actions where supplied by the detection path. Investigation correlation records supported relationships between authentication and network activity. Risk assessments expose a score breakdown; asset criticality and attack progression remain explicit inputs and are not inferred automatically by the CLI.

## Evaluation and tests

The repository includes a labelled synthetic dataset under `datasets/synthetic/`:

- `events.jsonl` — sample security events
- `ground_truth.json` — scenario labels
- `evaluation-results.json` — event-ID-based evaluation output

Run the event-level synthetic evaluation from the repository root:

```bash
python -m soc_sentinel.evaluation.run_synthetic
```

Run the test suite:

```bash
python -m pytest -q tests/ --import-mode=importlib
```

The V3.0.0 regression suite passed **161 tests locally on Python 3.14.8**. GitHub Actions passed on **Python 3.11 and 3.12**.

The synthetic evaluation uses 46 labelled events and evaluates six detection rules using event-ID matching. Results describe only the supplied synthetic scenarios. Aggregate true-negative counts are summed across rule-level classifications and must not be interpreted as a count of distinct benign events.

### How to interpret the evaluation

The synthetic evaluation matches expected and predicted event identifiers independently for each rule. It calculates true positives, false positives, false negatives and true negatives, together with precision, recall and F1. True negatives are calculated from the supplied evaluation population and summed across rule-level classifications in the aggregate metrics. These results are limited to the labelled synthetic scenarios; they do not establish production detection performance or generalization to unseen environments.

## Project structure

```text
src/soc_sentinel/
├── alerts/          # Alert models and in-memory deduplication
├── config/          # Validated JSON/YAML settings
├── core/            # Security event and severity models
├── detection/       # Detection rules and rule catalogue
├── evaluation/      # Synthetic evaluation and metric helpers
├── incidents/       # Incident models
├── ingestion/       # Event loading and validation
├── investigation/   # Correlation and risk assessment
├── normalization/   # Event normalization
├── reporting/       # v1 and v2 report generation
└── utils/           # Shared utilities

datasets/synthetic/  # Synthetic events, labels, and evaluation output
docs/                # Architecture, detection, threat model, and configuration
tests/               # Automated tests
```

## Security considerations and limitations

SOC Sentinel is an investigation aid, not a complete SIEM or incident-response platform.

- **Heuristic detections:** alerts can be false positives or false negatives; analyst validation is required.
- **Alert evidence:** supported V3.0.0 detection results carry event identifiers and evidence context. Traceability depends on the quality and integrity of the ingested source events.
- **In-memory suppression:** duplicate suppression is process-local and is not persisted between runs.
- **Configuration coverage:** validated settings are passed through their supported CLI detection and investigation paths; standalone helpers do not necessarily accept every setting.
- **No durable backend:** the project does not currently provide a database-backed alert store.
- **No access-control layer:** authentication and role-based access control are not included.
- **No packet inspection:** the project analyzes supplied event records; it does not capture traffic or inspect full network sessions.
- **Synthetic evaluation:** sample data is useful for repeatable tests, but it is not proof of production effectiveness.

For the threat assumptions, controls, and operational guidance, read the [Threat Model](docs/THREAT_MODEL.md). Avoid placing credentials or unnecessary personal data in event metadata, and restrict access to source events and generated reports.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Detection Rules](docs/DETECTION_RULES.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Configuration and Investigation](docs/CONFIGURATION_AND_INVESTIGATION.md)
- [Changelog](CHANGELOG.md)
- [MIT License](LICENSE)

## Contributing

Issues and pull requests are welcome. For changes to detection logic, include focused tests and describe the expected event pattern, relevant fields, thresholds, and known false-positive considerations.

## License

SOC Sentinel is released under the [MIT License](LICENSE).
