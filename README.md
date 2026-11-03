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
    <a href="https://github.com/Hritam06/soc-sentinel/releases/tag/v2.0.0">
      <img src="https://img.shields.io/badge/release-v2.0.0-216e39" alt="Latest release v2.0.0">
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
    <a href="https://github.com/Hritam06/soc-sentinel/releases/tag/v2.0.0">Download v2.0.0</a>
  </p>
</div>

---

## Overview

SOC Sentinel is a defensive security-monitoring project for ingesting event data, identifying suspicious patterns, correlating related activity, and producing investigation reports.

Version **2.0.0** adds a structured event model and an opt-in investigation pipeline while retaining the original v1-compatible command-line path. It is designed as a small, inspectable toolkit that can be extended or used as a starting point for security automation.

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

### Install from the v2.0.0 source

```bash
git clone https://github.com/Hritam06/soc-sentinel.git
cd soc-sentinel
git checkout v2.0.0

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

# Structured v2 investigation report
soc-sentinel --file sample_events.jsonl --v2
```

The v2 mode emits a structured JSON report containing event, alert, correlation, and risk-assessment sections.

You can also pipe JSONL events through standard input:

```bash
cat sample_events.jsonl | soc-sentinel --v2
```

## v1 compatibility and the v2 pipeline

SOC Sentinel keeps the original CLI path as the default. Add `--v2` to opt into the newer event-validation, detection, correlation, alert-management, and reporting pipeline.

| Mode | Invocation | Output |
|---|---|---|
| v1-compatible | `soc-sentinel --file events.jsonl` | Human-readable text |
| v1-compatible JSON | `soc-sentinel --file events.jsonl --format json` | JSON with reports and login-failure correlations |
| v2 | `soc-sentinel --file events.jsonl --v2` | Structured v2 JSON investigation report |

The existing **v1.0.0** GitHub release remains available. See the [v2.0.0 release notes](https://github.com/Hritam06/soc-sentinel/releases/tag/v2.0.0).

## Detection coverage

The v2 detection catalogue currently includes these heuristic rules:

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

The v2 CLI accepts optional JSON or YAML configuration through `--config`. For example, create `config.yaml`:

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
  AUTH-001: high
  AUTH-002: high
  NET-001: medium
```

Run the v2 pipeline with that configuration:

```bash
soc-sentinel --file sample_events.jsonl --v2 --config config.yaml
```

Configuration is validated when loaded. Unknown keys and invalid values are rejected rather than silently accepted. The current CLI applies allowlists, suppression, rule-severity overrides, and selected detection thresholds/windows; **not every setting is enforced across every detection helper yet**. Review the settings model and current pipeline before relying on a configuration as a complete policy.

## Reports and investigation context

A v2 JSON report includes:

- Report version and generation timestamp
- Normalized events and event count
- Structured alerts and alert count
- Cross-event correlations
- A risk-assessment summary
- A reminder that detections are investigative indicators

The reporting module also provides helpers to build and write JSON and HTML reports:

- `soc_sentinel.reporting.v2_report.build_json_report`
- `soc_sentinel.reporting.v2_report.write_json_report`
- `soc_sentinel.reporting.v2_report.build_html_report`
- `soc_sentinel.reporting.v2_report.write_html_report`

HTML report data is escaped before rendering.

## Evaluation and tests

The repository includes a labelled synthetic dataset under `datasets/synthetic/`:

- `events.jsonl` — sample security events
- `ground_truth.json` — scenario labels
- `evaluation-results.json` — rule-presence evaluation output

Run the synthetic rule-presence evaluation from the repository root:

```bash
python -m soc_sentinel.evaluation.run_synthetic
```

Run the test suite:

```bash
python -m pytest -q tests/ --import-mode=importlib
```

The v2.0.0 release passed **123 local tests**. GitHub Actions also passed on **Python 3.11 and 3.12**.

### How to interpret the evaluation

The current synthetic evaluation checks whether expected scenarios are present and whether the corresponding detector fires. It is **not** event-level classification: the detectors do not yet return the triggering event IDs needed to support event-level true/false positives and negatives. Therefore, the project does not claim precision, recall, or F1 scores from this dataset. Synthetic results also do not establish real-world detection performance.

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
docs/                # Architecture, detection rules, and threat model
tests/               # Automated tests
```

## Security considerations and limitations

SOC Sentinel is an investigation aid, not a complete SIEM or incident-response platform.

- **Heuristic detections:** alerts can be false positives or false negatives; analyst validation is required.
- **Alert evidence:** current detector functions do not expose the triggering event IDs, so generated v2 alerts cannot yet provide complete event-level evidence.
- **In-memory suppression:** duplicate suppression is process-local and is not persisted between runs.
- **Configuration coverage:** some settings are not yet applied uniformly across all detection functions.
- **No durable backend:** the project does not currently provide a database-backed alert store.
- **No access-control layer:** authentication and role-based access control are not included.
- **No packet inspection:** the project analyzes supplied event records; it does not capture traffic or inspect full network sessions.
- **Synthetic evaluation:** sample data is useful for repeatable tests, but it is not proof of production effectiveness.

For the threat assumptions, controls, and operational guidance, read the [Threat Model](docs/THREAT_MODEL.md). Avoid placing credentials or unnecessary personal data in event metadata, and restrict access to source events and generated reports.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Detection Rules](docs/DETECTION_RULES.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Changelog](CHANGELOG.md)
- [MIT License](LICENSE)

## Contributing

Issues and pull requests are welcome. For changes to detection logic, include focused tests and describe the expected event pattern, relevant fields, thresholds, and known false-positive considerations.

## License

SOC Sentinel is released under the [MIT License](LICENSE).
