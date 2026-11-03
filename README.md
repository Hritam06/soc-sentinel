# SOC Sentinel

SOC Sentinel is a Python-based security event detection and investigation toolkit.

## Project status

Version 2.0.0 is released. The published v1.0.0 release remains available. The v2 pipeline is available through the opt-in `--v2` CLI mode; the default CLI path retains v1-compatible behavior.

## Features

- Security event ingestion and normalization.
- Authentication detection utilities.
- Network port-scan and connection fan-out detection.
- Suspicious DNS query heuristics.
- Cross-event correlation.
- Structured alerts and duplicate suppression.
- Risk assessment and MITRE ATT&CK mappings.
- JSON and HTML report generation.
- Synthetic labelled data and evaluation metrics.
- Structured JSON logging.

## Architecture

The project is organized into ingestion, normalization, detection, correlation, alert management, investigation, reporting, configuration, and evaluation modules.

See [Architecture](docs/ARCHITECTURE.md), [Detection Rules](docs/DETECTION_RULES.md), and [Threat Model](docs/THREAT_MODEL.md).

## Requirements

- Python 3.11 or later.
- Pydantic 2 or later.
- PyYAML 6 or later.

## Installation

Clone the repository and install it:

```bash
git clone https://github.com/Hritam06/soc-sentinel.git
cd soc-sentinel
python3 -m pip install -e .


Usage
Show available CLI options:
soc-sentinel --help


Process a JSON event:
soc-sentinel --event '{"timestamp":"2026-01-01T00:00:00Z","source":"firewall","event_type":"connection","source_ip":"192.0.2.10"}'


Process an event file:
soc-sentinel --file sample_events.jsonl


Select JSON output:
soc-sentinel --file sample_events.jsonl --format json


Set logging verbosity:
soc-sentinel --file sample_events.jsonl --log-level INFO


Configuration
The v2 CLI accepts `--config` for JSON or YAML settings. Allowlists, selected detection thresholds, severity mappings, and in-memory suppression are wired into v2 processing. Not every configuration value is applied by every detector. The current detector interface also does not attach triggering event IDs to generated alerts, and suppression is not durable.
Synthetic evaluation data
The datasets/synthetic/ directory contains labelled synthetic events and ground-truth definitions.

Synthetic data is useful for repeatable tests, but does not establish real-world detection accuracy. No production detection-performance claims are made.
Tests
Run the test suite:
python3 -m pytest -q


The local test suite passed **123 tests**. GitHub Actions also passed the test workflow on Python **3.11** and **3.12** for the release commit.
Security and limitations
- Detection results are investigative signals, not confirmation of malicious activity.
- Alert suppression is in-memory and is not durable.
- No database, authentication layer, or role-based access control is provided.
- No packet capture or full network protocol inspection is performed.
- Review reports and alerts before taking response actions.
See SECURITY.md and Threat Model.
Roadmap
- Apply all configuration values consistently across every detection rule.
- Attach triggering event IDs and supporting evidence to each alert.
- Expand synthetic evaluation to event-level TP/FP/TN/FN and precision/recall/F1 metrics.
- Add durable alert storage and suppression where persistence is required.
- Expand validation with representative real-world telemetry.
License
See LICENSE.
