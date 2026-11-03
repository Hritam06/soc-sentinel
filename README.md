# SOC Sentinel

SOC Sentinel is a Python-based security event detection and investigation toolkit.

## Project status

Version 2.0.0 is under development. The published v1.0.0 release remains unchanged. V2 features are implemented as modular components; full integration across the CLI and detection pipeline is still in progress.

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
Configuration models support detection thresholds, time windows, allowlists, suppression settings, and severity mappings. YAML and JSON loading are supported.

Configuration enforcement across every detection path and complete CLI integration are not yet implemented.
Synthetic evaluation data
The datasets/synthetic/ directory contains labelled synthetic events and ground-truth definitions.

Synthetic data is useful for repeatable tests, but does not establish real-world detection accuracy. No production detection-performance claims are made.
Tests
Run the test suite:
python3 -m pytest -q


The current local test suite contains 123 passing tests. Python 3.11 and 3.12 CI compatibility still requires verification.
Security and limitations
- Detection results are investigative signals, not confirmation of malicious activity.
- Alert suppression is in-memory and is not durable.
- No database, authentication layer, or role-based access control is provided.
- No packet capture or full network protocol inspection is performed.
- Review reports and alerts before taking response actions.
See SECURITY.md and Threat Model.
Roadmap
- Complete end-to-end v2 CLI integration.
- Enforce configuration consistently across detection paths.
- Expand integration and boundary testing.
- Verify supported Python versions in CI.
- Prepare the v2.0.0 release after final validation.
License
See LICENSE.
