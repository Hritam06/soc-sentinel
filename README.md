# SOC Sentinel

A defensive cybersecurity project for analyzing security events, detecting suspicious activity, assessing risk, preserving investigation evidence, and producing incident reports.

## Overview

SOC Sentinel turns raw security events into structured information that can support security monitoring and investigation.

The project follows a workflow covering event ingestion, normalization, detection, risk assessment, investigation, and reporting.

## Objectives

- Ingest and validate security events
- Normalize events into a consistent structure
- Detect suspicious activity using rules
- Assess alert severity and risk
- Preserve investigation evidence
- Generate incident reports
- Maintain automated test coverage

## Security Operations Workflow

1. Ingest security-event data
2. Normalize event fields
3. Validate event structure
4. Apply detection rules
5. Assess alert severity and risk
6. Preserve evidence and event references
7. Review incident findings

## Project Structure

- `src/soc_sentinel/core/` — event models and core logic
- `src/soc_sentinel/detection/` — detection rules, alert models, and risk scoring
- `src/soc_sentinel/ingestion/` — event ingestion and validation
- `src/soc_sentinel/investigation/` — investigation and evidence handling
- `src/soc_sentinel/normalization/` — event normalization and field aliases
- `src/soc_sentinel/reporting/` — incident reporting
- `tests/` — automated tests
- `sample_event.json` — sample security event
- `sample_events.jsonl` — sample events in JSON Lines format

## Current Capabilities

The current development version includes the following capabilities in the working tree; not all are part of the `v0.3.0` release:

- JSON event ingestion
- JSON Lines event processing
- Event normalization using common telemetry field aliases
- Structured event validation
- IPv4 and IPv6 address validation
- Additional structured event metadata
- Rule-based detection
- High-severity login-failure detection
- Suspicious source-IP detection
- Brute-force login-attempt detection
- Password-spray detection
- Severity-based risk scoring for detection alerts
- Investigation evidence and event ID fields on alerts
- Automated tests for event models, normalization, detection, risk scoring, and evidence handling

The event model supports context such as source and destination IP addresses, ports, protocols, usernames, hosts, processes, actions, outcomes, severity, messages, and additional metadata.

### Alert Risk Scores

Risk scores are mapped by alert severity:

| Severity | Risk score |
|---|---:|
| Low | 25 |
| Medium | 50 |
| High | 75 |
| Critical | 100 |

These alert scores are deterministic severity-based scores, not calibrated probabilities of compromise.

### Investigation Risk Score

The investigation report uses a separate contextual score:

- Base score by event severity: Low = 10, Medium = 30, High = 60, Critical = 90.
- Each detected alert adds 10 points, up to a maximum alert bonus of 40.
- The final score is capped at 100.

The investigation risk label is derived from the final score:

| Score | Risk level |
|---|---|
| 0–29 | Low |
| 30–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

Alert risk scores and investigation risk scores serve different purposes and use different mappings. Neither score is a calibrated probability of compromise.


### Incident Lifecycle

SOC Sentinel includes an in-memory incident lifecycle model. An incident starts
with the `new` status and supports these transitions:

- `new` → `investigating` or `false_positive`
- `investigating` → `resolved` or `false_positive`
- `resolved` and `false_positive` are terminal statuses in the current model.

Invalid transitions are rejected. Incident state is held in memory only; this
model does not currently provide persistence or CLI integration.

### Event Correlation

The investigation correlation helper groups login-failure events by source IP
within a configurable, inclusive time window. It supports a configurable
minimum event threshold and returns structured evidence including the source
IP, time range, event count, timestamps, usernames, and event IDs when present.
Groups may overlap when multiple qualifying windows exist.

The helper is available through
`src/soc_sentinel/investigation/correlation.py`. The CLI includes batch
correlation evidence in JSON output under `correlations`, alongside event report
strings in `reports`. Correlation evidence is not currently included in text
reports or integrated into the incident lifecycle.

## Example

Process a sample event:

```bash
soc-sentinel --file sample_event.json
```

Process a JSON Lines file:

```bash
soc-sentinel --file sample_events.jsonl --format json
```

The report output depends on the event data and the pipeline's implemented functionality.

## Testing

Run the automated test suite:

```bash
pytest -q
```

At the `v0.3.0` release checkpoint, **38 tests passed**. The latest local verification of the current working tree passed **107 tests**. This is a local result, not a claim that hosted CI has passed.

Run the tests after making changes to check for regressions.

## Development

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Install the project in editable mode:

```bash
pip install -e .
```

Run the tests:

```bash
pytest -q
```

Run the command-line tool:

```bash
soc-sentinel --file sample_event.json
```

## Continuous Integration

GitHub Actions is configured to run the test suite on pushes and pull requests using Python 3.11 and 3.12. The workflow has been checked locally for YAML structure; a successful hosted run has not yet been verified.

## Design Approach

SOC Sentinel is organized into modules with separate responsibilities for event models, ingestion, normalization, detection, investigation, and reporting.

This structure helps keep the security workflow testable and easier to extend.

## Security Focus

SOC Sentinel is intended for defensive cybersecurity work, security monitoring, incident analysis, and detection engineering.

Sample events are intended for controlled testing and demonstration. They do not represent access to real systems or actual security incidents.

## Roadmap

Potential future improvements include:

- Broader security-event coverage
- Additional detection rules
- More detailed investigation workflows
- Improved analyst output
- Expanded test coverage
- Additional security telemetry sources
- Further improvements to detection and risk analysis

## Version

Latest released version: `v0.3.0`

The current working tree prepares the planned `v1.0.0` release. It is not released until the final verification passes and the release tag is published.

GitHub repository: https://github.com/Hritam06/soc-sentinel

The project is under active development. Releases are versioned to make changes to the security-analysis workflow easier to track.
