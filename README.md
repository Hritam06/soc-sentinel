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

The `v0.3.0` release includes:

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

These are deterministic severity-based scores, not calibrated probabilities of compromise. The incident report may also display its own risk score; do not assume that every displayed risk score uses the same mapping.

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

At the `v0.3.0` release checkpoint, **38 tests passed**.

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

Current release: `v0.3.0`

GitHub repository: https://github.com/Hritam06/soc-sentinel

The project is under active development. Releases are versioned to make changes to the security-analysis workflow easier to track.
