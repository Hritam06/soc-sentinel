# SOC Sentinel

A practical Security Operations Center (SOC) platform for analyzing security events, detecting suspicious activity, investigating incidents, and producing clear analyst findings.

## Overview

SOC Sentinel is a defensive cybersecurity project built around a simple idea: turn raw security events into information that an analyst can actually use.

The project follows a security monitoring workflow that covers event ingestion, normalization, detection, risk assessment, investigation, and reporting.

## Objectives

- Collect and analyze security-event data
- Normalize events into a consistent structure
- Detect suspicious and potentially malicious activity
- Develop and test detection rules
- Assess severity and risk
- Investigate security incidents
- Preserve useful evidence for investigation
- Produce structured incident reports
- Maintain a tested and reproducible codebase

## Security Operations Workflow

SOC Sentinel follows a simple investigation flow:

1. Receive security-event data
2. Normalize the event into a consistent format
3. Apply detection rules
4. Assess severity and risk
5. Generate alerts
6. Investigate the activity and collect relevant evidence
7. Produce a report with the findings and recommended next steps

## Project Structure

The project is organized into separate modules so that each part of the security workflow can be developed and tested independently.

- `src/soc_sentinel/core/` contains shared event models and core logic
- `src/soc_sentinel/detection/` contains detection rules and alert models
- `src/soc_sentinel/ingestion/` handles incoming security events
- `src/soc_sentinel/investigation/` handles incident analysis and evidence
- `src/soc_sentinel/normalization/` prepares events for consistent processing
- `src/soc_sentinel/reporting/` produces incident reports
- `tests/` contains the automated test suite
- `sample_event.json` contains a sample security event
- `sample_events.jsonl` contains multiple sample events

## Current Capabilities

The current release, `v0.2.0`, provides:

- JSON event ingestion
- JSON Lines event processing
- Event normalization
- Structured security-event modeling
- Rule-based detection
- Severity assessment
- Risk scoring
- Alert generation
- Incident investigation
- Evidence collection from processed events
- Structured incident reporting
- Command-line execution
- Automated testing

The event model supports common security-event context such as source and destination IP addresses, ports, protocols, usernames, hosts, processes, actions, outcomes, severity, and event messages.

## Example

A security event can be processed directly from the command line:

    soc-sentinel --file sample_event.json

Multiple events can also be processed from a JSON Lines file:

    soc-sentinel --file sample_events.jsonl --format json

The processing pipeline takes the event through normalization, detection, risk assessment, investigation, and reporting.

## Testing

The project uses `pytest` for automated testing.

Run the complete test suite with:

    pytest -q

The current test suite contains 24 tests covering event models, ingestion, normalization, detection, investigation, reporting, command-line behaviour, and end-to-end processing.

Tests are kept alongside the application code so that changes can be checked before they become part of a release.

## Development

Create and activate a virtual environment:

    python3 -m venv .venv
    source .venv/bin/activate

Install the project dependencies:

    pip install -r requirements.txt

Install the project in editable mode:

    pip install -e .

Run the tests:

    pytest -q

Run the command-line tool:

    soc-sentinel --file sample_event.json

## Design Approach

SOC Sentinel is built as a modular Python project. Event ingestion, normalization, detection, investigation, and reporting have separate responsibilities.

This keeps the security workflow easier to test, understand, and extend as new event types and detection logic are added.

## Security Focus

SOC Sentinel is intended for defensive cybersecurity work, security monitoring, incident analysis, and detection engineering.

The sample events are designed for controlled testing and demonstration. They do not represent access to real systems or real security incidents.

## Roadmap

Future versions will build on the current event-analysis pipeline.

Planned areas include:

- Broader security-event coverage
- Additional detection rules
- More detailed investigation workflows
- Improved analyst output
- Expanded test coverage
- Additional security telemetry sources
- Further improvements to detection and risk analysis

## Version

Current release: `v0.2.0`

The project is under active development. Each release is kept versioned so that changes to the security-analysis workflow can be tracked clearly.
