# SOC Sentinel

A practical Security Operations Center (SOC) platform for analyzing security events, detecting suspicious activity, investigating incidents, and producing clear analyst findings.
## Overview

SOC Sentinel is a defensive cybersecurity project built around a simple idea: turn raw security events into information that an analyst can actually use.

The project follows a security monitoring workflow that covers event processing, normalization, detection, investigation, and reporting.
## Objectives

- Collect and analyze security-event data
- Normalize events from different sources
- Detect suspicious and potentially malicious activity
- Develop and test detection rules
- Investigate security incidents
- Map relevant activity to MITRE ATT&CK techniques
- Preserve useful evidence for investigation
- Produce structured incident reports
- Maintain a tested and reproducible codebase
## Security Operations Workflow

SOC Sentinel follows a simple investigation flow:

1. Receive security-event data
2. Normalize the event into a consistent format
3. Apply detection rules
4. Assess severity and generate alerts
5. Investigate the activity and collect relevant evidence
6. Map useful findings to MITRE ATT&CK techniques
7. Produce a report that explains what happened and what should be checked next


## Project Structure

The project is organized into separate modules so that event ingestion, normalization, detection, investigation, and reporting can be developed and tested independently.

- `src/soc_sentinel/` contains the application code
- `src/soc_sentinel/core/` contains shared models and core logic
- `src/soc_sentinel/detection/` contains detection rules and models
- `src/soc_sentinel/ingestion/` handles incoming security events
- `src/soc_sentinel/investigation/` handles incident analysis
- `src/soc_sentinel/normalization/` prepares events for consistent processing
- `src/soc_sentinel/reporting/` produces incident reports
- `tests/` contains the automated test suite
- `sample_event.json` contains a sample security event
- `sample_events.jsonl` contains multiple sample events

## Current Capabilities

The current version provides the foundation for an end-to-end security event analysis workflow, including:

- JSON event ingestion
- JSON Lines event processing
- Event normalization
- Rule-based detection
- Risk assessment
- Alert generation
- Basic incident investigation
- Structured incident reporting
- Command-line execution
- Automated tests

## Example

A security event can be processed directly from the command line:

    soc-sentinel --file sample_event.json

The sample event contains fields such as the timestamp, source, event type, source IP address, username, severity, and message. The platform processes these fields and produces an incident report with the relevant risk, alert, and recommendation information.

Multiple events can also be processed from a JSON Lines file:

    soc-sentinel --file sample_events.jsonl --format json

## Testing

The project uses `pytest` for automated testing.

Run the complete test suite with:

    pytest -q

The tests cover the main parts of the application, including event models, ingestion, normalization, detection, investigation, reporting, command-line behaviour, and end-to-end processing.

Tests are kept alongside the application code so that new changes can be checked before they become part of a release.

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

SOC Sentinel is built as a modular Python project. Each major stage of the security workflow has its own responsibility, which keeps the code easier to test, understand, and extend.

Event ingestion, normalization, detection, investigation, and reporting are kept separate so that changes in one part of the workflow do not unnecessarily affect the others.

## Security Focus

SOC Sentinel is intended for defensive cybersecurity work, security monitoring, incident analysis, and detection engineering.

The sample events are designed for controlled testing and demonstration. They do not represent access to real systems or real security incidents.

## Roadmap

The project will be developed in stages, with each version adding and testing a specific part of the security analysis workflow.

Planned areas of development include:

- Broader security-event coverage
- Additional detection rules
- Improved severity and risk scoring
- Stronger investigation workflows
- MITRE ATT&CK technique mapping
- Evidence tracking
- More detailed reporting
- Expanded test coverage
- Better analyst usability
- Additional security telemetry sources
- Improved documentation

## Version

Current release: v0.1.0

The project is under active development. Future releases will expand its detection, investigation, reporting, and analysis capabilities.
