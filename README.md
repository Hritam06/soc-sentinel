# SOC Sentinel

SOC Sentinel is a Python security monitoring project that processes security events, identifies suspicious login activity, assigns risk scores, and records evidence for investigation.

It provides a practical starting point for exploring event validation, normalization, detection rules, correlation, and incident handling in a defensive security workflow.

**Version:** 1.0.0

**Minimum Python version:** 3.11

**Locally tested with:** Python 3.14.8

**CI-tested versions:** Python 3.11 and 3.12

**Repository:** https://github.com/Hritam06/soc-sentinel

## Features

- Read security events from JSON and JSON Lines files.
- Validate event structure and supported fields.
- Normalize common telemetry field aliases.
- Detect high-severity login failures, suspicious source IP addresses, brute-force attempts, and password-spray activity.
- Assign severity-based alert risk scores.
- Calculate a separate contextual investigation risk score.
- Preserve event identifiers and supporting investigation evidence.
- Correlate login failures by source IP and time window.
- Track incident status and reject unsupported transitions.
- Generate command-line reports.

Detection results depend on the input data and the rules implemented in the project. An alert is a reason to investigate, not proof of compromise.


## Installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Python versions beyond those listed above have not yet been verified in this project's test matrix.

## Usage

Text report:

    soc-sentinel --file sample_event.json

JSON output:

    soc-sentinel --file sample_event.json --format json

Process JSON Lines input:

    soc-sentinel --file sample_events.jsonl --format json

## Testing

Install the test runner and run the suite:

    python -m pip install pytest
    python -m pytest -q

The continuous integration workflow tests Python 3.11 and 3.12.

## Detection scope and limitations

Detection rules use the event fields and thresholds implemented in the project. Brute-force and password-spray detection functions are available in the detection module; the CLI also performs login-failure correlation. Suspicious source IP checks use a small configured list, not a continuously updated threat-intelligence feed.

Risk scores help prioritize review; they do not establish that an account or host is compromised. Incident status tracking is in memory and is not persisted between runs. Review alerts and supporting evidence before taking action.
