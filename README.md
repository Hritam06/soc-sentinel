# SOC Sentinel

SOC Sentinel is a Python security monitoring project that turns raw security events into structured findings. It validates and normalizes event data, looks for suspicious login activity, assigns risk scores, and collects evidence that helps explain why an alert was raised.

The project follows a practical security operations workflow: ingest events, inspect them, identify suspicious patterns, and produce findings that an analyst can review.

**Current version:** `1.0.0`

**Python:** 3.11 and 3.12

**Repository:** https://github.com/Hritam06/soc-sentinel

## What it does

- **Event ingestion:** Read security events from JSON and JSON Lines files.
- **Data validation:** Check event structure and supported fields, including IPv4 and IPv6 addresses.
- **Event normalization:** Map common telemetry field aliases into a consistent event format.
- **Detection rules:** Identify high-severity login failures, suspicious source IP addresses, brute-force attempts, and password-spray activity.
- **Alert risk scoring:** Assign a score based on alert severity.
- **Investigation scoring:** Calculate a separate contextual risk score using event severity and detected alerts.
- **Evidence collection:** Retain relevant event IDs and investigation details with findings.
- **Event correlation:** Group login failures by source IP within a configurable time window.
- **Incident tracking:** Represent incident status and validate permitted status changes.
- **Command-line reporting:** Process event files and return structured findings.

Detection results depend on the supplied events and the implemented rules. SOC Sentinel supports analysis and does not replace an analyst's judgment.

## How it works

1. **Ingest:** Load events from a supported file format.
2. **Validate:** Check the event structure and supported field values.
3. **Normalize:** Convert recognized field aliases into a consistent representation.
4. **Detect:** Apply rules to identify suspicious activity.
5. **Assess:** Calculate alert severity scores and contextual investigation risk.
6. **Correlate:** Group related login failures and preserve supporting details.
7. **Review:** Examine the resulting findings and reports.

## Project structure

```text
soc-sentinel/
├── src/
│   └── soc_sentinel/
│       ├── core/             # Event models and core logic
│       ├── detection/        # Detection rules, alerts, and risk scoring
│       ├── ingestion/        # File ingestion and validation
│       ├── investigation/    # Evidence, correlation, and incident logic
│       ├── normalization/    # Field aliases and event normalization
│       └── reporting/        # Report generation
├── tests/                    # Automated tests
├── sample_event.json         # Single-event example
├── sample_events.jsonl       # JSON Lines example
├── pyproject.toml
└── README.md
