# SOC Sentinel Architecture

## Core modules

1. Ingestion and validation
2. Event normalization and UTC timestamps
3. Authentication, network, and DNS detection
4. Cross-event correlation
5. Alert management and duplicate suppression
6. Risk assessment and MITRE ATT&CK mappings
7. JSON and HTML reporting
8. Synthetic-data evaluation

## Reliability

- Malformed input raises explicit errors.
- Original event data is preserved.
- Alert suppression is process-local, not durable.
- Detection findings require analyst validation.

## Current limitation

Configuration enforcement across every detection path remains future integration work.
