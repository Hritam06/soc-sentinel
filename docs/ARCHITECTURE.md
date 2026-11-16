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

Configuration is validated centrally and supplied to the supported CLI detection and investigation paths. Environment overrides use the `SOC_SENTINEL__` prefix and are subject to strict configuration validation.


The V3.0.0 pipeline carries event-level provenance into supported alert results. Alert aggregation retains associated event identifiers and triggering conditions. Investigation correlation records supported relationships between authentication and network activity, while risk scoring exposes its component contributions. Asset criticality and progression are explicit inputs rather than automatically inferred facts.
