# Changelog

## 2.0.0 - 2026-11-04

### Added
- Expanded security event schema and UTC timestamp normalization.
- Authentication, network, and DNS detection utilities.
- YAML and JSON configuration models.
- Built-in detection rule catalogue.
- Cross-event correlation utilities.
- Structured alerts and in-memory duplicate suppression.
- Risk assessment and MITRE ATT&CK mappings.
- JSON and HTML reporting utilities.
- Synthetic labelled dataset and evaluation metrics.
- Structured JSON logging.
- Dedicated v2 feature tests.

### Changed
- CLI adds structured logging verbosity.
- Added PyYAML dependency.

### Compatibility
- Legacy v1 functionality and CLI options are retained.
- Published v1.0.0 release and tag remain unchanged.

### Status
Released. Local validation passed (123 tests); GitHub Actions passed on Python 3.11 and 3.12. Detection evaluation is rule-presence validation only and does not claim event-level precision, recall, or F1.

## 1.0.0
Original published release.
