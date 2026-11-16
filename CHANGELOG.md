# Changelog


## 3.0.0 - 2026-11-17

### Added
- Event-level alert provenance and traceability, including event identifiers, source and target entities, triggering conditions and recommended actions in supported alert results.
- Synthetic detection evaluation using labelled event identifiers, with precision, recall, F1 and rule-level classification metrics.
- Configuration and investigation controls, including validated environment overrides, configurable correlation windows and explainable risk-score contributions.
- Investigation correlation for supported authentication and network activity relationships.
- Configuration and investigation documentation.

### Changed
- Alert aggregation retains and merges supported event evidence and triggering-condition context.
- Investigation risk scoring supports explicit asset-criticality and attack-progression inputs, with configurable bonuses and a maximum score of 100.
- Configuration validation includes allowlist normalization and duplicate handling.
- Regression coverage expanded for evidence, evaluation, configuration, investigation and CLI integration.

### Compatibility
- Existing V1-compatible processing and the existing structured pipeline command-line interface are retained.
- Existing default risk-scoring behavior is preserved unless optional investigation inputs or settings are supplied.
- Python requirement remains >=3.11.

### Status
- Release preparation; local validation is recorded below.
- Local regression suite: 161 tests passed on Python 3.14.8.
- Python 3.11 and 3.12 CI results must be verified separately.
- Synthetic evaluation does not establish production detection effectiveness.


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
