# Detection Rules

## Authentication

- AUTH-001: Repeated login failures (brute force).
- AUTH-002: Password spraying across accounts.
- AUTH-003: Login failure followed by success.
- AUTH-004: Multiple source IPs targeting one account.
- AUTH-005: Authentication failure bursts.

## Network

- NET-001: One source contacting many destination ports on a target.
- NET-002: One source connecting to many destination hosts.

## DNS

- DNS-001: Suspiciously long or high-entropy DNS queries.

## Interpretation

Supported detection and investigation settings are validated centrally and passed through the corresponding CLI processing paths. This does not imply that every standalone helper accepts or enforces every setting.

# V3.0.0 Detection Catalogue

### Authentication
- AUTH-001: Repeated login failures / brute-force activity.
- AUTH-002: Password-spray attempts.
- AUTH-003: Authentication failure followed by success.
- AUTH-004: Multiple accounts targeted from a source.
- AUTH-005: Authentication bursts.

### Network
- NET-001: Port scanning.
- NET-002: Connection fan-out.

### DNS
- DNS-001: Suspicious DNS characteristics, including unusually long or high-entropy query names.

### Interpretation
Detection rules are heuristic and depend on the supplied event data and configured thresholds. Synthetic evaluation results are limited to the labelled scenarios and do not establish production effectiveness.
