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

Rules are heuristic detections, not proof of malicious activity. Thresholds and windows are configurable in the settings model, but are not yet enforced across every detection path.
