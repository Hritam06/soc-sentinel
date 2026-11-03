# SOC Sentinel Threat Model

## Assets

- Security event data and metadata.
- Detection alerts and investigation evidence.
- Configuration and allowlists.

## Potential threats

- Malformed or oversized event input.
- Spoofed or misleading event fields.
- High-volume events intended to exhaust processing resources.
- Sensitive information exposed through logs or reports.
- False positives and false negatives from heuristic rules.

## Security controls

- Input validation through Pydantic models.
- IP address and port validation.
- UTC timestamp normalization.
- HTML escaping in generated reports.
- Explicit errors for malformed input.

## Limitations

- No authentication or role-based access control.
- No durable alert storage.
- No encryption-at-rest feature.
- No guarantee that detections identify confirmed attacks.
- Synthetic evaluation data does not establish real-world detection performance.

## Operational guidance

Restrict access to event files and reports. Avoid storing credentials or unnecessary personal data in event metadata. Review alerts before taking incident-response action.
