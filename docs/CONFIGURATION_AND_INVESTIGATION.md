# Configuration and Investigation

## Configuration loading

SOC Sentinel accepts YAML (`.yaml` / `.yml`) and JSON configuration files.
Configuration is validated with Pydantic models. Unknown fields are rejected.

`load_config(path)` retains the existing interface. Optional environment
overrides can be supplied through `SOC_SENTINEL__` variables. Nested keys
are separated with double underscores and are case-insensitive.

Examples:

- `SOC_SENTINEL__DETECTION__BRUTE_FORCE_THRESHOLD=8`
- `SOC_SENTINEL__SUPPRESSION__ENABLED=false`
- `SOC_SENTINEL__INVESTIGATION__CORRELATION_WINDOW_MINUTES=15`

Values are parsed as JSON scalars when possible. Invalid values and unknown
settings fail validation rather than being silently ignored. Environment
overrides take precedence over file values. The `environ` argument allows
deterministic tests without changing the process environment.

Allowlisted IP addresses are parsed and canonicalized. Duplicate IPs and
account names are removed while preserving their first occurrence. Invalid
IP addresses and empty account names are rejected.

## Investigation configuration

The investigation settings provide a validated correlation window and
explicit contextual scoring bonus limits. Defaults preserve existing
behaviour.

## Explainable risk scoring

The risk score is a deterministic prioritization aid:

1. Each alert contributes its severity weight multiplied by confidence.
2. Asset criticality adds 0, 10, or 20 points for normal, high, or critical.
3. Attack progression adds an explicitly supplied integer from 0 to 20.
4. The final score is capped at 100.

The returned `score_breakdown` exposes every contribution and the uncapped
total. Default arguments add no contextual bonuses, preserving the prior
severity/confidence calculation. The score is not a probability and does
not establish compromise.

## Operational limitations

Environment variables are configuration inputs and should be protected
accordingly. Do not put secrets in configuration files or shell history.
Risk context must be supplied from verified investigation context; the
library does not infer asset criticality or attack progression.


## Runtime integration

The V3.0.0 CLI consumes the investigation configuration:
- `investigation.correlation_window_minutes` controls cross-event correlation.
- `investigation.high_asset_bonus` and `investigation.critical_asset_bonus`
  control the corresponding explicit asset-criticality scoring bonuses.
- `investigation.progression_bonus_max` limits the explicitly supplied
  progression score accepted by the risk assessor.

The CLI does not infer asset criticality or attack progression. Without
verified contextual inputs, the defaults remain normal asset criticality
and zero progression bonus. Direct callers can supply verified context
through the risk-assessment API.
