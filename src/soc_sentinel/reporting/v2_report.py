"""JSON and HTML reporting for v2 security investigations."""

import html
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


def _serialize(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "model_dump"):
        return _serialize(value.model_dump(mode="python"))
    if is_dataclass(value):
        return {key: _serialize(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize(item) for item in value]
    return value


def build_json_report(
    events: list,
    alerts: list,
    correlations: list,
    risk_assessment: dict | None = None,
) -> dict:
    """Build a deterministic, JSON-compatible investigation report."""
    return {
        "report_version": "2.0",
        "generated_at": datetime.now().astimezone().isoformat(),
        "event_count": len(events),
        "alert_count": len(alerts),
        "events": [_serialize(event) for event in events],
        "alerts": [_serialize(alert) for alert in alerts],
        "correlations": _serialize(correlations),
        "risk_assessment": _serialize(risk_assessment or {}),
        "disclaimer": "Detection results are investigative indicators, not confirmation of malicious activity.",
    }


def write_json_report(report: dict, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(_serialize(report), indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return destination


def build_html_report(report: dict) -> str:
    """Render a self-contained HTML report with escaped source data."""
    data = json.dumps(_serialize(report), indent=2, sort_keys=True, ensure_ascii=False)
    escaped = html.escape(data)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Sentinel Investigation Report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
h1{{font-size:1.8rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:1rem;border-radius:8px}}
.notice{{border-left:4px solid #777;padding:.5rem 1rem}}
</style>
</head>
<body>
<h1>SOC Sentinel Investigation Report</h1>
<p class="notice">Detection results are investigative indicators, not confirmation of malicious activity.</p>
<pre>{escaped}</pre>
</body>
</html>"""


def write_html_report(report: dict, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(build_html_report(report), encoding="utf-8")
    return destination
