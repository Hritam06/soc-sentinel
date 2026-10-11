import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from soc_sentinel.main import process_event
from soc_sentinel.investigation.correlation import correlate_login_failures
from soc_sentinel.normalization.normalizer import normalize_event


def _load_jsonl(text: str) -> list[dict]:
    events = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON on line {line_number}: {exc.msg}"
            ) from exc
        if not isinstance(event, dict):
            raise ValueError(
                f"Line {line_number} must contain a JSON object"
            )
        events.append(event)
    return events


def _load_input(args: argparse.Namespace) -> list[dict]:
    if args.event is not None:
        try:
            event = json.loads(args.event)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON supplied to --event: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise ValueError("--event must contain a JSON object")
        return [event]

    if args.file:
        path = Path(args.file)
        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".jsonl":
            return _load_jsonl(content)

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc.msg}") from exc

        if isinstance(data, dict):
            return [data]
        if isinstance(data, list) and all(isinstance(item, dict) for item in data):
            return data
        raise ValueError("JSON input must be an event object or an array of event objects")

    if not sys.stdin.isatty():
        return _load_jsonl(sys.stdin.read())

    raise ValueError("Provide --event, --file, or JSON through stdin")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Sentinel security event processor"
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--event", help="JSON security event")
    input_group.add_argument(
        "--file",
        help="Path to a JSON or JSONL security event file",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    args = parser.parse_args()

    try:
        raw_events = _load_input(args)
        reports = [process_event(event) for event in raw_events]
        normalized_events = [normalize_event(event) for event in raw_events]
        correlations = correlate_login_failures(normalized_events)
    except (OSError, ValueError, ValidationError) as exc:
        parser.exit(2, f"{parser.prog}: error: {exc}\n")

    if args.format == "json":
        print(json.dumps({"reports": reports, "correlations": correlations}, indent=2))
    else:
        print("\n\n".join(reports))


if __name__ == "__main__":
    main()
