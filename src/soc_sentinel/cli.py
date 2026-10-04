import argparse
import json
import sys

from soc_sentinel.main import process_event


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Sentinel security event processor"
    )

    parser.add_argument(
        "--event",
        help="JSON security event",
    )

    parser.add_argument(
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

    if args.event:
        raw_events = [json.loads(args.event)]

    elif args.file:
        with open(args.file, "r", encoding="utf-8") as file:
            if args.file.endswith(".jsonl"):
                raw_events = [
                    json.loads(line)
                    for line in file
                    if line.strip()
                ]
            else:
                raw_events = [json.load(file)]

    elif not sys.stdin.isatty():
        raw_events = [
            json.loads(line)
            for line in sys.stdin
            if line.strip()
        ]

    else:
        parser.error("Provide --event, --file, or JSON through stdin")

    reports = [process_event(event) for event in raw_events]

    if args.format == "json":
        print(json.dumps({"reports": reports}, indent=2))
    else:
        print("\n\n".join(reports))


if __name__ == "__main__":
    main()
