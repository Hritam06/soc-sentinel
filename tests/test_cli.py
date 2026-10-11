import json
import subprocess
import sys


EVENT = {
    "timestamp": "2026-10-05T03:20:00+00:00",
    "source": "authentication",
    "event": "login_failure",
    "src_ip": "192.168.1.50",
    "username": "admin",
    "severity": "high",
    "message": "Failed authentication attempt",
}


def test_cli_file_input():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--file",
            "sample_event.json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "SOC INCIDENT REPORT" in result.stdout
    assert "Risk: high" in result.stdout
    assert "192.168.1.50" in result.stdout


def test_cli_json_output():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--event",
            json.dumps(EVENT),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)

    assert "reports" in output
    assert "SOC INCIDENT REPORT" in output["reports"][0]
    assert "Risk: high" in output["reports"][0]


def test_cli_invalid_json_shows_concise_error():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--event",
            "{invalid-json",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "error" in result.stderr.lower()


def test_cli_rejects_conflicting_input_options():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--event",
            json.dumps(EVENT),
            "--file",
            "sample_event.json",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "event" in result.stderr.lower()
    assert "file" in result.stderr.lower()


def test_cli_jsonl_batch_input(tmp_path):
    event_two = {
        **EVENT,
        "timestamp": "2026-10-05T03:21:00+00:00",
        "src_ip": "192.168.1.51",
        "username": "guest",
    }
    jsonl_file = tmp_path / "events.jsonl"
    jsonl_file.write_text(
        json.dumps(EVENT) + "\n" + json.dumps(event_two) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--file",
            str(jsonl_file),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)
    assert len(output["reports"]) == 2
    assert all("SOC INCIDENT REPORT" in report for report in output["reports"])


def test_cli_json_array_file_input(tmp_path):
    event_two = {
        **EVENT,
        "timestamp": "2026-10-05T03:21:00+00:00",
        "src_ip": "192.168.1.51",
        "username": "guest",
    }
    event_file = tmp_path / "events.json"
    event_file.write_text(
        json.dumps([EVENT, event_two]),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--file",
            str(event_file),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)
    assert len(output["reports"]) == 2


def test_cli_stdin_input():
    result = subprocess.run(
        [sys.executable, "-m", "soc_sentinel.cli", "--format", "json"],
        input=json.dumps(EVENT) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)
    assert len(output["reports"]) == 1
    assert "SOC INCIDENT REPORT" in output["reports"][0]


def test_cli_invalid_event_schema_shows_concise_error():
    invalid_event = {"timestamp": "not-a-timestamp", "source": "authentication"}

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--event",
            json.dumps(invalid_event),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "error" in result.stderr.lower()


def test_cli_empty_jsonl_file_returns_empty_reports(tmp_path):
    jsonl_file = tmp_path / "empty.jsonl"
    jsonl_file.write_text("\n  \n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--file",
            str(jsonl_file),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert json.loads(result.stdout) == {"reports": [], "correlations": []}


def test_cli_json_batch_includes_correlations(tmp_path):
    events = [
        {
            **EVENT,
            "timestamp": f"2026-10-05T03:2{minute}:00+00:00",
            "event_id": f"event-{minute}",
            "src_ip": "192.168.1.50",
        }
        for minute in range(3)
    ]
    event_file = tmp_path / "login-failures.json"
    event_file.write_text(json.dumps(events), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_sentinel.cli",
            "--file",
            str(event_file),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)
    assert len(output["reports"]) == 3
    assert len(output["correlations"]) == 1
    group = output["correlations"][0]
    assert group["correlation_type"] == "brute_force_login_attempts"
    assert group["source_ip"] == "192.168.1.50"
    assert group["event_count"] == 3
    assert [event["event_id"] for event in group["events"]] == [
        "event-0",
        "event-1",
        "event-2",
    ]
