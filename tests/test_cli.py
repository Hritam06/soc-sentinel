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
