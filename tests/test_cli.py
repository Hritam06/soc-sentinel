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

def test_v2_cli_brute_force_alert_preserves_event_evidence(tmp_path):
    events = [
        {
            **EVENT,
            "event_id": f"v2-auth-{index}",
            "timestamp": f"2026-10-05T03:2{index}:00+00:00",
            "src_ip": "192.168.1.50",
            "username": "admin",
        }
        for index in range(5)
    ]
    event_file = tmp_path / "v2-auth-events.json"
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
            "--v2",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)
    brute_force_alerts = [
        alert for alert in output["alerts"]
        if alert["rule_id"] == "AUTH-001"
    ]

    assert len(brute_force_alerts) == 1
    alert = brute_force_alerts[0]
    assert set(alert["event_ids"]) == {
        f"v2-auth-{index}" for index in range(5)
    }
    assert alert["source_entities"] == ["192.168.1.50"]
    assert alert["target_entities"] == ["admin"]
    assert alert["severity"] == "high"
    assert alert["confidence"] == 0.75
    assert alert["triggering_conditions"]
    assert len(alert["evidence"]) == 5
    assert all(isinstance(item, dict) for item in alert["evidence"])
    assert {item["event_id"] for item in alert["evidence"]} == set(
        alert["event_ids"]
    )
    assert all(
        item["raw_event"]["event_id"] in alert["event_ids"]
        for item in alert["evidence"]
    )
    assert all(
        item["parser_version"] == "1.0.0"
        and item["schema_version"] == "1.0.0"
        for item in alert["evidence"]
    )



def test_v2_cli_port_scan_alert_preserves_event_evidence(tmp_path):
    events = [
        {
            "event_id": f"v2-network-{port}",
            "timestamp": f"2026-10-05T03:20:{index:02d}+00:00",
            "source": "firewall",
            "event": "connection",
            "category": "network",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "destination_port": port,
        }
        for index, port in enumerate(range(20, 30))
    ]
    event_file = tmp_path / "v2-network-events.json"
    event_file.write_text(json.dumps(events), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable, "-m", "soc_sentinel.cli",
            "--file", str(event_file), "--format", "json", "--v2",
        ],
        capture_output=True, text=True, check=True,
    )

    output = json.loads(result.stdout)
    alerts = [alert for alert in output["alerts"] if alert["rule_id"] == "NET-001"]

    assert len(alerts) == 1
    alert = alerts[0]
    expected_ids = {f"v2-network-{port}" for port in range(20, 30)}
    assert set(alert["event_ids"]) == expected_ids
    assert "192.0.2.10" in alert["source_entities"]
    assert "198.51.100.20" in alert["target_entities"]
    assert alert["triggering_conditions"]
    assert len(alert["evidence"]) == 10
    assert {item["event_id"] for item in alert["evidence"]} == expected_ids
    assert all(item["raw_event"]["event_id"] in expected_ids for item in alert["evidence"])
    assert all(
        item["parser_version"] == "1.0.0"
        and item["schema_version"] == "1.0.0"
        for item in alert["evidence"]
    )


def test_v2_cli_suspicious_dns_alert_preserves_event_evidence(tmp_path):
    event = {
        "event_id": "v2-dns-suspicious-1",
        "timestamp": "2026-10-05T03:20:00+00:00",
        "source": "dns",
        "event": "dns_query",
        "category": "dns",
        "dns_query": "a" * 55 + ".example",
        "src_ip": "192.0.2.53",
    }
    event_file = tmp_path / "v2-dns-events.json"
    event_file.write_text(json.dumps([event]), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable, "-m", "soc_sentinel.cli",
            "--file", str(event_file), "--format", "json", "--v2",
        ],
        capture_output=True, text=True, check=True,
    )

    output = json.loads(result.stdout)
    alerts = [alert for alert in output["alerts"] if alert["rule_id"] == "DNS-001"]

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["event_ids"] == ["v2-dns-suspicious-1"]
    assert alert["source_entities"] == ["192.0.2.53"]
    assert alert["target_entities"] == [event["dns_query"]]
    assert alert["triggering_conditions"]
    assert len(alert["evidence"]) == 1
    evidence = alert["evidence"][0]
    assert evidence["event_id"] == "v2-dns-suspicious-1"
    assert evidence["raw_event"]["dns_query"] == event["dns_query"]
    assert evidence["parser_version"] == "1.0.0"
    assert evidence["schema_version"] == "1.0.0"

def test_v2_cli_correlation_preserves_source_provenance(tmp_path):
    events = [
        {
            "event_id": "provenance-failure-1",
            "original_source_id": "windows-security-4625-001",
            "original_event_reference": "Security.evtx:record-001",
            "timestamp": "2026-10-05T03:20:00+00:00",
            "source": "authentication",
            "event": "login_failure",
            "src_ip": "192.0.2.25",
            "username": "admin",
        },
        {
            "event_id": "provenance-failure-2",
            "original_source_id": "windows-security-4625-002",
            "original_event_reference": "Security.evtx:record-002",
            "timestamp": "2026-10-05T03:21:00+00:00",
            "source": "authentication",
            "event": "login_failure",
            "src_ip": "192.0.2.25",
            "username": "admin",
        },
        {
            "event_id": "provenance-success-1",
            "original_source_id": "windows-security-4624-001",
            "original_event_reference": "Security.evtx:record-003",
            "timestamp": "2026-10-05T03:22:00+00:00",
            "source": "authentication",
            "event": "login_success",
            "src_ip": "192.0.2.25",
            "username": "admin",
        },
    ]
    event_file = tmp_path / "v2-provenance-events.json"
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
            "--v2",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = json.loads(result.stdout)
    correlations = [
        item for item in output["correlations"]
        if item["correlation_type"] == "authentication_failure_then_success"
    ]

    assert len(correlations) == 1
    provenance = correlations[0]["source_provenance"]
    assert provenance == [
        {
            "event_id": "provenance-failure-1",
            "original_source_id": "windows-security-4625-001",
            "original_event_reference": "Security.evtx:record-001",
        },
        {
            "event_id": "provenance-failure-2",
            "original_source_id": "windows-security-4625-002",
            "original_event_reference": "Security.evtx:record-002",
        },
        {
            "event_id": "provenance-success-1",
            "original_source_id": "windows-security-4624-001",
            "original_event_reference": "Security.evtx:record-003",
        },
    ]
