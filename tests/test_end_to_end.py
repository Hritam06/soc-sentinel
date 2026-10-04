from soc_sentinel.main import process_event


def test_end_to_end_high_severity_event():
    raw_event = {
        "timestamp": "2026-10-05T03:20:00+00:00",
        "source": "authentication",
        "event": "login_failure",
        "src_ip": "192.168.1.50",
        "username": "admin",
        "severity": "high",
        "message": "Failed authentication attempt",
    }

    report = process_event(raw_event)

    assert "SOC INCIDENT REPORT" in report
    assert "Event Type: login_failure" in report
    assert "Source IP: 192.168.1.50" in report
    assert "Username: admin" in report
    assert "Risk: high" in report
    assert "high_severity_login_failure" in report
