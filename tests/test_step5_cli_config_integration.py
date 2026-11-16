
def test_v2_cli_passes_investigation_settings_to_runtime(tmp_path, monkeypatch):
    import sys
    import soc_sentinel.cli as cli

    config_path = tmp_path / "step5-config.yaml"
    config_path.write_text(
        """
investigation:
  correlation_window_minutes: 23
  high_asset_bonus: 13
  critical_asset_bonus: 18
  progression_bonus_max: 9
""",
        encoding="utf-8",
    )

    captured = {}

    monkeypatch.setattr(cli, "load_events", lambda raw_events: [])
    monkeypatch.setattr(
        cli, "detect_authentication_alerts",
        lambda events, **kwargs: [],
    )
    monkeypatch.setattr(
        cli, "detect_network_alerts",
        lambda events, **kwargs: [],
    )
    monkeypatch.setattr(
        cli, "detect_suspicious_dns_alerts",
        lambda events, **kwargs: [],
    )

    def capture_correlation(events, window_minutes=10):
        captured["correlation_window"] = window_minutes
        return []

    def capture_risk(alerts, event_count=0, **kwargs):
        captured["risk_settings"] = kwargs
        return {}

    monkeypatch.setattr(cli, "correlate_security_events", capture_correlation)
    monkeypatch.setattr(cli, "assess_risk", capture_risk)
    monkeypatch.setattr(cli, "build_json_report", lambda *args: {})

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "soc-sentinel",
            "--event", "{}",
            "--v2",
            "--config", str(config_path),
        ],
    )

    cli.main()

    assert captured["correlation_window"] == 23
    assert captured["risk_settings"]["high_asset_bonus"] == 13
    assert captured["risk_settings"]["critical_asset_bonus"] == 18
    assert captured["risk_settings"]["progression_bonus_max"] == 9
