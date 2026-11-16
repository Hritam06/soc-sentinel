"""Configuration and investigation regression tests."""

import json
from types import SimpleNamespace

import pytest

from soc_sentinel.config.settings import load_config
from soc_sentinel.investigation.risk import assess_risk


def test_config_defaults_and_environment_overrides(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"detection": {"brute_force_threshold": 6}}))
    config = load_config(path, environ={
        "SOC_SENTINEL__DETECTION__PASSWORD_SPRAY_THRESHOLD": "8",
        "SOC_SENTINEL__INVESTIGATION__CORRELATION_WINDOW_MINUTES": "15",
    })
    assert config.detection.brute_force_threshold == 6
    assert config.detection.password_spray_threshold == 8
    assert config.investigation.correlation_window_minutes == 15
    assert config.suppression.enabled is True


def test_config_environment_boolean_and_numeric_values(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("suppression:\n  enabled: true\n")
    config = load_config(path, environ={
        "SOC_SENTINEL__SUPPRESSION__ENABLED": "false",
        "SOC_SENTINEL__SUPPRESSION__WINDOW_MINUTES": "30",
    })
    assert config.suppression.enabled is False
    assert config.suppression.window_minutes == 30


def test_config_rejects_unknown_environment_keys(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{}")
    with pytest.raises(ValueError):
        load_config(path, environ={"SOC_SENTINEL__UNKNOWN__VALUE": "1"})


def test_config_validates_and_normalizes_allowlists(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "allowlists": {
            "ips": ["192.0.2.1", "192.0.2.1"],
            "accounts": [" analyst ", "analyst"],
        }
    }))
    config = load_config(path, environ={})
    assert config.allowlists.ips == ["192.0.2.1"]
    assert config.allowlists.accounts == ["analyst"]


def test_config_rejects_invalid_allowlisted_ip(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"allowlists": {"ips": ["not-an-ip"]}}))
    with pytest.raises(ValueError):
        load_config(path, environ={})


def test_risk_assessment_preserves_default_scoring():
    alert = SimpleNamespace(
        rule_id="AUTH-001",
        rule_name="Brute force",
        severity="high",
        confidence=0.5,
    )
    result = assess_risk([alert], event_count=4)
    assert result["risk_score"] == 30
    assert result["score_breakdown"]["asset_criticality_bonus"] == 0
    assert result["score_breakdown"]["progression_score"] == 0
    assert result["contributors"][0]["mitre_attack"] == ["T1110"]


def test_risk_assessment_explains_contextual_contributions():
    alert = SimpleNamespace(
        rule_id="AUTH-001",
        rule_name="Brute force",
        severity="high",
        confidence=1.0,
    )
    result = assess_risk(
        [alert],
        asset_criticality="critical",
        progression_score=15,
    )
    assert result["risk_score"] == 95
    assert result["score_breakdown"]["alert_contributions"] == 60
    assert result["score_breakdown"]["asset_criticality_bonus"] == 20
    assert result["score_breakdown"]["progression_score"] == 15


def test_risk_assessment_rejects_invalid_context():
    with pytest.raises(ValueError):
        assess_risk([], asset_criticality="unknown")
    with pytest.raises(ValueError):
        assess_risk([], progression_score=21)



def test_risk_assessment_uses_configured_investigation_bonuses():
    from types import SimpleNamespace
    from soc_sentinel.investigation.risk import assess_risk

    alert = SimpleNamespace(
        severity="low",
        confidence=1.0,
        rule_id="AUTH-001",
        rule_name="Test rule",
    )
    result = assess_risk(
        [alert],
        asset_criticality="high",
        progression_score=7,
        high_asset_bonus=14,
        critical_asset_bonus=19,
        progression_bonus_max=8,
    )
    assert result["risk_score"] == 31
    assert result["score_breakdown"]["asset_criticality_bonus"] == 14
    assert result["score_breakdown"]["progression_score"] == 7


def test_risk_assessment_rejects_progression_above_configured_maximum():
    import pytest
    from soc_sentinel.investigation.risk import assess_risk

    with pytest.raises(ValueError, match="progression_bonus_max"):
        assess_risk([], progression_score=9, progression_bonus_max=8)


def test_risk_assessment_rejects_invalid_configured_bonus():
    import pytest
    from soc_sentinel.investigation.risk import assess_risk

    with pytest.raises(ValueError, match="critical_asset_bonus"):
        assess_risk([], critical_asset_bonus=21)
