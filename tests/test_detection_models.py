import pytest

from soc_sentinel.detection.models import DetectionAlert


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("low", 25),
        ("medium", 50),
        ("high", 75),
        ("critical", 100),
        ("HIGH", 75),
    ],
)
def test_risk_score_matches_severity(severity, expected):
    alert = DetectionAlert(
        rule="test_rule",
        severity=severity,
        message="Test alert",
    )
    assert alert.risk_score == expected


def test_risk_score_rejects_unsupported_severity():
    alert = DetectionAlert(
        rule="test_rule",
        severity="unknown",
        message="Test alert",
    )
    with pytest.raises(ValueError, match="Unsupported alert severity"):
        _ = alert.risk_score
