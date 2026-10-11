from datetime import timezone

import pytest

from soc_sentinel.incidents.models import Incident, IncidentStatus


def test_incident_defaults_to_new_with_unique_id():
    first = Incident(title="Suspicious login activity")
    second = Incident(title="Suspicious login activity")

    assert first.status is IncidentStatus.NEW
    assert first.incident_id
    assert first.incident_id != second.incident_id
    assert first.created_at.tzinfo is not None
    assert first.updated_at.tzinfo is not None


@pytest.mark.parametrize(
    ("initial", "next_status"),
    [
        (IncidentStatus.NEW, IncidentStatus.INVESTIGATING),
        (IncidentStatus.NEW, IncidentStatus.FALSE_POSITIVE),
        (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.FALSE_POSITIVE),
    ],
)
def test_allowed_incident_transitions(initial, next_status):
    incident = Incident(title="Test incident", status=initial)
    previous_updated_at = incident.updated_at

    incident.transition_to(next_status)

    assert incident.status is next_status
    assert incident.updated_at >= previous_updated_at


@pytest.mark.parametrize(
    ("initial", "next_status"),
    [
        (IncidentStatus.NEW, IncidentStatus.RESOLVED),
        (IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING),
        (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE),
        (IncidentStatus.FALSE_POSITIVE, IncidentStatus.INVESTIGATING),
        (IncidentStatus.FALSE_POSITIVE, IncidentStatus.RESOLVED),
    ],
)
def test_invalid_incident_transitions_are_rejected(initial, next_status):
    incident = Incident(title="Test incident", status=initial)

    with pytest.raises(ValueError, match="Invalid incident transition"):
        incident.transition_to(next_status)


@pytest.mark.parametrize("title", ["", "   "])
def test_incident_rejects_blank_title(title):
    with pytest.raises(ValueError, match="title"):
        Incident(title=title)


def test_incident_rejects_unknown_status():
    with pytest.raises(ValueError, match="Unsupported incident status"):
        Incident(title="Test incident", status="unknown")


def test_transition_rejects_unknown_status():
    incident = Incident(title="Test incident")

    with pytest.raises(ValueError, match="Unsupported incident status"):
        incident.transition_to("unknown")
