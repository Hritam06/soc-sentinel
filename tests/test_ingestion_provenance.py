import pytest

from soc_sentinel.ingestion.loader import load_events


def test_batch_ingestion_rejects_duplicate_event_ids():
    event = {
        "event_id": "duplicate-id",
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "authentication",
        "event_type": "login_failure",
    }

    with pytest.raises(ValueError, match="Duplicate event_id"):
        load_events([event, event])


def test_batch_ingestion_assigns_distinct_ids_when_missing():
    event = {
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "authentication",
        "event_type": "login_failure",
    }

    loaded = load_events([event, event])

    assert loaded[0].event_id
    assert loaded[1].event_id
    assert loaded[0].event_id != loaded[1].event_id
