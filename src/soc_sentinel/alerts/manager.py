"""In-memory alert deduplication and suppression."""

import json

from datetime import timedelta

from soc_sentinel.alerts.models import SecurityAlert


class AlertManager:
    """Manage alert deduplication within a configurable time window."""

    def __init__(self, window_minutes: int = 15, enabled: bool = True):
        if window_minutes < 1:
            raise ValueError("window_minutes must be at least 1")
        self.window = timedelta(minutes=window_minutes)
        self.enabled = enabled
        self.alerts: list[SecurityAlert] = []

    @staticmethod
    def _key(alert: SecurityAlert) -> tuple:
        return (
            alert.rule_id,
            alert.source_entities,
            alert.target_entities,
        )

    @staticmethod
    def _evidence_key(item: dict | str) -> str:
        """Create a stable key for string or structured evidence."""
        return json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)

    def _within_window(
        self,
        existing: SecurityAlert,
        incoming: SecurityAlert,
    ) -> bool:
        """Check the gap between alert intervals, independent of arrival order."""
        gap = max(
            timedelta(0),
            max(existing.first_seen, incoming.first_seen)
            - min(existing.last_seen, incoming.last_seen),
        )
        return gap <= self.window

    def add(self, alert: SecurityAlert) -> SecurityAlert:
        """Add an alert or merge it into a recent matching alert."""
        if not self.enabled:
            self.alerts.append(alert)
            return alert

        for existing in reversed(self.alerts):
            if self._key(existing) != self._key(alert):
                continue
            if not self._within_window(existing, alert):
                continue

            existing.first_seen = min(existing.first_seen, alert.first_seen)
            existing.last_seen = max(existing.last_seen, alert.last_seen)
            existing.event_ids = tuple(dict.fromkeys(
                existing.event_ids + alert.event_ids
            ))
            existing.triggering_conditions = tuple(dict.fromkeys(
                existing.triggering_conditions + alert.triggering_conditions
            ))
            merged_evidence = {}
            for item in existing.evidence + alert.evidence:
                merged_evidence.setdefault(self._evidence_key(item), item)
            existing.evidence = tuple(merged_evidence.values())
            return existing

        self.alerts.append(alert)
        return alert

    def list_alerts(self) -> list[SecurityAlert]:
        return list(self.alerts)

    def get(self, alert_id: str) -> SecurityAlert | None:
        return next(
            (alert for alert in self.alerts if alert.alert_id == alert_id),
            None,
        )
