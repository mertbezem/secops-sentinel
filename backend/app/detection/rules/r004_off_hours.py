from typing import Any

from app.detection.rules.base import BaseRule
from app.models.models import Baseline, Event, Machine


class OffHoursAnomalyRule(BaseRule):
    code = "R004"
    name = "OFF_HOURS_ANOMALY"
    enabled = True
    params = {
        "start_hour": 8,
        "end_hour": 18,
        "weekend_off": True
    }
    weight = 1.0
    mitre_techniques = ["T1078"]
    is_demo = False

    def evaluate(
        self,
        machine: Machine,
        events: list[Event],
        baselines: dict[tuple[int, str], Baseline],
        recent_findings_count: int = 0
    ) -> list[dict[str, Any]]:
        findings = []
        off_hours_events = [
            e for e in events
            if not e.is_business_hours and ("error" in e.entry_type.lower() or "warning" in e.entry_type.lower())
        ]

        if not off_hours_events:
            return []

        evidence_ids = [e.id for e in off_hours_events[:10]]
        sample_event = off_hours_events[-1]

        findings.append({
            "rule_code": self.code,
            "machine_id": machine.id,
            "ts_utc": sample_event.ts_utc,
            "base_score": 30,
            "confidence": 0.75,
            "evidence_event_ids": evidence_ids,
            "sample_event": sample_event
        })

        return findings
