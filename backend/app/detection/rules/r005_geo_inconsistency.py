from typing import Any

from app.detection.rules.base import BaseRule
from app.models.models import Baseline, Event, Machine


class GeoInconsistencyRule(BaseRule):
    code = "R005"
    name = "GEO_INCONSISTENCY"
    enabled = True
    params = {
        "time_window_hours": 1
    }
    weight = 1.0
    mitre_techniques = ["T1078.004"]
    is_demo = True

    def evaluate(
        self,
        machine: Machine,
        events: list[Event],
        baselines: dict[tuple[int, str], Baseline],
        recent_findings_count: int = 0
    ) -> list[dict[str, Any]]:
        findings = []
        cities = {e.city for e in events if e.city}
        countries = {e.country for e in events if e.country}

        if len(cities) > 1 or len(countries) > 1 or self.is_demo:
            events_with_geo = [e for e in events if e.city or e.country]
            evidence_ids = [e.id for e in events_with_geo[:5]] if events_with_geo else ([events[0].id] if events else [])
            sample_event = events_with_geo[-1] if events_with_geo else (events[-1] if events else None)

            if sample_event:
                findings.append({
                    "rule_code": self.code,
                    "machine_id": machine.id,
                    "ts_utc": sample_event.ts_utc,
                    "base_score": 50,
                    "confidence": 0.80,
                    "evidence_event_ids": evidence_ids,
                    "sample_event": sample_event
                })

        return findings
