from typing import Any

from app.detection.rules.base import BaseRule
from app.models.models import Baseline, Event, Machine


class ErrorBurstRule(BaseRule):
    code = "R001"
    name = "ERROR_BURST"
    enabled = True
    params = {
        "threshold_count": 5,
        "time_window_minutes": 10
    }
    weight = 1.0
    mitre_techniques = ["T1078", "T1489"]
    is_demo = False

    def evaluate(
        self,
        machine: Machine,
        events: list[Event],
        baselines: dict[tuple[int, str], Baseline],
        recent_findings_count: int = 0
    ) -> list[dict[str, Any]]:
        findings = []
        threshold = int(self.params.get("threshold_count", 5))
        window_minutes = int(self.params.get("time_window_minutes", 10))

        # Filter error/failure events
        error_events = [
            e for e in events
            if "error" in e.entry_type.lower() or "failure" in e.entry_type.lower()
        ]
        error_events.sort(key=lambda e: e.ts_utc)

        if len(error_events) < threshold:
            return []

        # Sliding window check
        n = len(error_events)
        for i in range(n):
            window_events = [error_events[i]]
            for j in range(i + 1, n):
                diff = (error_events[j].ts_utc - error_events[i].ts_utc).total_seconds() / 60.0
                if diff <= window_minutes:
                    window_events.append(error_events[j])
                else:
                    break

            if len(window_events) >= threshold:
                evidence_ids = [e.id for e in window_events]
                sample_event = window_events[-1]
                findings.append({
                    "rule_code": self.code,
                    "machine_id": machine.id,
                    "ts_utc": sample_event.ts_utc,
                    "base_score": 40,
                    "confidence": min(0.95, 0.60 + 0.05 * len(window_events)),
                    "evidence_event_ids": evidence_ids[:10],
                    "sample_event": sample_event
                })
                # Skip past window to avoid duplicate finding triggers
                break

        return findings
