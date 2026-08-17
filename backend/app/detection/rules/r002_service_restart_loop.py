from typing import Any

from app.detection.rules.base import BaseRule
from app.models.models import Baseline, Event, Machine

RESTART_KEYWORDS = [
    "re-start", "restart", "stop", "stopped", "service control manager",
    "software protection platform service", "scheduled software protection", "terminated"
]


class ServiceRestartLoopRule(BaseRule):
    code = "R002"
    name = "SERVICE_RESTART_LOOP"
    enabled = True
    params = {
        "threshold_count": 3,
        "time_window_minutes": 15
    }
    weight = 1.0
    mitre_techniques = ["T1489"]
    is_demo = False

    def evaluate(
        self,
        machine: Machine,
        events: list[Event],
        baselines: dict[tuple[int, str], Baseline],
        recent_findings_count: int = 0
    ) -> list[dict[str, Any]]:
        findings = []
        threshold = int(self.params.get("threshold_count", 3))
        window_minutes = int(self.params.get("time_window_minutes", 15))

        # Filter restart/service control events
        restart_events = [
            e for e in events
            if any(kw in e.message.lower() or kw in e.source.lower() for kw in RESTART_KEYWORDS)
        ]
        restart_events.sort(key=lambda e: e.ts_utc)

        if len(restart_events) < threshold:
            return []

        n = len(restart_events)
        for i in range(n):
            window_events = [restart_events[i]]
            for j in range(i + 1, n):
                diff = (restart_events[j].ts_utc - restart_events[i].ts_utc).total_seconds() / 60.0
                if diff <= window_minutes:
                    window_events.append(restart_events[j])
                else:
                    break

            if len(window_events) >= threshold:
                evidence_ids = [e.id for e in window_events]
                sample_event = window_events[-1]
                findings.append({
                    "rule_code": self.code,
                    "machine_id": machine.id,
                    "ts_utc": sample_event.ts_utc,
                    "base_score": 45,
                    "confidence": 0.85,
                    "evidence_event_ids": evidence_ids[:10],
                    "sample_event": sample_event
                })
                break

        return findings
