from typing import Any

from app.detection.rules.base import BaseRule
from app.models.models import Baseline, Event, Machine


class NewMessageTemplateRule(BaseRule):
    code = "R003"
    name = "NEW_MESSAGE_TEMPLATE"
    enabled = True
    params = {
        "min_confidence": 0.70
    }
    weight = 1.0
    mitre_techniques = ["T1068"]
    is_demo = False

    def evaluate(
        self,
        machine: Machine,
        events: list[Event],
        baselines: dict[tuple[int, str], Baseline],
        recent_findings_count: int = 0
    ) -> list[dict[str, Any]]:
        findings = []
        if not events:
            return []

        for event in events:
            if event.template and event.template.occurrence_count <= 5:
                findings.append({
                    "rule_code": self.code,
                    "machine_id": machine.id,
                    "ts_utc": event.ts_utc,
                    "base_score": 35,
                    "confidence": float(self.params.get("min_confidence", 0.70)),
                    "evidence_event_ids": [event.id],
                    "sample_event": event
                })
                if len(findings) >= 5:
                    break

        return findings
