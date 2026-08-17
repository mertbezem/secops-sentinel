from abc import ABC, abstractmethod
from typing import Any

from app.models.models import Baseline, Event, Machine


class BaseRule(ABC):
    code: str
    name: str
    enabled: bool = True
    params: dict[str, Any]
    weight: float = 1.0
    mitre_techniques: list[str]
    is_demo: bool = False

    def __init__(self, params: dict[str, Any] | None = None):
        if params is not None:
            self.params = params

    @abstractmethod
    def evaluate(
        self,
        machine: Machine,
        events: list[Event],
        baselines: dict[tuple[int, str], Baseline],
        recent_findings_count: int = 0
    ) -> list[dict[str, Any]]:
        pass
