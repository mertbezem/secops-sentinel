import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class MachineResponse(BaseModel):
    id: int
    name: str
    criticality: str
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    event_count: int

    model_config = ConfigDict(from_attributes=True)


class TimelineItem(BaseModel):
    timestamp: datetime.datetime
    item_type: str  # "EVENT" or "FINDING" or "INCIDENT"
    source_or_rule: str
    severity_or_entrytype: str
    summary: str
    details: Any | None = None


class MachineTimelineResponse(BaseModel):
    machine_id: int
    machine_name: str
    timeline: list[TimelineItem]
