import datetime

from pydantic import BaseModel, ConfigDict


class ReasonDetail(BaseModel):
    factor: str
    points: int


class FindingResponse(BaseModel):
    id: int
    rule_code: str
    rule_name: str | None = None
    machine_id: int
    machine_name: str | None = None
    ts_utc: datetime.datetime
    severity: str
    confidence: float
    risk_score: int
    reasons: list[ReasonDetail]
    evidence_event_ids: list[int]
    incident_id: int | None = None

    model_config = ConfigDict(from_attributes=True)
