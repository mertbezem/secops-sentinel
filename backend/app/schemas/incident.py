import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.event import EventResponse
from app.schemas.finding import FindingResponse


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    status: str
    severity: str
    risk_score: int
    machine_id: int
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    finding_count: int
    mitre_techniques: list[str]
    assignee: str | None = None
    notes: str | None = None


# Alias IncidentResponse to IncidentOut for router compatibility
class IncidentResponse(IncidentOut):
    machine_name: str | None = None
    created_at: datetime.datetime | None = None
    updated_at: datetime.datetime | None = None


class IncidentDetailResponse(IncidentResponse):
    findings: list[FindingResponse] = Field(default_factory=list)
    evidence_events: list[EventResponse] = Field(default_factory=list)


class IncidentUpdateParams(BaseModel):
    status: str | None = Field(None, description="Olay durumu: OPEN, INVESTIGATING, RESOLVED, CLOSED")
    assignee: str | None = Field(None, description="Atanan analist kullanıcı adı")
    notes: str | None = Field(None, description="Analist inceleme notları")


class IncidentNoteCreate(BaseModel):
    note_text: str = Field(..., description="Analist inceleme notu veya aksiyon açıklaması")
    action_type: str = Field("NOTE", description="Aksiyon türü: NOTE, STATUS_CHANGE, MITIGATION")


class IncidentNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    author_username: str
    action_type: str
    note_text: str
    created_at: datetime.datetime

