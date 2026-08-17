import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventResponse(BaseModel):
    id: int
    machine_id: int
    machine_name: str | None = None
    source: str
    category: str | None = None
    entry_type: str
    message: str
    template_id: int | None = None
    ts_utc: datetime.datetime
    hour_of_day: int
    day_of_week: int
    is_business_hours: bool
    country: str | None = None
    region_name: str | None = None
    city: str | None = None
    extracted_entities: dict[str, Any] = Field(default_factory=dict)
    dedup_hash: str
    ingested_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)
