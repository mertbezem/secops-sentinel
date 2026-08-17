import datetime

from pydantic import BaseModel, ConfigDict, Field


class TopSourceItem(BaseModel):
    source: str
    count: int


class PeriodDetail(BaseModel):
    from_time: datetime.datetime | None = Field(None, alias="from")
    to_time: datetime.datetime | None = Field(None, alias="to")

    model_config = ConfigDict(populate_by_name=True)


class StatsOverviewResponse(BaseModel):
    total_events: int
    total_machines: int
    open_incidents: int
    severity_breakdown: dict[str, int]
    top_sources: list[TopSourceItem]
    period: PeriodDetail


class StatsTimeseriesBucket(BaseModel):
    timestamp: datetime.datetime
    event_count: int
    incident_count: int


class StatsTimeseriesResponse(BaseModel):
    buckets: list[StatsTimeseriesBucket]
