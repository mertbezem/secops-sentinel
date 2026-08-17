import datetime

from pydantic import BaseModel


class IngestResponse(BaseModel):
    job_id: str
    status: str
    total_processed: int
    new_events: int
    duplicates_skipped: int
    templates_created: int
    message: str


class IngestJobResponse(BaseModel):
    job_id: str
    status: str
    total_processed: int
    new_events: int
    duplicates_skipped: int
    templates_created: int
    created_at: datetime.datetime
    completed_at: datetime.datetime | None = None
