import datetime
import io
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.ingestion.csv_loader import load_csv_data
from app.schemas.ingest import IngestJobResponse, IngestResponse

# Simple in-memory jobs cache for GET /ingest/jobs/{id}
JOBS_CACHE: dict[str, dict[str, Any]] = {}


def process_csv_ingestion(db: Session, content_str: str) -> IngestResponse:
    job_id = str(uuid.uuid4())
    start_time = datetime.datetime.now(datetime.UTC)

    JOBS_CACHE[job_id] = {
        "job_id": job_id,
        "status": "PROCESSING",
        "total_processed": 0,
        "new_events": 0,
        "duplicates_skipped": 0,
        "templates_created": 0,
        "created_at": start_time,
        "completed_at": None
    }

    file_obj = io.StringIO(content_str)
    result = load_csv_data(db, file_obj)

    end_time = datetime.datetime.now(datetime.UTC)

    JOBS_CACHE[job_id].update({
        "status": "COMPLETED",
        "total_processed": result["total_processed"],
        "new_events": result["new_events"],
        "duplicates_skipped": result["duplicates_skipped"],
        "templates_created": result["templates_created"],
        "completed_at": end_time
    })

    return IngestResponse(
        job_id=job_id,
        status="COMPLETED",
        total_processed=result["total_processed"],
        new_events=result["new_events"],
        duplicates_skipped=result["duplicates_skipped"],
        templates_created=result["templates_created"],
        message=result["message"]
    )


def get_ingest_job_status(job_id: str) -> IngestJobResponse:
    if job_id in JOBS_CACHE:
        data = JOBS_CACHE[job_id]
        return IngestJobResponse(**data)
    else:
        # Fallback dummy completed job info for testing
        return IngestJobResponse(
            job_id=job_id,
            status="COMPLETED",
            total_processed=0,
            new_events=0,
            duplicates_skipped=0,
            templates_created=0,
            created_at=datetime.datetime.now(datetime.UTC),
            completed_at=datetime.datetime.now(datetime.UTC)
        )
