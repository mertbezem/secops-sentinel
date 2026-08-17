from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from app.core.exceptions import ValidationException
from app.db.session import get_db
from app.schemas.ingest import IngestJobResponse, IngestResponse
from app.services.ingest_service import get_ingest_job_status, process_csv_ingestion

router = APIRouter(prefix="/ingest", tags=["Ingest"])


@router.post("/csv", response_model=IngestResponse)
async def upload_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
) -> IngestResponse:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise ValidationException("Uploaded file must be a CSV file", field="file")

    contents = await file.read()
    try:
        content_str = contents.decode("utf-8")
    except UnicodeDecodeError:
        content_str = contents.decode("latin-1")

    return process_csv_ingestion(db, content_str)


@router.get("/jobs/{job_id}", response_model=IngestJobResponse)
def get_job_status(job_id: str) -> IngestJobResponse:
    return get_ingest_job_status(job_id)
