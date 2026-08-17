from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.detection.engine import run_detection_pipeline

router = APIRouter(prefix="/detection", tags=["Detection"])


@router.post("/run", response_model=dict[str, Any])
def trigger_detection(
    db: Session = Depends(get_db)
) -> dict[str, Any]:
    """
    Triggers the autonomous detection pipeline across all events.
    """
    return run_detection_pipeline(db)
