from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_optional_current_user
from app.db.session import get_db
from app.models.models import Incident, IncidentNote, User
from app.schemas.common import PageEnvelope
from app.schemas.incident import (
    IncidentDetailResponse,
    IncidentNoteCreate,
    IncidentNoteResponse,
    IncidentOut,
)
from app.services.ai_analysis_service import AiAnalysisService
from app.services.incident_service import IncidentService, get_incident_by_id
from app.services.pdf_report_service import PdfReportService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class IncidentStatusUpdate(BaseModel):
    status: str
    notes: str | None = None


@router.get("", response_model=PageEnvelope[IncidentOut])
def list_incidents(
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
) -> PageEnvelope[IncidentOut]:
    items, total = IncidentService.get_paginated_incidents(
        db=db, status=status_filter, severity=severity, page=page, page_size=page_size
    )
    validated_items = [IncidentOut.model_validate(i) for i in items]
    return PageEnvelope(items=validated_items, total=total, page=page, page_size=page_size)


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db)
) -> IncidentDetailResponse:
    return get_incident_by_id(db, incident_id)


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db)
) -> IncidentOut:
    valid_statuses = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "IN_PROGRESS", "CLOSED"}
    if payload.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_STATUS", "message": f"Status must be one of {valid_statuses}", "field": "status"}
        )

    incident = IncidentService.update_status(db, incident_id, payload.status, payload.notes)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Incident #{incident_id} not found", "field": "id"}
        )
    return IncidentOut.model_validate(incident)


@router.get("/{incident_id}/pdf")
def download_incident_pdf(
    incident_id: int,
    db: Session = Depends(get_db)
) -> Response:
    """
    Olay için Türkçe karakter destekli adli bilişim inceleme raporunu (PDF) üretir ve indirir.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Incident #{incident_id} not found", "field": "id"}
        )

    pdf_bytes = PdfReportService.generate_incident_pdf(incident=incident, db=db)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=SecOps_Incident_{incident_id}_Report.pdf"
        }
    )


@router.get("/{incident_id}/ai-analysis")
def get_ai_incident_analysis(
    incident_id: int,
    db: Session = Depends(get_db)
):
    """
    Yapay zeka (AI) ile tehdit kök neden analizi, saldırgan motivasyonu ve önerilen müdahale komutlarını üretir.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Incident #{incident_id} not found", "field": "id"}
        )
    return AiAnalysisService.analyze_incident(incident=incident, db=db)


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse, status_code=status.HTTP_201_CREATED)
def add_incident_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user)
) -> IncidentNote:
    """
    Olay denetim geçmişine kalıcı bir analist inceleme notu veya müdahale aksiyonu ekler.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Incident #{incident_id} not found", "field": "id"}
        )

    username = current_user.username if current_user else "analyst"
    note = IncidentNote(
        incident_id=incident.id,
        author_username=username,
        action_type=payload.action_type,
        note_text=payload.note_text
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.get("/{incident_id}/notes", response_model=list[IncidentNoteResponse])
def get_incident_notes(
    incident_id: int,
    db: Session = Depends(get_db)
) -> list[IncidentNote]:
    """
    Olay için kronolojik analist inceleme notlarını ve aksiyon geçmişini getirir.
    """
    notes = db.scalars(
        select(IncidentNote)
        .where(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at.desc())
    ).all()
    return list(notes)
