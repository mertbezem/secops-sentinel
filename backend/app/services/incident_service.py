import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundException
from app.models.models import Event, Finding, Incident
from app.schemas.event import EventResponse
from app.schemas.finding import FindingResponse, ReasonDetail
from app.schemas.incident import IncidentDetailResponse, IncidentResponse, IncidentUpdateParams

VALID_STATUSES = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "IN_PROGRESS", "CLOSED"}


class IncidentService:
    @staticmethod
    def get_paginated_incidents(
        db: Session,
        status: str | None = None,
        severity: str | None = None,
        page: int = 1,
        page_size: int = 20
    ) -> tuple[list[Incident], int]:
        stmt = select(Incident)
        if status:
            stmt = stmt.where(func.upper(Incident.status) == status.upper())
        if severity:
            stmt = stmt.where(func.upper(Incident.severity) == severity.upper())

        total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        offset = (page - 1) * page_size
        items = list(db.scalars(stmt.order_by(Incident.first_seen.desc()).offset(offset).limit(page_size)).all())
        return items, total

    @staticmethod
    def update_status(
        db: Session,
        incident_id: int,
        status: str,
        notes: str | None = None
    ) -> Incident | None:
        inc = db.get(Incident, incident_id)
        if not inc:
            return None
        inc.status = status
        if notes is not None:
            inc.notes = notes
        inc.updated_at = datetime.datetime.now(datetime.UTC)
        db.commit()
        db.refresh(inc)
        return inc


def get_incidents_paginated(
    db: Session,
    severity: str | None = None,
    status: str | None = None,
    machine: str | None = None,
    sort: str = "desc",
    page: int = 1,
    page_size: int = 50
) -> tuple[list[IncidentResponse], int]:
    items, total = IncidentService.get_paginated_incidents(
        db=db, status=status, severity=severity, page=page, page_size=page_size
    )
    responses = [
        IncidentResponse(
            id=inc.id,
            title=inc.title,
            status=inc.status,
            severity=inc.severity,
            risk_score=inc.risk_score,
            machine_id=inc.machine_id,
            machine_name=inc.machine.name if inc.machine else None,
            first_seen=inc.first_seen,
            last_seen=inc.last_seen,
            finding_count=inc.finding_count,
            mitre_techniques=inc.mitre_techniques or [],
            assignee=inc.assignee,
            notes=inc.notes,
            created_at=inc.created_at,
            updated_at=inc.updated_at
        )
        for inc in items
    ]
    return responses, total


def get_incident_by_id(db: Session, incident_id: int) -> IncidentDetailResponse:
    inc = db.get(Incident, incident_id)
    if not inc:
        raise NotFoundException(f"Incident with id {incident_id} not found", field="incident_id")

    findings = db.scalars(
        select(Finding)
        .where(Finding.incident_id == incident_id)
        .order_by(Finding.ts_utc.desc())
    ).all()

    finding_responses: list[FindingResponse] = []
    evidence_event_ids: set[int] = set()

    for f in findings:
        reasons_list = [
            ReasonDetail(factor=r.get("factor", "unknown"), points=int(r.get("points", 0)))
            for r in (f.reasons or [])
        ]
        evidence_event_ids.update(f.evidence_event_ids or [])
        finding_responses.append(
            FindingResponse(
                id=f.id,
                rule_code=f.rule_code,
                rule_name=f.rule.name if f.rule else f.rule_code,
                machine_id=f.machine_id,
                machine_name=f.machine.name if f.machine else None,
                ts_utc=f.ts_utc,
                severity=f.severity,
                confidence=f.confidence,
                risk_score=f.risk_score,
                reasons=reasons_list,
                evidence_event_ids=f.evidence_event_ids or [],
                incident_id=f.incident_id
            )
        )

    # Fetch evidence events
    event_responses: list[EventResponse] = []
    if evidence_event_ids:
        events = db.scalars(
            select(Event).where(Event.id.in_(list(evidence_event_ids)))
        ).all()
        for e in events:
            event_responses.append(
                EventResponse(
                    id=e.id,
                    machine_id=e.machine_id,
                    machine_name=e.machine.name if e.machine else None,
                    source=e.source,
                    category=e.category,
                    entry_type=e.entry_type,
                    message=e.message,
                    template_id=e.template_id,
                    ts_utc=e.ts_utc,
                    hour_of_day=e.hour_of_day,
                    day_of_week=e.day_of_week,
                    is_business_hours=e.is_business_hours,
                    country=e.country,
                    region_name=e.region_name,
                    city=e.city,
                    extracted_entities=e.extracted_entities or {},
                    dedup_hash=e.dedup_hash,
                    ingested_at=e.ingested_at
                )
            )

    return IncidentDetailResponse(
        id=inc.id,
        title=inc.title,
        status=inc.status,
        severity=inc.severity,
        risk_score=inc.risk_score,
        machine_id=inc.machine_id,
        machine_name=inc.machine.name if inc.machine else None,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        finding_count=inc.finding_count,
        mitre_techniques=inc.mitre_techniques or [],
        assignee=inc.assignee,
        notes=inc.notes,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        findings=finding_responses,
        evidence_events=event_responses
    )


def update_incident(db: Session, incident_id: int, params: IncidentUpdateParams) -> IncidentResponse:
    inc = IncidentService.update_status(
        db,
        incident_id,
        params.status if params.status else "OPEN",
        params.notes
    )
    if not inc:
        raise NotFoundException(f"Incident with id {incident_id} not found", field="incident_id")

    if params.assignee is not None:
        inc.assignee = params.assignee
        db.commit()
        db.refresh(inc)

    return IncidentResponse(
        id=inc.id,
        title=inc.title,
        status=inc.status,
        severity=inc.severity,
        risk_score=inc.risk_score,
        machine_id=inc.machine_id,
        machine_name=inc.machine.name if inc.machine else None,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        finding_count=inc.finding_count,
        mitre_techniques=inc.mitre_techniques or [],
        assignee=inc.assignee,
        notes=inc.notes,
        created_at=inc.created_at,
        updated_at=inc.updated_at
    )
