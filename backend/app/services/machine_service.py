from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundException
from app.models.models import Event, Finding, Machine
from app.schemas.machine import MachineResponse, MachineTimelineResponse, TimelineItem


def get_machines_paginated(
    db: Session,
    page: int = 1,
    page_size: int = 50
) -> tuple[list[MachineResponse], int]:
    stmt = select(Machine).order_by(Machine.event_count.desc())
    
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    offset = (page - 1) * page_size
    machines = db.scalars(stmt.offset(offset).limit(page_size)).all()

    items = [MachineResponse.model_validate(m) for m in machines]
    return items, total


def get_machine_by_id(db: Session, machine_id: int) -> MachineResponse:
    machine = db.get(Machine, machine_id)
    if not machine:
        raise NotFoundException(f"Machine with id {machine_id} not found", field="machine_id")
    return MachineResponse.model_validate(machine)


def get_machine_timeline(db: Session, machine_id: int, limit: int = 100) -> MachineTimelineResponse:
    machine = db.get(Machine, machine_id)
    if not machine:
        raise NotFoundException(f"Machine with id {machine_id} not found", field="machine_id")

    items: list[TimelineItem] = []

    # Events
    events = db.scalars(
        select(Event)
        .where(Event.machine_id == machine_id)
        .order_by(Event.ts_utc.desc())
        .limit(limit)
    ).all()

    for e in events:
        items.append(
            TimelineItem(
                timestamp=e.ts_utc,
                item_type="EVENT",
                source_or_rule=e.source,
                severity_or_entrytype=e.entry_type,
                summary=e.message[:120] + ("..." if len(e.message) > 120 else ""),
                details={"event_id": e.id, "city": e.city}
            )
        )

    # Findings
    findings = db.scalars(
        select(Finding)
        .where(Finding.machine_id == machine_id)
        .order_by(Finding.ts_utc.desc())
        .limit(limit)
    ).all()

    for f in findings:
        rule_name = f.rule.name if f.rule else f.rule_code
        items.append(
            TimelineItem(
                timestamp=f.ts_utc,
                item_type="FINDING",
                source_or_rule=rule_name,
                severity_or_entrytype=f.severity,
                summary=f"Finding by {rule_name} (Risk Score: {f.risk_score})",
                details={"finding_id": f.id, "reasons": f.reasons}
            )
        )

    # Sort combined timeline DESC
    items.sort(key=lambda x: x.timestamp, reverse=True)

    return MachineTimelineResponse(
        machine_id=machine.id,
        machine_name=machine.name,
        timeline=items[:limit]
    )
