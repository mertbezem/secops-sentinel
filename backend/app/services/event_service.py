import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundException
from app.models.models import Event, Machine
from app.schemas.event import EventResponse


def get_events_paginated(
    db: Session,
    machine: str | None = None,
    source: str | None = None,
    entry_type: str | None = None,
    from_time: datetime.datetime | None = None,
    to_time: datetime.datetime | None = None,
    query_str: str | None = None,
    sort: str = "desc",
    page: int = 1,
    page_size: int = 50
) -> tuple[list[EventResponse], int]:
    stmt = select(Event)

    if machine:
        stmt = stmt.join(Machine).where(func.lower(Machine.name) == machine.lower())

    if source:
        stmt = stmt.where(func.lower(Event.source) == source.lower())

    if entry_type:
        stmt = stmt.where(func.lower(Event.entry_type) == entry_type.lower())

    if from_time:
        stmt = stmt.where(Event.ts_utc >= from_time)

    if to_time:
        stmt = stmt.where(Event.ts_utc <= to_time)

    if query_str:
        pattern = f"%{query_str.lower()}%"
        stmt = stmt.where(func.lower(Event.message).like(pattern))

    # Total count query
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = db.scalar(count_stmt) or 0

    # Sorting
    if sort.lower() == "asc":
        stmt = stmt.order_by(Event.ts_utc.asc())
    else:
        stmt = stmt.order_by(Event.ts_utc.desc())

    # Pagination
    offset = (page - 1) * page_size
    stmt = stmt.offset(offset).limit(page_size)

    events = db.scalars(stmt).all()

    items = []
    for e in events:
        resp = EventResponse(
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
        items.append(resp)

    return items, total


def get_event_by_id(db: Session, event_id: int) -> EventResponse:
    e = db.get(Event, event_id)
    if not e:
        raise NotFoundException(f"Event with id {event_id} not found", field="event_id")

    return EventResponse(
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
