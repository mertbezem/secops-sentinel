import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.common import PaginatedResponse
from app.schemas.event import EventResponse
from app.services.event_service import get_event_by_id, get_events_paginated

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("", response_model=PaginatedResponse[EventResponse])
def list_events(
    machine: str | None = Query(None, description="Filter by Machine name"),
    source: str | None = Query(None, description="Filter by Source name"),
    entry_type: str | None = Query(None, description="Filter by EntryType"),
    from_time: datetime.datetime | None = Query(None, alias="from", description="Filter start timestamp (UTC)"),
    to_time: datetime.datetime | None = Query(None, alias="to", description="Filter end timestamp (UTC)"),
    q: str | None = Query(None, description="Search term in message"),
    sort: str = Query("desc", description="Sort order: asc or desc"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    db: Session = Depends(get_db)
) -> PaginatedResponse[EventResponse]:
    items, total = get_events_paginated(
        db=db,
        machine=machine,
        source=source,
        entry_type=entry_type,
        from_time=from_time,
        to_time=to_time,
        query_str=q,
        sort=sort,
        page=page,
        page_size=page_size
    )
    return PaginatedResponse[EventResponse](
        items=items,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/{event_id}", response_model=EventResponse)
def get_event(
    event_id: int,
    db: Session = Depends(get_db)
) -> EventResponse:
    return get_event_by_id(db, event_id)
