from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.common import PaginatedResponse
from app.schemas.machine import MachineResponse, MachineTimelineResponse
from app.services.machine_service import (
    get_machine_by_id,
    get_machine_timeline,
    get_machines_paginated,
)

router = APIRouter(prefix="/machines", tags=["Machines"])


@router.get("", response_model=PaginatedResponse[MachineResponse])
def list_machines(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    db: Session = Depends(get_db)
) -> PaginatedResponse[MachineResponse]:
    items, total = get_machines_paginated(db=db, page=page, page_size=page_size)
    return PaginatedResponse[MachineResponse](
        items=items,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/{machine_id}", response_model=MachineResponse)
def get_machine(
    machine_id: int,
    db: Session = Depends(get_db)
) -> MachineResponse:
    return get_machine_by_id(db, machine_id)


@router.get("/{machine_id}/timeline", response_model=MachineTimelineResponse)
def get_timeline(
    machine_id: int,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
) -> MachineTimelineResponse:
    return get_machine_timeline(db, machine_id, limit=limit)
