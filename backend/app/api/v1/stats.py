from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.stats import StatsOverviewResponse, StatsTimeseriesResponse
from app.services.stats_service import get_mitre_matrix, get_stats_overview, get_stats_timeseries

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("/overview", response_model=StatsOverviewResponse)
def overview(
    db: Session = Depends(get_db)
) -> StatsOverviewResponse:
    return get_stats_overview(db)


@router.get("/timeseries", response_model=StatsTimeseriesResponse)
def timeseries(
    buckets: int = Query(24, ge=2, le=100),
    db: Session = Depends(get_db)
) -> StatsTimeseriesResponse:
    return get_stats_timeseries(db, buckets_count=buckets)


@router.get("/mitre-matrix")
def mitre_matrix(
    db: Session = Depends(get_db)
):
    """
    Tespit edilen tehditlerin MITRE ATT&CK Taktik ve Teknik ısı haritası matrisini döner.
    """
    return get_mitre_matrix(db)

