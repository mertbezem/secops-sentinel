
from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/healthz", response_model=dict[str, str])
def health_check() -> dict[str, str]:
    return {"status": "ok"}
