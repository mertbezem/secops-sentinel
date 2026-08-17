from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.common import PaginatedResponse
from app.schemas.rule import RuleResponse, RuleUpdateParams
from app.services.rule_service import get_all_rules, update_rule_config

router = APIRouter(prefix="/rules", tags=["Rules"])


@router.get("", response_model=PaginatedResponse[RuleResponse])
def list_rules(
    db: Session = Depends(get_db)
) -> PaginatedResponse[RuleResponse]:
    rules = get_all_rules(db)
    return PaginatedResponse[RuleResponse](
        items=rules,
        total=len(rules),
        page=1,
        page_size=max(1, len(rules))
    )


@router.patch("/{code}", response_model=RuleResponse)
def patch_rule(
    code: str,
    params: RuleUpdateParams,
    db: Session = Depends(get_db)
) -> RuleResponse:
    return update_rule_config(db, code, params)
