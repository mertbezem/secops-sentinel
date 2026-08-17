
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundException
from app.detection.rules.registry import registry
from app.models.models import Rule
from app.schemas.rule import RuleResponse, RuleUpdateParams


def get_all_rules(db: Session) -> list[RuleResponse]:
    registry.seed_rules(db)
    rules = db.scalars(select(Rule).order_by(Rule.code.asc())).all()
    return [RuleResponse.model_validate(r) for r in rules]


def update_rule_config(db: Session, rule_code: str, params: RuleUpdateParams) -> RuleResponse:
    registry.seed_rules(db)
    rule = db.get(Rule, rule_code.upper())
    if not rule:
        raise NotFoundException(f"Rule with code '{rule_code}' not found", field="code")

    if params.enabled is not None:
        rule.enabled = params.enabled

    if params.params is not None:
        merged_params = dict(rule.params)
        merged_params.update(params.params)
        rule.params = merged_params

    if params.weight is not None:
        rule.weight = int(params.weight)

    db.commit()
    db.refresh(rule)

    return RuleResponse.model_validate(rule)
