from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.rules.base import BaseRule
from app.detection.rules.r001_error_burst import ErrorBurstRule
from app.detection.rules.r002_service_restart_loop import ServiceRestartLoopRule
from app.detection.rules.r003_new_template import NewMessageTemplateRule
from app.detection.rules.r004_off_hours import OffHoursAnomalyRule
from app.detection.rules.r005_geo_inconsistency import GeoInconsistencyRule
from app.models.models import Rule


class RuleRegistry:
    def __init__(self):
        self._rule_classes: dict[str, type[BaseRule]] = {
            "R001": ErrorBurstRule,
            "R002": ServiceRestartLoopRule,
            "R003": NewMessageTemplateRule,
            "R004": OffHoursAnomalyRule,
            "R005": GeoInconsistencyRule,
        }

    def seed_rules(self, db: Session) -> None:
        """
        Seeds default rule definitions into `rules` DB table if missing.
        Syncs DB parameters to rule instances.
        """
        existing_rules = {r.code: r for r in db.scalars(select(Rule)).all()}

        for code, rule_cls in self._rule_classes.items():
            if code not in existing_rules:
                db_rule = Rule(
                    code=rule_cls.code,
                    name=rule_cls.name,
                    enabled=rule_cls.enabled,
                    params=rule_cls.params,
                    weight=rule_cls.weight,
                    mitre_techniques=rule_cls.mitre_techniques,
                    is_demo=rule_cls.is_demo,
                )
                db.add(db_rule)
        db.commit()

    def get_active_rules(self, db: Session) -> list[BaseRule]:
        """
        Returns active BaseRule instances initialized with params from DB.
        """
        db_rules = db.scalars(select(Rule).where(Rule.enabled == True)).all()
        rule_instances: list[BaseRule] = []

        for r_db in db_rules:
            if r_db.code in self._rule_classes:
                cls = self._rule_classes[r_db.code]
                instance = cls(params=r_db.params)
                instance.enabled = r_db.enabled
                instance.weight = r_db.weight
                instance.mitre_techniques = r_db.mitre_techniques
                instance.is_demo = r_db.is_demo
                rule_instances.append(instance)

        return rule_instances


registry = RuleRegistry()
