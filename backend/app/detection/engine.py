from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.baseline.calculator import compute_machine_baselines
from app.core.logging import logger
from app.detection.correlator import correlate_findings_into_incidents
from app.detection.rules.registry import registry
from app.detection.scoring import calculate_risk_score
from app.models.models import Baseline, Event, Finding, Machine


def run_detection_pipeline(db: Session) -> dict[str, Any]:
    """
    Runs full detection & correlation pipeline across all ingested data:
    1. Seeds default rules in database
    2. Computes baseline statistical profiles
    3. Executes active detection rules (R001-R005)
    4. Applies explainable risk scoring
    5. Stores new findings in DB
    6. Correlates findings into Incidents
    """
    registry.seed_rules(db)
    baselines_updated = compute_machine_baselines(db)

    active_rules = registry.get_active_rules(db)
    machines = db.scalars(select(Machine)).all()
    baselines_list = db.scalars(select(Baseline)).all()
    baselines_map = {(b.machine_id, b.source): b for b in baselines_list}

    total_findings_created = 0
    total_incidents_created = 0

    for machine in machines:
        events = list(
            db.scalars(
                select(Event)
                .where(Event.machine_id == machine.id)
                .order_by(Event.ts_utc.asc())
            ).all()
        )

        if not events:
            continue

        recent_findings_count = db.scalar(
            select(func.count(Finding.id))
            .where(Finding.machine_id == machine.id)
        ) or 0

        for rule in active_rules:
            candidate_findings = rule.evaluate(
                machine=machine,
                events=events,
                baselines=baselines_map,
                recent_findings_count=recent_findings_count
            )

            for cf in candidate_findings:
                sample_evt = cf["sample_event"]
                is_new_tmpl = bool(sample_evt.template and sample_evt.template.occurrence_count <= 5)
                risk_score, severity, _, reasons = calculate_risk_score(
                    entry_type=sample_evt.entry_type,
                    source=sample_evt.source,
                    is_business_hours=sample_evt.is_business_hours,
                    is_new_template=is_new_tmpl,
                    machine_criticality=machine.criticality,
                    recent_findings_count=recent_findings_count,
                    base_weight=cf["base_score"]
                )

                finding = Finding(
                    rule_code=rule.code,
                    machine_id=machine.id,
                    ts_utc=cf["ts_utc"],
                    severity=severity,
                    confidence=cf["confidence"],
                    risk_score=risk_score,
                    reasons=reasons,
                    evidence_event_ids=cf["evidence_event_ids"],
                    incident_id=None
                )
                db.add(finding)
                total_findings_created += 1

        db.commit()

        # Correlate findings for machine
        incidents_created = correlate_findings_into_incidents(db, machine.id)
        total_incidents_created += incidents_created

    logger.info(
        f"Detection pipeline finished. Findings: {total_findings_created}, Incidents: {total_incidents_created}"
    )

    return {
        "status": "COMPLETED",
        "baselines_updated": baselines_updated,
        "findings_created": total_findings_created,
        "incidents_created": total_incidents_created,
        "message": f"Detection run complete. Created {total_findings_created} findings and {total_incidents_created} correlated incidents."
    }
