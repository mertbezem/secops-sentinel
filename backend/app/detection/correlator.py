from datetime import timedelta

from sqlalchemy.orm import Session

from app.models.models import Finding, Incident


class IncidentCorrelator:
    @staticmethod
    def correlate_machine_findings(db: Session, machine_id: int) -> int:
        """
        Makineye ait gruplanmamış (incident_id IS NULL) bulguları inceler ve olaylara (Incident) bağlar.
        """
        unassigned = (
            db.query(Finding)
            .filter(Finding.machine_id == machine_id, Finding.incident_id.is_(None))
            .order_by(Finding.ts_utc.asc())
            .all()
        )
        if not unassigned:
            return 0

        created_incidents_count = 0
        window = timedelta(minutes=30)

        current_batch: list[Finding] = [unassigned[0]]

        for f in unassigned[1:]:
            if f.ts_utc - current_batch[-1].ts_utc <= window:
                current_batch.append(f)
            else:
                IncidentCorrelator._create_incident(db, machine_id, current_batch)
                created_incidents_count += 1
                current_batch = [f]

        if current_batch:
            IncidentCorrelator._create_incident(db, machine_id, current_batch)
            created_incidents_count += 1

        db.commit()
        return created_incidents_count

    @staticmethod
    def _create_incident(db: Session, machine_id: int, findings: list[Finding]) -> Incident:
        first_seen = findings[0].ts_utc
        last_seen = findings[-1].ts_utc
        max_risk = max(f.risk_score for f in findings)

        # En yüksek severity'yi belirle
        severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        top_severity = max(findings, key=lambda f: severity_order.get(f.severity, 0)).severity

        # Unique kuralları başlığa ekle
        rules_triggered = list({f.rule_code for f in findings})
        title = f"Security Incident on Machine #{machine_id} [{', '.join(rules_triggered)}]"

        # MITRE tekniklerini topla
        mitre_set = set()
        for f in findings:
            if hasattr(f, "rule") and f.rule and f.rule.mitre_techniques:
                mitre_set.update(f.rule.mitre_techniques)

        incident = Incident(
            title=title,
            status="OPEN",
            severity=top_severity,
            risk_score=max_risk,
            machine_id=machine_id,
            first_seen=first_seen,
            last_seen=last_seen,
            finding_count=len(findings),
            mitre_techniques=list(mitre_set)
        )
        db.add(incident)
        db.flush()

        for f in findings:
            f.incident_id = incident.id

        # Trigger Automated Email Notification if enabled
        from app.services.alert_service import AlertService
        AlertService.send_incident_alert(incident, findings)

        return incident


# Module-level convenience wrapper for engine.py
def correlate_findings_into_incidents(db: Session, machine_id: int) -> int:
    return IncidentCorrelator.correlate_machine_findings(db, machine_id)
