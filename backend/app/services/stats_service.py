import datetime

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.models.models import Event, Incident, Machine
from app.schemas.stats import (
    PeriodDetail,
    StatsOverviewResponse,
    StatsTimeseriesBucket,
    StatsTimeseriesResponse,
    TopSourceItem,
)


def get_stats_overview(db: Session) -> StatsOverviewResponse:
    total_events = db.scalar(select(func.count(Event.id))) or 0
    total_machines = db.scalar(select(func.count(Machine.id))) or 0
    open_incidents = db.scalar(
        select(func.count(Incident.id)).where(Incident.status.in_(["OPEN", "IN_PROGRESS"]))
    ) or 0

    # Severity breakdown
    sev_rows = db.execute(
        select(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
    ).all()
    
    sev_map: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    }
    for sev, count in sev_rows:
        if sev and sev.upper() in sev_map:
            sev_map[sev.upper()] = count

    # Top sources
    source_rows = db.execute(
        select(Event.source, func.count(Event.id).label("cnt"))
        .group_by(Event.source)
        .order_by(text("cnt DESC"))
        .limit(5)
    ).all()

    top_sources = [
        TopSourceItem(source=row.source, count=row.cnt)
        for row in source_rows
    ]

    # Period
    min_ts = db.scalar(select(func.min(Event.ts_utc)))
    max_ts = db.scalar(select(func.max(Event.ts_utc)))

    return StatsOverviewResponse(
        total_events=total_events,
        total_machines=total_machines,
        open_incidents=open_incidents,
        severity_breakdown=sev_map,
        top_sources=top_sources,
        period=PeriodDetail.model_validate({"from": min_ts, "to": max_ts})
    )


def get_stats_timeseries(db: Session, buckets_count: int = 24) -> StatsTimeseriesResponse:
    min_ts = db.scalar(select(func.min(Event.ts_utc)))
    max_ts = db.scalar(select(func.max(Event.ts_utc)))

    if not min_ts or not max_ts:
        return StatsTimeseriesResponse(buckets=[])

    total_seconds = (max_ts - min_ts).total_seconds()
    if total_seconds <= 0:
        total_seconds = 3600

    step_seconds = max(60, int(total_seconds / buckets_count))

    buckets: list[StatsTimeseriesBucket] = []
    curr = min_ts

    while curr <= max_ts:
        next_curr = curr + datetime.timedelta(seconds=step_seconds)
        
        evt_cnt = db.scalar(
            select(func.count(Event.id))
            .where(Event.ts_utc >= curr, Event.ts_utc < next_curr)
        ) or 0

        inc_cnt = db.scalar(
            select(func.count(Incident.id))
            .where(Incident.first_seen >= curr, Incident.first_seen < next_curr)
        ) or 0

        buckets.append(
            StatsTimeseriesBucket(
                timestamp=curr,
                event_count=evt_cnt,
                incident_count=inc_cnt
            )
        )
        curr = next_curr

    return StatsTimeseriesResponse(buckets=buckets)


MITRE_TACTIC_CATALOG = {
    "Impact": [
        {"id": "T1489", "name": "Service Stop", "desc": "Sistem veya güvenlik servislerinin durdurulması"}
    ],
    "Defense Evasion": [
        {"id": "T1070.001", "name": "Clear Windows Event Logs", "desc": "İz silme amacıyla olay günlüklerinin temizlenmesi"},
        {"id": "T1562", "name": "Impair Defenses", "desc": "Güvenlik araçlarının devre dışı bırakılması"}
    ],
    "Initial Access": [
        {"id": "T1078", "name": "Valid Accounts", "desc": "Geçerli hesapların yetkisiz kullanımı / coğrafi anomali"}
    ],
    "Execution": [
        {"id": "T1059", "name": "Command & Scripting", "desc": "Komut satırı ve PowerShell betik çalıştırma"}
    ],
    "Persistence": [
        {"id": "T1543", "name": "Create or Modify System Process", "desc": "Kalıcılık sağlamak için servis modifikasyonu"}
    ],
    "Discovery": [
        {"id": "T1082", "name": "System Information Discovery", "desc": "Sistem donanım ve işletim sistemi keşfi"}
    ]
}


def get_mitre_matrix(db: Session) -> dict:
    incidents = db.scalars(select(Incident)).all()
    technique_stats: dict[str, dict] = {}

    for inc in incidents:
        for tech in (inc.mitre_techniques or []):
            if tech not in technique_stats:
                technique_stats[tech] = {
                    "count": 0,
                    "incident_ids": [],
                    "severities": set(),
                    "top_severity": "LOW"
                }
            technique_stats[tech]["count"] += 1
            technique_stats[tech]["incident_ids"].append(inc.id)
            technique_stats[tech]["severities"].add(inc.severity)

    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    for data in technique_stats.values():
        data["top_severity"] = max(data["severities"], key=lambda s: severity_order.get(s, 0))
        data["severities"] = list(data["severities"])

    tactics_output = []
    for tactic_name, techniques in MITRE_TACTIC_CATALOG.items():
        tech_list = []
        for t in techniques:
            tech_id = t["id"]
            stat = technique_stats.get(tech_id, {
                "count": 0,
                "incident_ids": [],
                "severities": [],
                "top_severity": "NONE"
            })
            tech_list.append({
                "id": tech_id,
                "name": t["name"],
                "desc": t["desc"],
                "is_detected": stat["count"] > 0,
                "hit_count": stat["count"],
                "incident_ids": stat["incident_ids"][:5],
                "top_severity": stat["top_severity"]
            })
        tactics_output.append({
            "tactic": tactic_name,
            "techniques": tech_list
        })

    return {
        "tactics": tactics_output,
        "total_active_techniques": sum(1 for s in technique_stats.values() if s["count"] > 0),
        "total_hits": sum(s["count"] for s in technique_stats.values())
    }

