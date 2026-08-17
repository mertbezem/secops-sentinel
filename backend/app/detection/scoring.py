from typing import Any

CRITICAL_SOURCES = {
    "Service Control Manager",
    "Application Error",
    "Windows Error Reporting",
    "Microsoft-Windows-Security-Auditing",
    "Windows Defender",
    "EventLog",
}


def map_score_to_severity(score: int) -> str:
    """
    Helper function to map a risk score (0-100) to severity.
    """
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    elif score >= 15:
        return "LOW"
    else:
        return "INFO"


def calculate_risk_score(
    entry_type: str,
    source: str,
    is_business_hours: bool,
    is_new_template: bool,
    machine_criticality: str,
    recent_findings_count: int,
    base_weight: int = 0,
) -> tuple[int, str, float, list[dict[str, Any]]]:
    """
    Ek C'ye göre açıklanabilir risk skoru ve seviyesi hesaplar.
    """
    reasons: list[dict[str, Any]] = []
    score = base_weight

    if entry_type == "Error":
        score += 20
        reasons.append({"factor": "entry_type_error", "points": 20})
    elif entry_type == "Warning":
        score += 10
        reasons.append({"factor": "entry_type_warning", "points": 10})
    elif entry_type == "FailureAudit":
        score += 25
        reasons.append({"factor": "entry_type_failure_audit", "points": 25})

    if source in CRITICAL_SOURCES:
        score += 20
        reasons.append({"factor": f"critical_source:{source}", "points": 20})

    if not is_business_hours:
        score += 10
        reasons.append({"factor": "outside_business_hours", "points": 10})

    if is_new_template:
        score += 15
        reasons.append({"factor": "new_message_template", "points": 15})

    if machine_criticality == "HIGH":
        score += 15
        reasons.append({"factor": "machine_criticality_high", "points": 15})

    if recent_findings_count >= 3:
        score += 10
        reasons.append({"factor": "high_recent_finding_density", "points": 10})

    final_score = min(100, score)

    severity = map_score_to_severity(final_score)
    confidence = round(min(1.0, 0.5 + (len(reasons) * 0.08)), 2)

    return final_score, severity, confidence, reasons
