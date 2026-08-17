from app.detection.scoring import calculate_risk_score, map_score_to_severity


def test_map_score_to_severity():
    assert map_score_to_severity(85) == "CRITICAL"
    assert map_score_to_severity(70) == "HIGH"
    assert map_score_to_severity(45) == "MEDIUM"
    assert map_score_to_severity(20) == "LOW"
    assert map_score_to_severity(5) == "INFO"


def test_risk_score_calculation_with_modifiers():
    score, severity, confidence, reasons = calculate_risk_score(
        entry_type="Error",
        source="Service Control Manager",
        is_business_hours=False,
        is_new_template=True,
        machine_criticality="HIGH",
        recent_findings_count=3,
        base_weight=40
    )

    # 40 (base) + 20 (Error) + 20 (Critical source) + 10 (off hours) + 15 (new template) + 15 (Criticality HIGH) + 10 (Frequency spike) = 130 -> capped at 100
    assert score == 100
    assert severity == "CRITICAL"
    assert confidence > 0.8
    assert len(reasons) == 6
