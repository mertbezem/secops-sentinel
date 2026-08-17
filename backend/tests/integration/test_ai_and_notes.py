import datetime

from app.models.models import Incident, Machine
from app.services.ai_analysis_service import AiAnalysisService


def test_ai_analysis_service(db_session):
    now = datetime.datetime.now(datetime.UTC)
    machine = Machine(
        name="SRV-DB-PROD",
        criticality="CRITICAL",
        first_seen=now,
        last_seen=now,
        event_count=50
    )
    db_session.add(machine)
    db_session.flush()

    incident = Incident(
        machine_id=machine.id,
        title="Repeated Service Failure & Defense Evasion",
        severity="CRITICAL",
        risk_score=92,
        status="OPEN",
        first_seen=now,
        last_seen=now,
        finding_count=2,
        mitre_techniques=["T1489", "T1070.001"]
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    analysis = AiAnalysisService.analyze_incident(incident=incident, db=db_session)
    assert analysis["incident_id"] == incident.id
    assert "executive_summary" in analysis
    assert "attack_scenario" in analysis
    assert analysis["confidence_score"] >= 70
    assert len(analysis["recommended_commands"]) > 0


def test_ai_analysis_api_endpoint(client, db_session, admin_token):
    now = datetime.datetime.now(datetime.UTC)
    machine = Machine(
        name="SRV-APP-02",
        criticality="HIGH",
        first_seen=now,
        last_seen=now,
        event_count=20
    )
    db_session.add(machine)
    db_session.flush()

    incident = Incident(
        machine_id=machine.id,
        title="Off-Hours Authentication Outlier",
        severity="HIGH",
        risk_score=78,
        status="OPEN",
        first_seen=now,
        last_seen=now,
        finding_count=1,
        mitre_techniques=["T1078"]
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    res = client.get(
        f"/api/v1/incidents/{incident.id}/ai-analysis",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == incident.id
    assert "confidence_score" in data
    assert "recommended_commands" in data


def test_incident_notes_and_audit_trail(client, db_session, admin_token):
    now = datetime.datetime.now(datetime.UTC)
    machine = Machine(
        name="SRV-WEB-01",
        criticality="MEDIUM",
        first_seen=now,
        last_seen=now,
        event_count=10
    )
    db_session.add(machine)
    db_session.flush()

    incident = Incident(
        machine_id=machine.id,
        title="Web Server Burst",
        severity="MEDIUM",
        risk_score=55,
        status="OPEN",
        first_seen=now,
        last_seen=now,
        finding_count=1
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    # 1. Post a note
    post_res = client.post(
        f"/api/v1/incidents/{incident.id}/notes",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "note_text": "Firewall IP engelleme kuralı uygulandı ve makine izole edildi.",
            "action_type": "CONTAINMENT"
        }
    )
    assert post_res.status_code == 201
    note_data = post_res.json()
    assert note_data["note_text"] == "Firewall IP engelleme kuralı uygulandı ve makine izole edildi."
    assert note_data["action_type"] == "CONTAINMENT"

    # 2. Get notes
    get_res = client.get(
        f"/api/v1/incidents/{incident.id}/notes",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert get_res.status_code == 200
    notes_list = get_res.json()
    assert len(notes_list) >= 1
    assert notes_list[0]["author_username"] == "admin"
