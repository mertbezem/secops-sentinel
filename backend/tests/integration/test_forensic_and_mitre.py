import datetime
from unittest.mock import patch

from app.models.models import Incident, Machine
from app.services.alert_service import AlertService
from app.services.pdf_report_service import PdfReportService


def test_pdf_report_generation(db_session):
    now = datetime.datetime.now(datetime.UTC)
    machine = Machine(
        name="TEST-SRV-99",
        criticality="CRITICAL",
        first_seen=now,
        last_seen=now,
        event_count=10
    )
    db_session.add(machine)
    db_session.flush()

    incident = Incident(
        machine_id=machine.id,
        title="Test Critical Malicious Activity Detected",
        severity="CRITICAL",
        risk_score=95,
        status="OPEN",
        first_seen=now,
        last_seen=now,
        finding_count=2,
        mitre_techniques=["T1489", "T1070.001"]
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    pdf_bytes = PdfReportService.generate_incident_pdf(incident, db_session)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")


def test_download_incident_pdf_api_endpoint(client, db_session, admin_token):
    now = datetime.datetime.now(datetime.UTC)
    machine = Machine(
        name="APP-SERVER-01",
        criticality="HIGH",
        first_seen=now,
        last_seen=now,
        event_count=5
    )
    db_session.add(machine)
    db_session.flush()

    incident = Incident(
        machine_id=machine.id,
        title="Test Lateral Movement Incident",
        severity="HIGH",
        risk_score=80,
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
        f"/api/v1/incidents/{incident.id}/pdf",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "SecOps_Incident_" in res.headers.get("content-disposition", "")
    assert res.content.startswith(b"%PDF")


def test_mitre_matrix_api_endpoint(client, db_session):
    res = client.get("/api/v1/stats/mitre-matrix")
    assert res.status_code == 200
    data = res.json()
    assert "tactics" in data
    assert "total_active_techniques" in data
    assert "total_hits" in data
    assert len(data["tactics"]) > 0


def test_webhook_alert_dispatch(db_session):
    now = datetime.datetime.now(datetime.UTC)
    machine = Machine(
        name="DC-ROOT-01",
        criticality="CRITICAL",
        first_seen=now,
        last_seen=now,
        event_count=15
    )
    db_session.add(machine)
    db_session.flush()

    incident = Incident(
        machine_id=machine.id,
        title="Domain Controller Tampering",
        severity="CRITICAL",
        risk_score=99,
        status="OPEN",
        first_seen=now,
        last_seen=now,
        finding_count=3,
        mitre_techniques=["T1070.001"]
    )
    db_session.add(incident)
    db_session.commit()

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.status = 200
        success = AlertService.send_webhook_alert(
            incident=incident,
            webhook_url="https://discord.com/api/webhooks/mock/123"
        )
        assert success is True
        assert mock_urlopen.called
