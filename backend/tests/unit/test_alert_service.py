import datetime
from unittest.mock import MagicMock, patch

from app.core.config import settings
from app.models.models import Finding, Incident, Machine
from app.services.alert_service import AlertService


def test_should_alert_threshold():
    settings.ALERT_MIN_SEVERITY = "HIGH"
    assert AlertService.should_alert("CRITICAL") is True
    assert AlertService.should_alert("HIGH") is True
    assert AlertService.should_alert("MEDIUM") is False
    assert AlertService.should_alert("LOW") is False

    settings.ALERT_MIN_SEVERITY = "MEDIUM"
    assert AlertService.should_alert("MEDIUM") is True
    assert AlertService.should_alert("LOW") is False

    # Restore default
    settings.ALERT_MIN_SEVERITY = "HIGH"


def test_render_email_content():
    machine = Machine(
        id=1,
        name="SRV-DATABASE-01",
        criticality="HIGH",
        first_seen=datetime.datetime.now(datetime.UTC),
        last_seen=datetime.datetime.now(datetime.UTC),
        event_count=50
    )
    incident = Incident(
        id=42,
        title="Security Incident on Machine #1 [R001, R002]",
        status="OPEN",
        severity="CRITICAL",
        risk_score=85,
        machine_id=1,
        first_seen=datetime.datetime.now(datetime.UTC),
        last_seen=datetime.datetime.now(datetime.UTC),
        finding_count=2,
        mitre_techniques=["T1489", "T1070.001"]
    )
    incident.machine = machine

    finding = Finding(
        id=101,
        rule_code="R001",
        machine_id=1,
        ts_utc=datetime.datetime.now(datetime.UTC),
        severity="CRITICAL",
        confidence=0.9,
        risk_score=85,
        reasons=[{"factor": "entry_type_error", "points": 20}],
        evidence_event_ids=[1, 2, 3],
        incident_id=42
    )

    html, text = AlertService._render_email_content(incident, [finding])

    assert "SRV-DATABASE-01" in html
    assert "CRITICAL" in html
    assert "85" in html
    assert "T1489" in html
    assert "R001" in html

    assert "SRV-DATABASE-01" in text
    assert "CRITICAL" in text
    assert "T1489" in text


@patch("smtplib.SMTP")
def test_send_incident_alert_success(mock_smtp):
    mock_server = MagicMock()
    mock_smtp.return_value = mock_server

    settings.EMAIL_ALERTS_ENABLED = True
    settings.ALERT_EMAIL_TO = "security-analyst@example.com"
    settings.ALERT_MIN_SEVERITY = "HIGH"

    incident = Incident(
        id=99,
        title="Critical Anomaly Detected",
        status="OPEN",
        severity="CRITICAL",
        risk_score=90,
        machine_id=1,
        first_seen=datetime.datetime.now(datetime.UTC),
        last_seen=datetime.datetime.now(datetime.UTC),
        finding_count=1,
        mitre_techniques=["T1489"]
    )

    result = AlertService.send_incident_alert(incident=incident)
    assert result is True
    mock_server.sendmail.assert_called_once()
    mock_server.quit.assert_called_once()

    # Reset
    settings.EMAIL_ALERTS_ENABLED = False


def test_send_incident_alert_disabled_skips():
    settings.EMAIL_ALERTS_ENABLED = False
    incident = Incident(
        id=100,
        title="Ignored Low Threat",
        status="OPEN",
        severity="CRITICAL",
        risk_score=80,
        machine_id=1,
        first_seen=datetime.datetime.now(datetime.UTC),
        last_seen=datetime.datetime.now(datetime.UTC),
        finding_count=1,
        mitre_techniques=[]
    )
    result = AlertService.send_incident_alert(incident=incident)
    assert result is False
