from unittest.mock import MagicMock, patch


def test_get_alert_config(client):
    res = client.get("/api/v1/alerts/config")
    assert res.status_code == 200
    data = res.json()
    assert "email_alerts_enabled" in data
    assert "smtp_host" in data
    assert "smtp_port" in data
    assert "alert_min_severity" in data


@patch("smtplib.SMTP")
def test_post_test_email(mock_smtp, client):
    mock_server = MagicMock()
    mock_smtp.return_value = mock_server

    res = client.post("/api/v1/alerts/test", json={"recipient": "test-admin@secops.local"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["recipient"] == "test-admin@secops.local"


def test_post_incident_alert_not_found(client):
    res = client.post("/api/v1/alerts/incident/99999")
    assert res.status_code == 404
