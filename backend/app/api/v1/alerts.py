from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.models import Finding, Incident
from app.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class TestEmailRequest(BaseModel):
    recipient: str | None = None


class AlertConfigResponse(BaseModel):
    email_alerts_enabled: bool
    smtp_host: str
    smtp_port: int
    smtp_user_configured: bool
    smtp_tls: bool
    smtp_ssl: bool
    alert_email_from: str
    alert_email_to: str
    alert_min_severity: str


@router.get("/config", response_model=AlertConfigResponse)
def get_alert_config():
    """
    Mevcut e-posta alarm yapılandırmasını döner (kimlik bilgileri maskelenmiştir).
    """
    return AlertConfigResponse(
        email_alerts_enabled=settings.EMAIL_ALERTS_ENABLED,
        smtp_host=settings.SMTP_HOST,
        smtp_port=settings.SMTP_PORT,
        smtp_user_configured=bool(settings.SMTP_USER),
        smtp_tls=settings.SMTP_TLS,
        smtp_ssl=settings.SMTP_SSL,
        alert_email_from=settings.ALERT_EMAIL_FROM,
        alert_email_to=settings.ALERT_EMAIL_TO,
        alert_min_severity=settings.ALERT_MIN_SEVERITY
    )


@router.post("/test")
def send_test_email(payload: TestEmailRequest | None = None):
    """
    SMTP ayarlarını test etmek amacıyla doğrulama e-postası gönderir.
    """
    target_email = (payload.recipient if payload and payload.recipient else settings.ALERT_EMAIL_TO)
    result = AlertService.send_test_alert(recipient=target_email)
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "SMTP_ERROR", "message": result["message"], "field": "smtp"}
        )
    return result


@router.post("/incident/{incident_id}")
def send_incident_email_alert(
    incident_id: int,
    recipient: str | None = Query(None),
    db: Session = Depends(get_db)
):
    """
    Belirli bir güvenlik olayı için e-posta alarmını manuel olarak tetikler.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Incident #{incident_id} not found", "field": "id"}
        )

    findings = db.query(Finding).filter(Finding.incident_id == incident_id).all()
    success = AlertService.send_incident_alert(incident=incident, findings=findings, recipient=recipient)

    return {
        "incident_id": incident_id,
        "success": success,
        "recipient": recipient or settings.ALERT_EMAIL_TO,
        "message": f"Email alert sent for Incident #{incident_id}" if success else "Failed to send email alert. Verify SMTP settings."
    }
