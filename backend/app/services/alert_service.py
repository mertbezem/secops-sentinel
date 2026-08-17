import email.utils
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from app.core.config import settings
from app.core.logging import logger
from app.models.models import Finding, Incident

SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}


class AlertService:
    @staticmethod
    def should_alert(severity: str) -> bool:
        min_sev = settings.ALERT_MIN_SEVERITY.upper()
        min_level = SEVERITY_LEVELS.get(min_sev, 3)
        incident_level = SEVERITY_LEVELS.get(severity.upper(), 0)
        return incident_level >= min_level

    @classmethod
    def send_incident_alert(
        cls,
        incident: Incident,
        findings: list[Finding] | None = None,
        recipient: str | None = None
    ) -> bool:
        """
        Sends an email alert for a high/critical security incident.
        """
        if not settings.EMAIL_ALERTS_ENABLED and recipient is None:
            logger.debug(
                f"[AlertService] Email alerts disabled. Skipping email for Incident #{incident.id} [{incident.severity}]."
            )
            return False

        if not cls.should_alert(incident.severity) and recipient is None:
            logger.debug(
                f"[AlertService] Incident #{incident.id} severity {incident.severity} is below threshold {settings.ALERT_MIN_SEVERITY}."
            )
            return False

        to_email = recipient or settings.ALERT_EMAIL_TO
        from_email = settings.ALERT_EMAIL_FROM
        subject = f"[{incident.severity}] Security Alert: {incident.title} (Risk: {incident.risk_score}/100)"

        html_body, text_body = cls._render_email_content(incident, findings)

        # Dispatch Webhook Alert if configured
        if settings.WEBHOOK_URL:
            cls.send_webhook_alert(incident=incident, findings=findings)

        return cls._send_smtp_email(
            to_email=to_email,
            from_email=from_email,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )

    @classmethod
    def send_webhook_alert(
        cls,
        incident: Incident,
        findings: list[Finding] | None = None,
        webhook_url: str | None = None
    ) -> bool:
        """
        Dispatches a rich JSON / Discord / Slack webhook alert for an incident.
        """
        target_url = webhook_url or settings.WEBHOOK_URL
        if not target_url:
            return False

        machine_name = incident.machine.name if incident.machine else f"Machine #{incident.machine_id}"
        sev_color_int = {
            "CRITICAL": 15682628,  # Red #EF4444
            "HIGH": 16347926,      # Orange #F97316
            "MEDIUM": 15381256,    # Yellow #EAB308
            "LOW": 2278750         # Green #22C55E
        }.get(incident.severity.upper(), 3717112)

        mitre_str = ", ".join(incident.mitre_techniques or []) or "None"

        payload = {
            "content": f"🚨 **SecOps Sentinel Alert** — [{incident.severity}] {incident.title}",
            "embeds": [
                {
                    "title": f"Incident #{incident.id}: {incident.title}",
                    "description": f"Target: `{machine_name}` | Risk Score: **{incident.risk_score}/100**",
                    "color": sev_color_int,
                    "fields": [
                        {"name": "Severity", "value": incident.severity, "inline": True},
                        {"name": "Status", "value": incident.status, "inline": True},
                        {"name": "Findings Count", "value": str(incident.finding_count), "inline": True},
                        {"name": "MITRE ATT&CK", "value": f"`{mitre_str}`", "inline": False},
                        {"name": "First Seen (UTC)", "value": str(incident.first_seen), "inline": True},
                        {"name": "Last Seen (UTC)", "value": str(incident.last_seen), "inline": True}
                    ],
                    "footer": {"text": "SecOps Sentinel SIEM Alerting"}
                }
            ]
        }

        try:
            import json
            import urllib.request
            req = urllib.request.Request(
                target_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "SecOpsSentinel/0.1"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                logger.info(f"[AlertService] Webhook dispatched to {target_url[:30]}... status={resp.status}")
                return True
        except Exception as e:
            logger.warning(f"[AlertService] Failed to dispatch webhook alert: {e}")
            return False


    @classmethod
    def send_test_alert(cls, recipient: str) -> dict[str, Any]:
        """
        Sends a test email to verify SMTP configuration.
        """
        subject = "[TEST ALERT] SecOps Sentinel Alerting Engine Verification"
        text_body = (
            "This is a test notification from SecOps Sentinel SIEM Alerting Engine.\n\n"
            "If you are receiving this message, your SMTP server configuration and email notifications "
            "are working successfully."
        )
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; padding: 24px;">
                <h2 style="color: #38bdf8; margin-top: 0;">SecOps Sentinel — Test Alert</h2>
                <p>This is a verification email from your <strong>SecOps Sentinel SIEM Alerting Engine</strong>.</p>
                <div style="background-color: #0f172a; border-left: 4px solid #22c55e; padding: 12px; border-radius: 4px; margin: 16px 0;">
                    <p style="margin: 0; color: #22c55e; font-weight: bold;">SMTP Connection Test: SUCCESSFUL</p>
                </div>
                <p style="color: #94a3b8; font-size: 13px;">Recipient: {recipient}</p>
                <p style="color: #94a3b8; font-size: 13px;">Host: {settings.SMTP_HOST}:{settings.SMTP_PORT}</p>
            </div>
        </body>
        </html>
        """

        success = cls._send_smtp_email(
            to_email=recipient,
            from_email=settings.ALERT_EMAIL_FROM,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )

        return {
            "success": success,
            "recipient": recipient,
            "smtp_host": settings.SMTP_HOST,
            "smtp_port": settings.SMTP_PORT,
            "message": "Test email dispatched successfully." if success else "Failed to dispatch test email. Check server logs."
        }

    @classmethod
    def _render_email_content(
        cls,
        incident: Incident,
        findings: list[Finding] | None = None
    ) -> tuple[str, str]:
        sev = incident.severity.upper()
        sev_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
            "INFO": "#38bdf8"
        }.get(sev, "#94a3b8")

        mitre_tags = ", ".join(incident.mitre_techniques or []) or "None"
        machine_name = incident.machine.name if incident.machine else f"Machine #{incident.machine_id}"

        # Text Body
        text_lines = [
            "=" * 60,
            f"SECOPS SENTINEL SECURITY ALERT: {incident.title}",
            "=" * 60,
            f"Incident ID: #{incident.id}",
            f"Severity: {incident.severity}",
            f"Risk Score: {incident.risk_score} / 100",
            f"Target Machine: {machine_name}",
            f"First Seen (UTC): {incident.first_seen}",
            f"Last Seen (UTC): {incident.last_seen}",
            f"Findings Count: {incident.finding_count}",
            f"MITRE ATT&CK: {mitre_tags}",
            "-" * 60,
        ]

        if findings:
            text_lines.append("Triggered Findings:")
            for f in findings[:5]:
                text_lines.append(f"  - [{f.rule_code}] {f.severity} (Score: {f.risk_score})")

        text_lines.extend([
            "-" * 60,
            "Action Required: Please log in to the SecOps Sentinel SOC Dashboard to investigate.",
            "=" * 60
        ])
        text_body = "\n".join(text_lines)

        # Findings table rows for HTML
        findings_html = ""
        if findings:
            rows = []
            for f in findings[:6]:
                reasons_text = ", ".join(r.get("factor", "") for r in (f.reasons or [])) or "Standard trigger"
                rows.append(f"""
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #334155; font-family: monospace;">{f.rule_code}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155; color: {sev_color}; font-weight: bold;">{f.severity}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155;">{f.risk_score}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155; color: #94a3b8; font-size: 12px;">{reasons_text}</td>
                </tr>
                """)
            findings_html = f"""
            <table style="width: 100%; border-collapse: collapse; margin-top: 12px; background: #0f172a; border-radius: 6px; overflow: hidden;">
                <thead>
                    <tr style="background: #1e293b; color: #94a3b8; font-size: 12px; text-align: left;">
                        <th style="padding: 8px;">RULE</th>
                        <th style="padding: 8px;">SEVERITY</th>
                        <th style="padding: 8px;">SCORE</th>
                        <th style="padding: 8px;">FACTORS</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
            """

        # HTML Body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
        </head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 24px; margin: 0;">
            <div style="max-width: 650px; margin: 0 auto; background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);">
                <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 16px;">
                    <h2 style="margin: 0; color: #f8fafc; font-size: 20px;">🛡️ SecOps Sentinel — Security Alert</h2>
                    <span style="background-color: {sev_color}; color: #000000; font-weight: bold; padding: 4px 10px; border-radius: 4px; font-size: 12px;">
                        {incident.severity}
                    </span>
                </div>

                <div style="background-color: #0f172a; border-left: 4px solid {sev_color}; padding: 14px; border-radius: 4px; margin-bottom: 16px;">
                    <h3 style="margin: 0 0 6px 0; font-size: 16px; color: #ffffff;">{incident.title}</h3>
                    <p style="margin: 0; color: #94a3b8; font-size: 13px;">Incident #{incident.id} &bull; Target: <strong style="color: #38bdf8;">{machine_name}</strong></p>
                </div>

                <table style="width: 100%; border-collapse: collapse; margin-bottom: 16px;">
                    <tr>
                        <td style="padding: 6px 0; color: #94a3b8; width: 140px; font-size: 13px;">Risk Score:</td>
                        <td style="padding: 6px 0; font-size: 14px;"><strong style="color: {sev_color};">{incident.risk_score}</strong> / 100</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #94a3b8; font-size: 13px;">MITRE ATT&CK:</td>
                        <td style="padding: 6px 0; font-family: monospace; font-size: 13px; color: #38bdf8;">{mitre_tags}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #94a3b8; font-size: 13px;">First Seen (UTC):</td>
                        <td style="padding: 6px 0; font-size: 13px;">{incident.first_seen}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #94a3b8; font-size: 13px;">Last Seen (UTC):</td>
                        <td style="padding: 6px 0; font-size: 13px;">{incident.last_seen}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #94a3b8; font-size: 13px;">Findings Count:</td>
                        <td style="padding: 6px 0; font-size: 13px;">{incident.finding_count}</td>
                    </tr>
                </table>

                {findings_html}

                <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #334155; text-align: center;">
                    <p style="margin: 0 0 12px 0; color: #94a3b8; font-size: 12px;">This is an automated notification from your SecOps Sentinel SIEM instance.</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html_body, text_body

    @classmethod
    def _send_smtp_email(
        cls,
        to_email: str,
        from_email: str,
        subject: str,
        html_body: str,
        text_body: str
    ) -> bool:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_email
            msg["To"] = to_email
            msg["Date"] = email.utils.formatdate(localtime=True)

            msg.attach(MIMEText(text_body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))

            server: smtplib.SMTP | smtplib.SMTP_SSL
            if settings.SMTP_SSL:
                server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)
            else:
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10)
                if settings.SMTP_TLS:
                    server.starttls()

            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

            server.sendmail(from_email, [to_email], msg.as_string())
            server.quit()
            logger.info(f"[AlertService] Successfully delivered email alert to {to_email}: {subject}")
            return True
        except Exception as e:
            logger.error(f"[AlertService] Failed to send email alert to {to_email}: {e}")
            return False
