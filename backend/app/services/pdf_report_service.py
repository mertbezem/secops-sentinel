import io
import os
from datetime import UTC, datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.platypus.flowables import Flowable
from sqlalchemy.orm import Session

from app.models.models import Event, Finding, Incident

# Register TrueType Fonts for Turkish character compatibility
font_dir = "C:\\Windows\\Fonts"
arial_regular = os.path.join(font_dir, "arial.ttf")
arial_bold = os.path.join(font_dir, "arialbd.ttf")
arial_italic = os.path.join(font_dir, "ariali.ttf")

if os.path.exists(arial_regular) and os.path.exists(arial_bold):
    pdfmetrics.registerFont(TTFont("ReportFont", arial_regular))
    pdfmetrics.registerFont(TTFont("ReportFont-Bold", arial_bold))
    pdfmetrics.registerFont(TTFont("ReportFont-Italic", arial_italic if os.path.exists(arial_italic) else arial_regular))
    FONT_NAME = "ReportFont"
    FONT_BOLD = "ReportFont-Bold"
    FONT_ITALIC = "ReportFont-Italic"
else:
    FONT_NAME = "Helvetica"
    FONT_BOLD = "Helvetica-Bold"
    FONT_ITALIC = "Helvetica-Oblique"


class IncidentReportCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count):
        self.saveState()
        self.setFont(FONT_NAME, 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(40, 805, "SecOps Sentinel — Resmi Güvenlik Olayı & Adli İnceleme Raporu")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(40, 800, 555, 800)

        # Footer
        page_text = f"Sayfa {self._pageNumber} / {page_count}"
        self.drawRightString(555, 26, page_text)
        self.drawString(40, 26, "SecOps Sentinel SIEM Engine © 2026 | Confidential - For SOC Internal Use Only")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(40, 36, 555, 36)
        self.restoreState()


class PdfReportService:
    @classmethod
    def generate_incident_pdf(cls, incident: Incident, db: Session) -> bytes:
        """
        Generates a professional forensic incident PDF report in memory.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=40,
            rightMargin=40,
            topMargin=40,
            bottomMargin=45
        )

        styles = getSampleStyleSheet()

        # Custom Palette
        primary_color = colors.HexColor("#0F172A")    # Slate 900
        dark_accent = colors.HexColor("#0369A1")      # Sky 700
        card_bg = colors.HexColor("#F8FAFC")          # Slate 50
        text_dark = colors.HexColor("#1E293B")        # Slate 800

        sev_colors = {
            "CRITICAL": colors.HexColor("#DC2626"),
            "HIGH": colors.HexColor("#EA580C"),
            "MEDIUM": colors.HexColor("#CA8A04"),
            "LOW": colors.HexColor("#16A34A"),
            "INFO": colors.HexColor("#0284C7")
        }
        sev_color = sev_colors.get(incident.severity.upper(), dark_accent)

        # Typography
        style_title = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName=FONT_BOLD,
            fontSize=16,
            leading=20,
            textColor=primary_color,
            spaceAfter=2
        )
        style_subtitle = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName=FONT_NAME,
            fontSize=9.5,
            leading=13,
            textColor=dark_accent,
            spaceAfter=8
        )
        style_h1 = ParagraphStyle(
            "Header1",
            parent=styles["Normal"],
            fontName=FONT_BOLD,
            fontSize=11,
            leading=14,
            textColor=primary_color,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True
        )
        style_body = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName=FONT_NAME,
            fontSize=8.5,
            leading=12,
            textColor=text_dark,
            spaceAfter=4
        )
        style_th = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName=FONT_BOLD,
            fontSize=8,
            leading=10.5,
            textColor=colors.white,
            alignment=0
        )
        style_td = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName=FONT_NAME,
            fontSize=7.8,
            leading=10.5,
            textColor=text_dark
        )
        style_td_bold = ParagraphStyle(
            "TableCellBold",
            parent=styles["Normal"],
            fontName=FONT_BOLD,
            fontSize=7.8,
            leading=10.5,
            textColor=text_dark
        )

        elements: list[Flowable] = []

        # Title & Meta Banner
        now_str = datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
        elements.append(Paragraph(f"🛡️ Güvenlik Olayı Adli Raporu — Incident #{incident.id}", style_title))
        elements.append(Paragraph(f"Olay Başlığı: {incident.title} | Üretilme Tarihi: {now_str}", style_subtitle))
        elements.append(HRFlowable(width="100%", thickness=1.2, color=sev_color, spaceBefore=0, spaceAfter=8))

        # Section 1: Olay Özet Tablosu
        elements.append(Paragraph("1. Olay Özet Bilgileri", style_h1))
        
        machine_name = incident.machine.name if incident.machine else f"Machine #{incident.machine_id}"
        mitre_str = ", ".join(incident.mitre_techniques or []) or "Belirtilmemiş"

        overview_data = [
            [
                Paragraph("<b>Olay ID:</b>", style_td_bold),
                Paragraph(f"#{incident.id}", style_td),
                Paragraph("<b>Tehdit Seviyesi:</b>", style_td_bold),
                Paragraph(f"<font color='{sev_color.hexval()}'><b>{incident.severity}</b></font>", style_td),
            ],
            [
                Paragraph("<b>Etkilenen Cihaz:</b>", style_td_bold),
                Paragraph(f"<b>{machine_name}</b>", style_td),
                Paragraph("<b>Risk Puanı:</b>", style_td_bold),
                Paragraph(f"<b>{incident.risk_score} / 100</b>", style_td),
            ],
            [
                Paragraph("<b>Olay Durumu:</b>", style_td_bold),
                Paragraph(f"{incident.status}", style_td),
                Paragraph("<b>Bulgu Sayısı:</b>", style_td_bold),
                Paragraph(f"{incident.finding_count} Bulgu", style_td),
            ],
            [
                Paragraph("<b>İlk Görülme (UTC):</b>", style_td_bold),
                Paragraph(f"{incident.first_seen}", style_td),
                Paragraph("<b>Son Görülme (UTC):</b>", style_td_bold),
                Paragraph(f"{incident.last_seen}", style_td),
            ],
            [
                Paragraph("<b>MITRE ATT&CK:</b>", style_td_bold),
                Paragraph(f"<code>{mitre_str}</code>", style_td),
                Paragraph("<b>Atanan Analist:</b>", style_td_bold),
                Paragraph(f"{incident.assignee or 'SOC Havuzu (Atanmamış)'}", style_td),
            ]
        ]
        t_overview = Table(overview_data, colWidths=[110, 140, 110, 140])
        t_overview.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), card_bg),
            ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(t_overview)
        elements.append(Spacer(1, 4))

        # Section 2: Tetiklenen Bulgular (Findings)
        elements.append(Paragraph("2. Tespit Edilen Bulgular ve Risk Faktörleri", style_h1))
        findings = db.query(Finding).filter(Finding.incident_id == incident.id).all()
        
        findings_table_data = [
            [
                Paragraph("<b>Bulgu ID</b>", style_th),
                Paragraph("<b>Kural Kodu</b>", style_th),
                Paragraph("<b>Seviye</b>", style_th),
                Paragraph("<b>Skor</b>", style_th),
                Paragraph("<b>Zaman Damgası (UTC)</b>", style_th),
                Paragraph("<b>Açıklanabilir Nedenler & Faktörler</b>", style_th),
            ]
        ]

        all_evidence_event_ids: list[int] = []
        for f in findings:
            all_evidence_event_ids.extend(f.evidence_event_ids or [])
            reasons_str = ", ".join(f"{r.get('factor', '')} (+{r.get('points', 0)}p)" for r in (f.reasons or [])) or "Standart kural eşleşmesi"
            findings_table_data.append([
                Paragraph(f"#{f.id}", style_td_bold),
                Paragraph(f"{f.rule_code}", style_td_bold),
                Paragraph(f"<b>{f.severity}</b>", style_td),
                Paragraph(f"{f.risk_score}", style_td),
                Paragraph(f"{str(f.ts_utc)[:19]}", style_td),
                Paragraph(f"{reasons_str}", style_td),
            ])

        t_findings = Table(findings_table_data, colWidths=[50, 60, 50, 35, 110, 195])
        t_findings.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, card_bg]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_findings)
        elements.append(Spacer(1, 4))

        # Section 3: Kanıt Olay Kayıtları (Evidence Log Entries)
        elements.append(Paragraph("3. Adli Kanıt Log Kayıtları (Sample Evidence Logs)", style_h1))
        
        unique_event_ids = list(dict.fromkeys(all_evidence_event_ids))[:5]
        evidence_events = db.query(Event).filter(Event.id.in_(unique_event_ids)).all() if unique_event_ids else []

        if evidence_events:
            evidence_table_data = [
                [
                    Paragraph("<b>Event ID</b>", style_th),
                    Paragraph("<b>Kaynak (Source)</b>", style_th),
                    Paragraph("<b>Tür</b>", style_th),
                    Paragraph("<b>Mesaj Şablonu / Ham Log</b>", style_th),
                ]
            ]
            for ev in evidence_events:
                msg_preview = (ev.template.template_text if ev.template else ev.message)[:130]
                evidence_table_data.append([
                    Paragraph(f"#{ev.id}", style_td_bold),
                    Paragraph(f"{ev.source}", style_td),
                    Paragraph(f"{ev.entry_type}", style_td),
                    Paragraph(f"<i>{msg_preview}...</i>", style_td),
                ])

            t_ev = Table(evidence_table_data, colWidths=[50, 110, 65, 275])
            t_ev.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), dark_accent),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, card_bg]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_ev)
        else:
            elements.append(Paragraph("<i>Bağlantılı doğrudan kanıt log kaydı bulunamadı.</i>", style_body))

        elements.append(Spacer(1, 4))

        # Section 4: Müdahale ve İyileştirme Rehberi (SOAR Remediation Playbook)
        elements.append(Paragraph("4. SOC Müdahale ve İyileştirme Planı (Remediation Playbook)", style_h1))
        
        playbook_text = (
            "<b>Adım 1 (İzolasyon & Sınırlandırma):</b> Etkilenen makinenin (<code>" + machine_name + "</code>) "
            "ağ bağlantısını firewall üzerinden karantinaya alınız.<br/>"
            "<b>Adım 2 (Hesap Güvenliği):</b> İlişkili kullanıcı hesaplarının oturumlarını sonlandırıp geçici olarak devre dışı bırakınız.<br/>"
            "<b>Adım 3 (Servis & Süreç İncelemesi):</b> Tetiklenen MITRE tekniklerine (<code>" + mitre_str + "</code>) ait "
            "çalışan servis ve süreçleri Process Explorer ve Event Viewer üzerinden denetleyiniz.<br/>"
            "<b>Adım 4 (Kapatma & Doğrulama):</b> İyileştirme tamamlandığında olay durumunu 'RESOLVED' olarak güncelleyiniz."
        )
        t_playbook = Table([[Paragraph(playbook_text, style_body)]], colWidths=[500])
        t_playbook.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F0FDF4")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#16A34A")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(t_playbook)

        doc.build(elements, canvasmaker=IncidentReportCanvas)
        return buffer.getvalue()
