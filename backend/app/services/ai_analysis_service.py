from typing import Any

from sqlalchemy.orm import Session

from app.models.models import Event, Finding, Incident


class AiAnalysisService:
    @classmethod
    def analyze_incident(cls, incident: Incident, db: Session) -> dict[str, Any]:
        """
        Performs in-depth algorithmic & heuristic forensic AI analysis of a security incident.
        """
        machine_name = incident.machine.name if incident.machine else f"Machine #{incident.machine_id}"
        crit = incident.machine.criticality if incident.machine else "MEDIUM"
        findings = db.query(Finding).filter(Finding.incident_id == incident.id).all()

        # Collect evidence event samples
        all_event_ids: list[int] = []
        rule_codes: set[str] = set()
        for f in findings:
            rule_codes.add(f.rule_code)
            all_event_ids.extend(f.evidence_event_ids or [])

        unique_event_ids = list(dict.fromkeys(all_event_ids))[:6]
        events = db.query(Event).filter(Event.id.in_(unique_event_ids)).all() if unique_event_ids else []
        sources = list({e.source for e in events})

        # Calculate Confidence Score based on evidence richness and criticality
        confidence = min(98, max(70, 70 + (incident.risk_score // 5) + (len(findings) * 4)))

        # Rule-specific storyline building
        story_points = []
        commands = []
        containment = []

        if "R001" in rule_codes:
            story_points.append(
                f"Kısa zaman aralığında {machine_name} makinesinde yoğun hata (Error Burst) patlaması tespit edildi. "
                "Bu durum genellikle servis çökertme veya yetkisiz erişim denemelerine işaret eder."
            )
            commands.append("Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 50")
            containment.append("Hata üreten servis süreçlerinin hafıza dökümünü (crash dump) alınız.")

        if "R002" in rule_codes:
            story_points.append(
                f"{machine_name} üzerindeki kritik Windows servisleri 3 dakikada çok sayıda restart döngüsüne (Restart Loop) girdi. "
                "Saldırgan DLL injection veya DoS saldırısı ile güvenlik izleme ajanlarını etkisiz kılmaya çalışıyor olabilir."
            )
            commands.append("Get-Service | Where-Object {$_.Status -eq 'Stopped'}")
            commands.append("Get-Process | Sort-Object CPU -Descending | Select-Object -First 10")
            containment.append("Sistemdeki bilinmeyen servis ve zamanlanmış görevleri (Scheduled Tasks) denetleyiniz.")

        if "R003" in rule_codes:
            story_points.append(
                "Bu cihazın geçmiş davranışsal taban çizgisinde (Baseline) hiç görülmemiş yeni bir log mesaj şablonu (New Template Anomaly) tetiklendi."
            )
            commands.append("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
            containment.append("Kayıt defteri (Registry Run keys) ve başlangıç klasörlerini inceleyiniz.")

        if "R004" in rule_codes:
            story_points.append(
                "Mesai saatleri dışında (Gece / Hafta sonu) beklenmedik yüksek hacimli aktivite tespit edildi."
            )
            commands.append("netstat -ano | findstr ESTABLISHED")
            containment.append("Aktif ağ bağlantılarını ve uzak oturum açma (RDP/SSH) isteklerini sonlandırınız.")

        if "R005" in rule_codes:
            story_points.append(
                "İmkânsız seyahat veya coğrafi tutarsızlık anomalisi saptandı."
            )
            commands.append("net user /active:no")
            containment.append("İlgili kullanıcı hesabını acil olarak kilitleyip parola sıfırlama uygulayınız.")

        if not story_points:
            story_points.append(
                f"{machine_name} cihazında olağandışı aktivite tespit edildi. Risk puanı {incident.risk_score}/100 olarak hesaplandı."
            )
            commands.append(f"Get-WinEvent -MaxEvents 20 -ComputerName '{machine_name}'")
            containment.append("Cihazı SOC ağ izleme havuzuna alınız.")

        executive_summary = (
            f"SecOps Sentinel AI Motoru, Incident #{incident.id} üzerinde adli inceleme gerçekleştirdi. "
            f"{machine_name} ({crit} Kritiklik Dereceli) cihazında {len(findings)} adet bağımsız güvenlik bulgusu "
            f"korele edildi. Tehdit seviyesi {incident.severity} ve genel risk puanı {incident.risk_score}/100'dür."
        )

        attack_scenario = " ".join(story_points)

        return {
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "target_machine": machine_name,
            "machine_criticality": crit,
            "confidence_score": confidence,
            "executive_summary": executive_summary,
            "attack_scenario": attack_scenario,
            "mitre_techniques": incident.mitre_techniques or [],
            "identified_sources": sources,
            "recommended_commands": commands,
            "containment_steps": containment
        }
