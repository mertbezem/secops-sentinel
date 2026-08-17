# SecOps Sentinel — Tehdit Algılama Kuralları Spesifikasyonu

Bu doküman, **R001–R005** kurallarının çalışma mantığını, eşik parametrelerini, MITRE ATT&CK teknik eşleştirmelerini ve bilinen yanlış pozitif (false positive) senaryolarını detaylandırır.

---

## R001: `ERROR_BURST` (Hata Logu Patlaması)

- **Açıklama**: Kısa bir kayan zaman penceresi içinde bir makinede gerçekleşen `Error` veya `FailureAudit` olaylarındaki ani artışları tespit eder.
- **Çalışma Mantığı**: $T$ dakika içinde $\ge N$ adet hata olayı gerçekleşip gerçekleşmediğini denetler.
- **Varsayılan Parametreler**:
  - `threshold_count`: 5
  - `time_window_minutes`: 10
- **MITRE ATT&CK Eşleştirmesi**: `T1078` (Valid Accounts), `T1489` (Service Stop)
- **Bilinen Yanlış Pozitif (False Positive) Senaryoları**:
  - Planlı sistem bakımı veya Windows Güncellemeleri yüklenirken geçici olarak çok sayıda hata üretilmesi.
  - Hatalı yapılandırılmış bir uygulamanın başlangıçta ardışık log basması.

---

## R002: `SERVICE_RESTART_LOOP` (Tekrarlayan Servis Başlatma Döngüsü)

- **Açıklama**: Bir makinede kısa bir zaman aralığında bir servisin tekrar tekrar durdurulduğunu, başlatıldığını veya yeniden başlatma planlandığını tespit eder.
- **Çalışma Mantığı**: `Service Control Manager`, `Software Protection Platform Service` kaynaklı olayları veya yeniden başlatma anahtar kelimelerini filtreler. $T$ dakika içinde $\ge N$ olay olduğunda tetiklenir.
- **Varsayılan Parametreler**:
  - `threshold_count`: 3
  - `time_window_minutes`: 15
- **MITRE ATT&CK Eşleştirmesi**: `T1489` (Service Stop / Denial of Service)
- **Bilinen Yanlış Pozitif (False Positive) Senaryoları**:
  - Windows Software Protection Service'in yasal lisans kontrolü sırasında periyodik olarak yeniden başlatma planlaması.
  - Bir yazılımcının yerel bir Windows servisini test ederken elle art arda yeniden başlatması.

---

## R003: `NEW_MESSAGE_TEMPLATE` (Anomali Mesaj Şablonu)

- **Açıklama**: Bir makinenin geçmiş taban çizgisinde (baseline) daha önce hiç kaydedilmemiş veya nadir görülen yeni log şablonlarını belirler.
- **Çalışma Mantığı**: Normalize edilmiş şablon frekansı $\le 5$ olan olaylarda tetiklenir.
- **Varsayılan Parametreler**:
  - `min_confidence`: 0.70
- **MITRE ATT&CK Eşleştirmesi**: `T1068` (Exploitation for Privilege Escalation)
- **Bilinen Yanlış Pozitif (False Positive) Senaryoları**:
  - Yeni bir yazılımın sisteme ilk defa kurulması veya yeni bir işletim sistemi güncellemesinin yeni standart loglar üretmesi.

---

## R004: `OFF_HOURS_ANOMALY` (Mesai Dışı Aktivite Anomalisi)

- **Açıklama**: Normal çalışma saatleri (08:00–18:00 UTC, Pazartesi-Cuma) dışında üretilen `Error` veya `Warning` seviyesindeki olayları tespit eder.
- **Çalışma Mantığı**: `is_business_hours == False` durumunu değerlendirir.
- **Varsayılan Parametreler**:
  - `start_hour`: 8
  - `end_hour`: 18
  - `weekend_off`: True
- **MITRE ATT&CK Eşleştirmesi**: `T1078` (Valid Accounts / Off-Hours Activity)
- **Bilinen Yanlış Pozitif (False Positive) Senaryoları**:
  - Gece saatlerinde çalışan otomatik yedekleme (backup), toplu veri işleme veya periyodik bakım betikleri.

---

## R005: `GEO_INCONSISTENCY` (Coğrafi Konum Tutarsızlığı — DEMO)

- **Açıklama**: `is_demo: True` bayrağı ile işaretlenmiştir. Tek bir makine için farklı şehir ve ülkelerden gelen eşzamanlı girişleri simüle ve tespit eder.
- **Çalışma Mantığı**: Belirlenen zaman penceresinde aynı makineye ait farklı coğrafi metaveriler bulunduğunda tetiklenir.
- **Varsayılan Parametreler**:
  - `time_window_hours`: 1
- **MITRE ATT&CK Eşleştirmesi**: `T1078.004` (Unusual Geographic Location)
- **Bilinen Yanlış Pozitif (False Positive) Senaryoları**:
  - Çok bölgeli VPN düğümlerine bağlanan veya dinamik IP rotasyonu kullanan meşru kullanıcılar.
