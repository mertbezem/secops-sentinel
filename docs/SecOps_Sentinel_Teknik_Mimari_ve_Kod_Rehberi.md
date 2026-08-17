# 🛡️ SecOps Sentinel — Kapsamlı Teknik Mimari ve Kod Rehberi

Bu doküman, **SecOps Sentinel** projesinin tüm mimari kararlarını, hangi modülün neden yazıldığını, kod parçalarının ne işe yaradığını ve katmanlar arasındaki veri akışını detaylı bir şekilde açıklamaktadır.

---

## 📋 İÇİNDEKİLER

1. [Proje Özeti ve Amacı](#1-proje-özeti-ve-amacı)
2. [Sistem Mimarisi ve Veri Akış Şeması](#2-sistem-mimarisi-ve-veri-akış-şeması)
3. [Dizin Yapısı ve Klasör Haritası](#3-dizin-yapısı-ve-klasör-haritası)
4. [Parça Parça Kod ve Modül Açıklamaları](#4-parça-parça-kod-ve-modül-açıklamaları)
   - [4.1. Core Katmanı (Yapılandırma & Hata Yönetimi)](#41-core-katmanı-yapılandırma--hata-yönetimi)
   - [4.2. Database & Veri Modelleri (DB & ORM)](#42-database--veri-modelleri-db--orm)
   - [4.3. Schemas (Pydantic v2 Sözleşmeleri)](#43-schemas-pydantic-v2-sözleşmeleri)
   - [4.4. Ingestion Hatı (CSV Yükleme, Teilleme ve Şablonlama)](#44-ingestion-hattı-csv-yükleme-teilleme-ve-şablonlama)
   - [4.5. Baseline Motoru (Davranış Temeli)](#45-baseline-motoru-davranış-temeli)
   - [4.6. Detection & Correlation Motoru (Kurallar, Skorlama ve Korelasyon)](#46-detection--correlation-motoru-kurallar-skorlama-ve-korelasyon)
   - [4.7. Services Katmanı (İş Mantığı Ayrımı - NFR-11)](#47-services-katmanı-iş-mantığı-ayrımı---nfr-11)
   - [4.8. API Routers Katmanı (Sadece Routing ve Validation)](#48-api-routers-katmanı-sadece-routing-ve-validation)
   - [4.9. Frontend (Demo Dashboard)](#49-frontend-demo-dashboard)
5. [Hangi Kodu Niye Yazdık? (Kritik Mimari Kararlar)](#5-hangi-kodu-niye-yazdık-kritik-mimari-kararlar)

---

## 1. PROJE ÖZETİ VE AMACI

**SecOps Sentinel**, yüksek hacimli **Windows Event Log** kayıtlarını işleyen, temizleyen, anomali tespiti yapan, açıklanabilir risk skorlaması uygulayan ve bulguları ilintilendirerek güvenlik analistlerine önceliklendirilmiş alarm üreten kurumsal bir **SIEM (Security Information and Event Management) Tespit ve Korelasyon Motorudur**.

### Temel Özellikler
- **Yüksek Hacimli Batch Ingestion**: Pandas/CSV Chunking ile 158.000+ satırlı log verilerini bellek şişmesi yaşanmadan saniyeler içinde işler.
- **SHA-256 Deduplication**: Tekrar eden logları veritabanına girmeden eler (%57+ sıkıştırma).
- **Mesaj Şablonlama**: Değişken parametreleri (IP, GUID, Hex, Dosya Yolu, Sayı) yer tutucularla maskeler ($\ge 50:1$ indirgeme oranı).
- **İstatistiksel Baseline**: Her makine ve kaynak için saatlik ortalama ($\mu$) ve standart sapma ($\sigma$) hesaplar.
- **Dinamik Kural Motoru (R001–R005)**: Eşik değerlerini veritabanı JSONB alanından okuyan 5 aktif kural.
- **Açıklanabilir Risk Skorlaması**: Puanlama gerekçelerini (`reasons`) şeffaf olarak sunan risk motoru.
- **Görsel SOC Panosu**: Sadece tek bir Vanilla JS dosyası (`demo/index.html`) ile canlı izleme ve incident yönetimi.

---

## 2. SİSTEM MİMARİSİ VE VERİ AKIŞ ŞEMASI

```
[Ham Windows Log CSV]
        │
        ▼
[Ingestion Hatı] ──► SHA-256 Dedup Check ──► Machine/Template Creation ──► Bulk SQL Insert
        │
        ▼
[Baseline Engine] ──► Saatlik Olay Dağılımı (mean μ, stddev σ)
        │
        ▼
[Detection Engine] ──► R001 (Error Burst), R002 (Service Loop), R003 (New Template)
                    ──► R004 (Off-Hours), R005 (Geo Inconsistency)
        │
        ▼
[Scoring & Correlation] ──► Explaining Risk Score ──► Incident Correlation (Window = 30m)
        │
        ▼
[REST API (FastAPI)] ──► Service Isolation (NFR-11) ──► Pydantic v2 Envelopes
        │
        ▼
[SOC Dashboard (demo/index.html)]
```

---

## 3. DİZİN YAPISI VE KLASÖR HARİTASI

```
secops-sentinel/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # SADECE HTTP routing & validation (SQL YOK)
│   │   │   ├── events.py, incidents.py, machines.py, rules.py, ingest.py, stats.py, health.py
│   │   ├── core/            # Config, logging, error handling, CORS
│   │   │   ├── config.py, logging.py, exceptions.py
│   │   ├── db/              # Session, Base, Engine
│   │   │   └── session.py
│   │   ├── models/          # SQLAlchemy 2.0 ORM modelleri
│   │   │   └── models.py
│   │   ├── schemas/         # Pydantic v2 sözleşmeleri (Strict typing)
│   │   │   ├── common.py, event.py, finding.py, incident.py, machine.py, rule.py, stats.py
│   │   ├── ingestion/       # CSV loader, dedup, template & entity extraction
│   │   │   ├── csv_loader.py, template_extractor.py, entity_extractor.py, normalizer.py
│   │   ├── baseline/        # Davranış temeli istatistik motoru
│   │   │   └── calculator.py
│   │   ├── detection/       # Kural motoru, R001-R005, scoring, correlation
│   │   │   ├── rules/ (r001..r005, base.py, registry.py)
│   │   │   ├── engine.py, scoring.py, correlator.py
│   │   └── services/        # İş mantığı (Business logic) katmanı
│   │       ├── event_service.py, incident_service.py, ingest_service.py, machine_service.py...
│   └── tests/               # Pytest birim ve entegrasyon testleri
├── docs/                    # Mimari, kural ve veri profilleme dokümanları
├── demo/                    # Single-file HTML/JS SOC Dashboard
│   └── index.html
├── docker-compose.yml       # Docker Compose (PostgreSQL 16 + FastAPI)
└── README.md                # Kurulum ve performans metrikleri
```

---

## 4. PARÇA PARÇA KOD VE MODÜL AÇIKLAMALARI

### 4.1. Core Katmanı (Yapılandırma & Hata Yönetimi)

#### `backend/app/core/config.py`
- **Ne İşe Yarar?**: Uygulamanın tüm konfigürasyon parametrelerini (Veritabanı URL'si, CORS izinleri, Ingestion batch boyutu, log seviyesi) tek bir merkezde toplar.
- **Niye Yazdık?**: Sabit değerleri (hardcoded strings) kodun içerisine saçmamak ve ortam değişkenlerini (`.env`) Pydantic `BaseSettings` ile tip güvenli bir şekilde yönetmek için. `AliasChoices` sayesinde `CORS_ORIGINS` veya `ALLOWED_ORIGINS` gibi farklı env isimlerini otomatik eşleştirir.

#### `backend/app/core/exceptions.py`
- **Ne İşe Yarar?**: Özel istisna sınıflarını (`NotFoundException`, `ValidationException`, `DuplicateException`) ve bunlara karşılık gelen varsayılan HTTP durum kodlarını tanımlar.
- **Niye Yazdık?**: Servis katmanından fırlatılan iş mantığı hatalarının, istemciye (Frontend/API tüketicisi) standart bir `{"error": {"code": "...", "message": "...", "field": "..."}}` yapısıyla dönmesini sağlamak için.

#### `backend/app/core/logging.py`
- **Ne İşe Yarar?**: Uygulama genelinde renkli ve zaman damgalı standart konsol/dosya loglayıcısını yapılandırır.
- **Niye Yazdık?**: `print()` kullanımı yerine log seviyelerine (`INFO`, `WARNING`, `ERROR`) göre izlenebilirlik sağlamak için.

---

### 4.2. Database & Veri Modelleri (DB & ORM)

#### `backend/app/db/session.py`
- **Ne İşe Yarar?**: SQLAlchemy veritabanı bağlantı motorunu (`engine`) ve oturum fabrikasını (`SessionLocal`) kurar. FastAPI bağımlılık enjeksiyonu için `get_db()` üretecini (generator) sunar.
- **Niye Yazdık?**: Her HTTP isteğinde güvenli bir veritabanı oturumu açıp, işlem bitince otomatik olarak kapatmak (connection leak'i önlemek) için.

#### `backend/app/models/models.py`
- **Ne İşe Yarar?**: Veritabanı tablolarını (`Machine`, `MessageTemplate`, `Event`, `Rule`, `Finding`, `Incident`, `Baseline`) SQLAlchemy 2.0 Declarative Mapped API ile nesnel olarak tanımlar.
- **Niye Yazdık?**:
  - `BIGINT_PK = Integer().with_variant(BigInteger, "postgresql")`: Hem SQLite (Pytest/Lokal) autoincrement mekanizmasıyla hem de PostgreSQL (Production) türleriyle sorunsuz çapraz uyumlu çalışmasını sağlamak için.
  - `JSON_TYPE` & `ARRAY_STRING`: Postgres'te `JSONB` ve `TEXT[]` kullanırken, SQLite'ta otomatik `JSON` fallback'i sağlamak için.
  - Zorunlu indeksler (`ix_events_machine_ts`, `ix_incidents_status_severity_first_seen` vb.): Sorgu performansını milisaniye seviyesinde tutmak için.

---

### 4.3. Schemas (Pydantic v2 Sözleşmeleri)

#### `backend/app/schemas/common.py`
- **Ne İşe Yarar?**: Ortak API zarflarını (`PageEnvelope[T]`, `StandardErrorEnvelope`) tanımlar.
- **Niye Yazdık?**: Frontend geliştiricisinin tüm liste yanıtlarında aynı veri yapısıyla (`items`, `total`, `page`, `page_size`) karşılaşmasını sağlamak için.

#### `backend/app/schemas/event.py`, `finding.py`, `incident.py`, `machine.py`, `rule.py`, `stats.py`
- **Ne İşe Yarar?**: API'ye gelen istek body'lerinin doğrulanmasını (Validation) ve API'den çıkan yanıtların serileştirilmesini sağlar.
- **Niye Yazdık?**: `model_config = ConfigDict(from_attributes=True)` sayesinde ORM nesnelerini doğrudan güvenli JSON yanıtlarına dönüştürmek ve tip güvenliğini garanti etmek için.

---

### 4.4. Ingestion Hattı (CSV Yükleme, Teilleme ve Şablonlama)

#### `backend/app/ingestion/template_extractor.py`
- **Ne İşe Yarar?**: Serbest metin halindeki log mesajlarını deterministik olarak şablonlara dönüştürür (`extract_template`).
- **Niye Yazdık?**: Metin icindeki değişken verileri (`<IP>`, `<GUID>`, `<HEX>`, `<PATH>`, `<UNC_PATH>`, `<TIMESTAMP>`, `<NUM>`) maskeleyerek 158.000+ ham mesajı 3.153 şablona düşürmek (**50.17 : 1 indirgeme oranı**) ve anomali tespitini kolaylaştırmak için.

#### `backend/app/ingestion/entity_extractor.py`
- **Ne İşe Yarar?**: Log mesajı içerisinden IP adreslerini, hesap adlarını, servis isimlerini ve dosya yollarını regex ile çıkarır (`extract_entities`).
- **Niye Yarar?**: Olay analizi sırasında analiste yapılı kanıt verisi sunabilmek için.

#### `backend/app/ingestion/normalizer.py`
- **Ne İşe Yarar?**: Zaman damgasını UTC ISO-8601 formatına dönüştürür, `is_business_hours` (mesai saati) bilgisini hesaplar ve SHA-256 `dedup_hash` üretir.
- **Niye Yazdık?**: `SHA256(MachineName | Source | EntryType | TimeGenerated | Message)` kombinasyonu ile mükerrer logların veritabanına eklenmesini önlemek için.

#### `backend/app/ingestion/csv_loader.py`
- **Ne İşe Yarar?**: CSV dosyasını `chunk_size=5000` parçalarıyla okur, teilleme kontrolünü yapar, şablon ve makine kayıtlarını önbelleğe alıp toplu SQL eklemesi (`bulk_insert_mappings`) gerçekleştirir.
- **Niye Yazdık?**: 158.000 satırlık veriyi RAM'i doldurmadan saniyeler içinde veritabanına kaydetmek için.

---

### 4.5. Baseline Motoru (Davranış Temeli)

#### `backend/app/baseline/calculator.py`
- **Ne İşe Yarar?**: Her makine ve log kaynağı için saatlik olay sayısının ortalamasını ($\mu$) ve standart sapmasını ($\sigma$) hesaplayarak `baselines` tablosuna yazar.
- **Niye Yazdık?**: Statik eşikler yerine makinelerin kendi geçmiş davranışlarına göre anomali tespiti yapabilmek (R001 Error Burst kuralında kullanılmak) için.

---

### 4.6. Detection & Correlation Motoru (Kurallar, Skorlama ve Korelasyon)

#### `backend/app/detection/rules/base.py` & `registry.py`
- **Ne İşe Yarar?**: Tüm kuralların türetildiği soyut taban sınıfı (`BaseRule`) ve kuralları dinamik kaydeden/çağıran yapıyı (`RuleRegistry`) sunar.
- **Niye Yazdık?**: Yeni bir tespit kuralı eklenirken mevcut koda dokunmadan modüler genişletilebilirlik sağlamak için.

#### `backend/app/detection/rules/r001_error_burst.py` (R001: Error Burst)
- **Ne İşe Yarar?**: Son $N$ dakikada bir makinede gerçekleşen hata logu sayısını baseline ortalamasıyla karşılaştırır.
- **Niye Yazdık?**: Uygulama çöküş patlamalarını ve ani hata artışlarını tespit etmek için.

#### `backend/app/detection/rules/r002_service_restart_loop.py` (R002: Service Restart Loop)
- **Ne İşe Yarar?**: Bir servisin kısa süre içinde birden fazla kez durup yeniden başladığını tespit eder.
- **Niye Yazdık?**: Döngüsel servis kilitlenmelerini ve çöküşlerini yakalamak için.

#### `backend/app/detection/rules/r003_new_template.py` (R003: New Template)
- **Ne İşe Yarar?**: Sistemde daha önce hiç görülmemiş yeni bir mesaj şablonu belirdiğinde tetiklenir.
- **Niye Yazdık?**: Sistemde ilk kez oluşan anormallikleri ve bilinmeyen olayları ortaya çıkarmak için.

#### `backend/app/detection/rules/r004_off_hours.py` (R004: Off-Hours Anomaly)
- **Ne İşe Yarar?**: Mesai saatleri dışında (`08:00 - 18:00` dışı) gerçekleşen kritik logları tespit eder.
- **Niye Yazdık?**: Gece veya hafta sonu yapılan şüpheli aktiviteleri belirlemek için.

#### `backend/app/detection/rules/r005_geo_inconsistency.py` (R005: Geo Inconsistency - Demo)
- **Ne İşe Yarar?**: Aynı makineden farklı coğrafi konumlara ait oturum açma kayıtlarını tespit eder (`is_demo: True`).
- **Niye Yazdık?**: Coğrafi oturum anomalisi senaryosunu demo ortamında simüle etmek için.

#### `backend/app/detection/scoring.py`
- **Ne İşe Yarar?**: `calculate_risk_score()` fonksiyonu ile bulgulara $0 - 100$ arasında açıklanabilir risk skoru verir ve seviyeye eşler (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Niye Yazdık?**: Hangi puanın nereden geldiğini (`entry_type_error: +20`, `outside_business_hours: +10` vb.) şeffaf olarak raporlamak için.

#### `backend/app/detection/correlator.py`
- **Ne İşe Yarar?**: Makine bazında 30 dakikalık zaman penceresinde oluşan ham bulguları gruplayarak tek bir `Incident` (Güvenlik Olayı) haline getirir.
- **Niye Yazdık?**: Analisti 4000 ayrı alarmla boğmak yerine gruplanmış 23 anlamlı incident sunarak alarm yorgunluğunu (Alert Fatigue) önlemek için.

#### `backend/app/detection/engine.py`
- **Ne İşe Yarar?**: Ingestion sonrası baseline hesaplamasını, tüm kuralların çalıştırılmasını ve incident korelasyonunu sırayla çalıştıran orkestratördür.

---

### 4.7. Services Katmanı (İş Mantığı Ayrımı - NFR-11)

- **`event_service.py`**, **`incident_service.py`**, **`ingest_service.py`**, **`machine_service.py`**, **`rule_service.py`**, **`stats_service.py`**
- **Ne İşe Yarar?**: Veritabanı sorgularını, filtreleme mantığını ve sayfalama işlemlerini yürütür.
- **Niye Yazdık?**: **NFR-11 Katman İzolasyonu prensibi** gereği API router'ları içerisine tek bir çizgi veritabanı kodu veya iş mantığı koymamak için.

---

### 4.8. API Routers Katmanı (Sadece Routing ve Validation)

- **`backend/app/api/v1/*.py`** (`events.py`, `incidents.py`, `ingest.py`, `machines.py`, `rules.py`, `stats.py`, `detection_router.py`, `health.py`)
- **Ne İşe Yarar?**: Gelen HTTP isteklerini karşılar, Pydantic ile parametreleri doğrular, ilgili `service` fonksiyonunu çağırır ve yanıtı döner.
- **Niye Yazdık?**: API katmanını hafif tutmak, test edilebilirliği artırmak ve ileride farklı bir arayüz/framework eklendiğinde servis katmanını değiştirmeden kullanabilmek için.

---

### 4.9. Frontend (Demo Dashboard)

#### `demo/index.html`
- **Ne İşe Yarar?**: Sadece HTML, Vanilla JS ve CSS değişkenleri (`:root`) ile yazılmış tek dosyalık dark-mode SOC analist panelidir.
- **Niye Yazdık?**: Herhangi bir npm build adımı veya React bağımlılığı olmadan, `/api/v1/stats/overview` ve `/api/v1/incidents` REST API'lerini canlı olarak görselleştirmek ve status güncellemelerini test etmek için.

---

## 5. HANGİ KODU NİYE YAZDIK? (KRİTİK MİMARİ KARARLAR)

| Karar / Kod Parçası | Neden Bu Şekilde Yazdık? (Teknik Gerekçe) |
| :--- | :--- |
| **Pydantic Settings & `.env`** | Veritabanı şifresi veya gizli bilgilerin git geçmişine sızmasını önlemek (NFR-14). |
| **SQLAlchemy 2.0 `select()` & Mapped** | Legacy 1.x `query()` formatı yerine tip güvenliği tam olan yeni 2.0 standartlarını uygulamak. |
| **`BIGINT_PK` Variant Yapısı** | SQLite'ın 64-bit rowid autoincrement yapısı ile PostgreSQL'in `BIGINT/BIGSERIAL` yapısını sorunsuz tek modelde birleştirmek. |
| **`dedup_hash` (SHA-256)** | Veritabanına gereksiz mükerrer kayıt girmesini engelleyerek disk alanını ve sorgu süresini %57 korumak. |
| **Regex `TemplateExtractor`** | Log mesajlarındaki değişken verileri temizleyerek log hacmini 50:1 oranında küçültmek. |
| **Zaman Damgalarında UTC Zorunluluğu** | Farklı coğrafyalardaki makinelerin olaylarını sliding window içinde zaman kayması olmadan doğru ilintilendirmek. |
| **Router - Service Ayrımı (NFR-11)** | HTTP katmanı ile iş mantığını tamamen ayırıp birim testlerini veritabanından bağımsız koşturabilmek. |
| **Single-File Vanilla JS Dashboard** | Karmaşık frontend build bağımlılıkları olmadan MVP API sözleşmesini hızlıca kanıtlamak. |
