# SecOps Sentinel — Sistem Mimarisi & Tasarım Kararları

## 1. Katmanlı Mimari & Sorumlulukların Ayrımı

SecOps Sentinel, katı bir mimari katman ayrımı uygular (NFR-11):

```
+-------------------------------------------------------------+
|                 FastAPI Yönlendirme & Doğrulama             |
|                    backend/app/api/v1/                       |
|   (HTTP Doğrulama, Pydantic Şemaları, SQL / İş Mantığı YOK) |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                     İş Mantığı Katmanı                      |
|                    backend/app/services/                    |
|  (Sorgu Çalıştırma, İçe Aktarma, Baseline, Kural Yönetimi)  |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                 SQLAlchemy 2.0 ORM Modelleri                |
|                    backend/app/models/                      |
|      (Machine, Event, MessageTemplate, Rule, Finding)       |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|              Veritabanı Motoru (PostgreSQL / SQLite)        |
+-------------------------------------------------------------+
```

---

## 2. İçe Aktarma & Normalizasyon Stratejisi

1. **Parçalı Akış (Chunked Streaming)**: Büyük CSV dosyalarını yapılandırılabilir partiler halinde (varsayılan 5.000 satır) yükleyerek bellek kullanımını $< 150 \text{MB}$ seviyesinde tutar.
2. **Teilleme Motoru (Deduplication)**: Her satır için `SHA256(machine | source | entry_type | ts_utc | message)` hash'i hesaplar. Mükerrer loglar elenerek mükerrer bulgu üretilmesi engellenir.
3. **Mesaj Şablonlama (Template Extraction)**: Değişken parametreleri (Hex, GUID, SID, IP adresi, Dosya yolu, Zaman damgası, Tırnak içi metin, Sayılar) standart yer tutucularla (`<HEX>`, `<GUID>`, `<IP>`, `<PATH>`, `<TIMESTAMP>` vb.) değiştirir. **50.17:1 sıkıştırma oranı** sağlar.
4. **Varlık Çıkarımı (Entity Extraction)**: Düzenli ifadeler (Regex) ile mesaj içindeki IP adreslerini, SID'leri, hata kodlarını ve dosya yollarını JSONB alanında yapılandırır.

---

## 3. Davranışsal Taban Çizgisi & İstatistiksel Hesaplama

Her makine için saatlik log frekansı ortalaması ($\mu$) ve standart sapması ($\sigma$) hesaplanır:

$$\mu = \frac{\text{Toplam Olay Sayısı}}{\text{Saat Cinsinden Zaman Aralığı}}$$

$$\sigma = \sqrt{\mu}$$

Taban çizgisi metrikleri `baselines` tablosunda saklanır ve algılama kuralları tarafından dinamik olarak sorgulanır.

---

## 4. React Entegrasyonuna Hazırlık & API-First İlkeleri

1. **Yalnızca JSON**: Arka uç sunucu taraflı HTML render etmez (Jinja2 yoktur), tek çıktı standart JSON'dur.
2. **Evrensel Sayfalama Zarfı**: Tüm liste uç noktaları `{"items": [...], "total": N, "page": N, "page_size": N}` yapısını döndürür.
3. **ISO 8601 UTC Zaman Damgaları**: Tüm tarihler `Z` sonekiyle ISO 8601 biçiminde döner (`2020-11-14T08:41:59Z`).
4. **Büyük Harf Enum Standartları**: Tüm önem dereceleri (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) ve durumlar (`OPEN`, `INVESTIGATING`, `RESOLVED`, `CLOSED`) standart büyük harfli dizelerdir.
5. **Standart Hata Şeması**: `{"error": {"code": "...", "message": "...", "field": "..."}}`.
