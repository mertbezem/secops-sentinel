# SecOps Sentinel — REST API Referans Dokümanı

Tüm API uç noktaları `/api/v1` ön eki altında sunulmaktadır.

---

## 📌 Uç Noktalar Özeti

| Metot | Uç Nokta (Endpoint) | Açıklama |
| :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | JWT Bearer Token ile kullanıcı girişi |
| `POST` | `/api/v1/ingest/csv` | Windows Olay Günlüğü CSV dosyasını yükleme |
| `GET` | `/api/v1/ingest/jobs/{id}` | İçe aktarma arka plan iş durumunu sorgulama |
| `GET` | `/api/v1/events` | Logları listeleme (sayfalı ve filtrelenebilir) |
| `GET` | `/api/v1/events/{id}` | Tek bir log kaydını ID ile getirme |
| `GET` | `/api/v1/machines` | İzlenen makineleri listeleme |
| `GET` | `/api/v1/machines/{id}` | Makine detaylarını ve kritiklik seviyesini getirme |
| `GET` | `/api/v1/machines/{id}/timeline` | Makinenin olay ve bulgu zaman çizelgesini alma |
| `POST` | `/api/v1/detection/run` | Tüm veriler üzerinde tehdit tespit motorunu çalıştırma |
| `GET` | `/api/v1/incidents` | Korele edilmiş güvenlik olaylarını listeleme |
| `GET` | `/api/v1/incidents/{id}` | Olay detayını, bulguları ve kanıt loglarını getirme |
| `PATCH` | `/api/v1/incidents/{id}` | Olay durumunu (status) ve notlarını güncelleme |
| `GET` | `/api/v1/incidents/{id}/pdf` | Olay için adli adli bilişim PDF raporu indirme |
| `GET` | `/api/v1/incidents/{id}/ai-analysis` | Olay için yapay zeka tehdit kök neden analizi üretme |
| `GET` | `/api/v1/rules` | Algılama kurallarını listeleme |
| `PATCH` | `/api/v1/rules/{code}` | Kural parametrelerini dinamik olarak güncelleme |
| `GET` | `/api/v1/stats/overview` | SOC gösterge paneli özet metrikleri |
| `GET` | `/api/v1/stats/timeseries` | Zaman serisi olay ve anomali dağılımı |
| `GET` | `/api/v1/stats/mitre-matrix` | MITRE ATT&CK taktik ve teknik ısı haritası |
| `GET` | `/api/v1/healthz` | Sistem sağlık ve hazır olma kontrolü |

---

## 📦 Standart Yanıt Zarfı (Response Envelope)

Tüm liste uç noktaları standart sayfalama zarfı döner:

```json
{
  "items": [],
  "total": 100,
  "page": 1,
  "page_size": 50
}
```

---

## ❌ Standart Hata Formatı

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "status: 'INVALID' geçersiz durum. Şunlardan biri olmalı: OPEN, INVESTIGATING, RESOLVED, CLOSED",
    "field": "status"
  }
}
```
