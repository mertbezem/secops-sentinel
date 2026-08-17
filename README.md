# SecOps Sentinel — Güvenlik Olay Günlüğü & Otonom Alarm Motoru

[![CI](https://github.com/user/secops-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/user/secops-sentinel/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)

**SecOps Sentinel**, yüksek hacimli Windows Olay Günlüklerini (Event Log) analiz etmek için geliştirilmiş kurumsal seviyede bir SIEM Tespit ve Olay Müdahale (Incident Response) platformudur. Ham log akışlarını normalize edilmiş mesaj şablonlarına indirger, makine bazlı davranışsal taban çizgileri (baseline) hesaplar, dinamik algılama kurallarıyla (R001–R005) anomalileri yakalar, tespitleri MITRE ATT&CK teknikleriyle eşleştirir ve ilişkili güvenlik olaylarını modern, koyu temalı bir SOC panelinde analistlerin incelemesine sunar.

---

## 🌟 Temel Özellikler & Başarılar

- **Yüksek Hızlı CSV İçe Aktarma (Ingestion)**: Parçalı (chunked) toplu yükleme ve SHA-256 tabanlı teilleme (deduplication) mimarisi (158.184 ham kayıttan **90.474 adet mükerrer satır** filtrelendi).
- **Mesaj Şablonlama Motoru (Template Extractor)**: Değişken parametreleri (Hex, GUID, SID, IP adresi, Dosya yolları, Zaman damgaları, Tırnak içi metinler, Sayılar) standart yer tutucularla değiştirir. **50.17 : 1 şablon indirgeme oranı** elde edilmiştir (şartnamedeki $\ge 50:1$ hedefi başarıyla aşıldı).
- **Davranışsal Taban Çizgisi (Baseline Engine)**: Her makine ve kaynak için saatlik ortalama olay sıklığı ($\mu$) ve standart sapma ($\sigma$) hesaplar.
- **Korelasyon & Algılama Motoru**:
  - `R001` (`ERROR_BURST`): Hata loglarında ani artış tespiti.
  - `R002` (`SERVICE_RESTART_LOOP`): Tekrarlayan servis durma/başlatma döngüleri.
  - `R003` (`NEW_MESSAGE_TEMPLATE`): Geçmişte hiç görülmemiş yeni mesaj şablonu anomalisi.
  - `R004` (`OFF_HOURS_ANOMALY`): Mesai saatleri dışındaki şüpheli güvenlik aktiviteleri.
  - `R005` (`GEO_INCONSISTENCY`): Coğrafi giriş tutarsızlığı (`is_demo: True`).
- **Açıklanabilir Risk Skorlaması**: `risk_score = min(100, base + Σ modifiers)` formülü ve açık puanlama gerekçeleri.
- **Modern SOC Arayüzü & Swagger**: Koyu obsidiyen temalı tek sayfalık web paneli (`demo/index.html` & `/docs`), canlı grafikler (Chart.js), olay filtreleme, adli AI analizi ve PDF rapor çıktısı.

---

## 🚀 Hızlı Başlangıç & Kurulum

### 1. Docker Compose ile Çalıştırma (Önerilen)

```bash
docker-compose up --build
```
- **SOC Web Arayüzü**: [http://localhost:8000/](http://localhost:8000/)
- **Swagger API Dokümantasyonu**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc Dokümantasyonu**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### 2. Yerel Python Ortamı ile Çalıştırma

```powershell
# Sanal ortam oluşturma ve aktifleştirme (Windows)
python -m venv backend/venv
.\backend\venv\Scripts\activate

# Bağımlılıkları yükleme
pip install -e backend/.[dev]

# API ve Arayüz Sunucusunu Başlatma
cd backend
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## 📊 Ölçülen Performans Kriterleri

| Metrik / Test | Ölçülen Değer | Hedef / Şartname | Durum |
| :--- | :--- | :--- | :--- |
| **Tam CSV İçe Aktarma (158.184 olay)** | 8.4 saniye | $< 30.0$ saniye | BAŞARILI |
| **Mesaj Şablonlama Oranı** | **50.17 : 1** | $\ge 50:1$ | BAŞARILI |
| **Mükerrer Log Temizleme (Dedup)** | 90.474 olay | Hatasız SHA-256 | BAŞARILI |
| **API Yanıt Süresi (`GET /stats/overview`)**| $< 25 \text{ ms}$ | $< 100 \text{ ms}$ | BAŞARILI |
| **Algılama Motoru Çalışma Süresi** | $1.2 \text{ saniye}$ | $< 5.0 \text{ saniye}$ | BAŞARILI |
| **Test Başarı Oranı** | 51 / 51 Test Geçti | $\%100$ | BAŞARILI |

---

## ⚠️ Bu Sistem Neyi Tespit Edemez? (Sınırlılıklar & Kapsam)

Sistemin sınırlarını şeffaf ve bilimsel bir yaklaşımla belirtmek amacıyla, **mevcut MVP motorunun doğrudan tespit edemeyeceği tehdit vektörleri** aşağıda listelenmiştir:

1. **Çekirdek Düzeyi & Rootkit Aktiviteleri (DKOM)**: SecOps Sentinel, kullanıcı alanındaki (user-space) Windows Olay Günlüklerine dayanır. Sürücü düzeyinde bellek manipülasyonu yapan veya Windows Log mekanizmasını baypas eden gelişmiş rootkit'ler tespit edilemez.
2. **Şifreli Ağ Paket İçeriği Saldırıları**: Log kayıtları metin ve metaverileri inceler; TLS üzerinden akan şifreli ağ trafiği için derin paket incelemesi (DPI) veya C2 oturum çözümü yapılmaz.
3. **Bellek İçi Dosyasız Zararlılar (Fileless Malware / Process Injection)**: Windows Olay Günlüğü üretmeden yalnızca RAM üzerinde çalışan Reflective DLL veya Process Hollowing saldırıları log üretmediği takdirde tetiklenmez.
4. **Normal Log İmzasına Sahip Sıfır Gün (Zero-Day) Açıkları**: Mesai saatleri içinde geçerli kullanıcı kimlikleriyle yapılan ve sistemde standart loglar oluşturan meşru görünümlü yetki yükseltmeler istatistiksel eşikleri aşmayabilir.
5. **Makineler Arası Yanal İlerleme Zincirleri (Cross-Machine Lateral Movement)**: Mevcut korelasyon motoru bulguları aynı makine üzerinde gruplar. Çok makineli saldırı yolları (örneğin 10 Domain Controller arasında Pass-the-Hash zincirleri) Faz 3 grafik korelasyon kapsamındadır.
