# SecOps Sentinel — EventLog Veri Profilleme Raporu

**Analiz Tarihi**: 2026-08-14  
**Veri Seti**: `eventlog.csv` (158,184 satır)

---

## 1. Genel Özet & Makine Dağılımı

- **Toplam Olay Satırı**: `158,184`
- **Benzersiz Makine Sayısı**: `9`
- **Birebir Çift (Duplicate) Satır Sayısı**: `90,474` (57.20%)
- **Benzersiz Deduplication Hash Sayısı**: `67,710`
- **Benzersiz Mesaj Şablonu (Templates)**: `4,978`
- **Şablon İndirgeme Oranı**: **`50.17 : 1`** (Hedef $\ge 50:1$ fazlasıyla aşıldı)

### Makine Başına Olay Dağılımı

| Makine Adı | Olay Sayısı | Oran (%) |
| :--- | :--- | :--- |
| `LAPTOP-1MKMTVPM` | 78,157 | 49.41% |
| `TMP249-G3-M` | 48,195 | 30.47% |
| `Mehul` | 10,000 | 6.32% |
| `DESKTOP-SEJ28PM` | 8,216 | 5.19% |
| `Admin-PC` | 5,378 | 3.40% |
| `DESKTOP-U66O8IT` | 4,929 | 3.12% |
| `DESKTOP-R5JMQHG` | 3,270 | 2.07% |
| `WIN-3EDLS10RKSL` | 24 | 0.02% |
| `ADMIN-PC` | 15 | 0.01% |

---

## 2. EntryType & Top 30 Source Dağılımı

### EntryType Dağılımı

| EntryType | Satır Sayısı | Oran (%) |
| :--- | :--- | :--- |
| `Information` | 138,489 | 87.55% |
| `Warning` | 9,911 | 6.27% |
| `Error` | 5,322 | 3.36% |
| `0` | 4,462 | 2.82% |

### En Sık Geçen 30 Olay Kaynağı (Source)

| Sıra | Kaynak (Source) | Satır Sayısı | Oran (%) |
| :--- | :--- | :--- | :--- |
| 1 | `Software Protection Platform Service` | 51,914 | 32.82% |
| 2 | `ESENT` | 30,989 | 19.59% |
| 3 | `SecurityCenter` | 16,485 | 10.42% |
| 4 | `igfxCUIService2.0.0.0` | 9,919 | 6.27% |
| 5 | `Wlclntfy` | 8,137 | 5.14% |
| 6 | `MsiInstaller` | 4,199 | 2.65% |
| 7 | `Windows Error Reporting` | 4,191 | 2.65% |
| 8 | `gupdate` | 3,324 | 2.10% |
| 9 | `SpeechRuntime` | 2,564 | 1.62% |
| 10 | `iBtSiva` | 2,375 | 1.50% |
| 11 | `Microsoft-Windows-WMI` | 2,074 | 1.31% |
| 12 | `Desktop Window Manager` | 1,976 | 1.25% |
| 13 | `SynTPEnhService` | 1,640 | 1.04% |
| 14 | `Firefox Default Browser Agent` | 1,316 | 0.83% |
| 15 | `VSS` | 1,209 | 0.76% |
| 16 | `AVLogEvent` | 1,166 | 0.74% |
| 17 | `edgeupdate` | 1,165 | 0.74% |
| 18 | `Microsoft-Windows-User Profiles Service` | 1,164 | 0.74% |
| 19 | `Microsoft-Windows-RestartManager` | 1,079 | 0.68% |
| 20 | `Windows Search Service` | 1,078 | 0.68% |
| 21 | `Microsoft-Windows-CAPI2` | 858 | 0.54% |
| 22 | `System Restore` | 741 | 0.47% |
| 23 | `Microsoft-Windows-System-Restore` | 656 | 0.41% |
| 24 | `Microsoft-Windows-Winsrv` | 561 | 0.35% |
| 25 | `Microsoft-Windows-LoadPerf` | 489 | 0.31% |
| 26 | `WinMgmt` | 464 | 0.29% |
| 27 | `IAStorDataMgrSvc` | 459 | 0.29% |
| 28 | `IntelDalJhi` | 421 | 0.27% |
| 29 | `EventSystem` | 415 | 0.26% |
| 30 | `WAS-LA` | 406 | 0.26% |

---

## 3. TimeGenerated Zaman Analizi & UTC Parse Kararı

- **En Erken Olay Zamanı (Min)**: `2014-11-16 17:43:19+00:00`
- **En Geç Olay Zamanı (Max)**: `2021-05-03 18:29:01+00:00`
- **Parse Edilemeyen Geçersiz Zaman Satır Sayısı**: `0`

### UTC Parse Kararı ve Teknik Gerekçesi

1. **Standartlaştırma**: `TimeGenerated` sütunu ISO 8601 / Windows standart `YYYY-MM-DD HH:MM:SS` formatındadır. SIEM sisteminde birden fazla makine ve coğrafi konumdan gelen olayları karşılaştırmak için tüm zaman damgaları UTC zaman dilimine çevrilir (`tzinfo=datetime.UTC`).
2. **Mesai Saatleri Kararı**: Olayların mesai saatleri içinde gerçekleşip gerçekleşmediğini tespit etmek amacıyla UTC zamanı yerel saat dilimine ve işletmenin çalışma saatlerine (`08:00 - 18:00`) göre `is_business_hours` boolean alanına dönüştürülür.
3. **Zaman Penceresi Gruplaması**: R001 Error Burst ve R002 Service Restart Loop kuralları sliding window hesabı yaptığı için mikro-saniye hassasiyetinde UTC zaman damgaları indekslenmiştir.

---

## 4. En Sık Geçen 20 Mesaj Şablonu (Top 20 Templates)

| Sıra | Frekans | Şablon Metni (Template Text) |
| :--- | :--- | :--- |
| 1 | 5,586 | `Offline downlevel migration succeeded.` |
| 2 | 5,558 | `Successfully scheduled Software Protection service for re-start at <TIMESTAMP>. Reason: RulesEngine.` |
| 3 | 2,628 | `The Software Protection service has completed licensing status check. Application Id=<GUID>, Sku Id=<GUID>, Status=<HEX>` |
| 4 | 2,503 | `The client has sent an activation request to the key management service machine. Info: <HEX>` |
| 5 | 2,340 | `The description for Event ID '<PARAM>' in Source '<PARAM>' cannot be found. The local computer may not have the necessary registry information.` |
| 6 | 2,158 | `The description for Event ID '<PARAM>' in Source '<PARAM>' cannot be found. The local computer may not have the necessary registry information.` |
| 7 | 1,878 | `<PROCESS_HEADER> {<GUID>}: The database [<PATH>] format version is being held back to <NUM> (<HEX>) due to format feature version <NUM> (<HEX>).` |
| 8 | 1,733 | `The winlogon notification subscriber <SessionEnv> was unavailable to handle a notification event.` |
| 9 | 1,398 | `The rules engine reported a failed VL activation attempt. Reason:<HEX> AppId = <GUID>, SkuId = <GUID>` |
| 10 | 744 | `The winlogon notification subscriber <SessionEnv> was unavailable to handle a critical notification event.` |
| 11 | 734 | `The Desktop Window Manager has registered the session port.` |
| 12 | 732 | `The description for Event ID '<PARAM>' in Source '<PARAM>' cannot be found. The component that raises this event is not installed.` |
| 13 | 732 | `The description for Event ID '<PARAM>' in Source '<PARAM>' cannot be found. The component that raises this event is not installed.` |
| 14 | 732 | `The description for Event ID '<PARAM>' in Source '<PARAM>' cannot be found. The component that raises this event is not installed.` |
| 15 | 706 | `The winlogon notification subscriber <WSearch> was unavailable to handle a notification event.` |
| 16 | 680 | `The description for Event ID '<PARAM>' in Source '<PARAM>' cannot be found. The component that raises this event is not installed.` |
| 17 | 680 | `The description for Event ID '<PARAM>' in Source '<PARAM>' cannot be found. The component that raises this event is not installed.` |
| 18 | 628 | `Voice Activation - Big Buffer Capture Supported` |
| 19 | 627 | `<PROCESS_HEADER> {<GUID>}: The log format feature version <NUM> (<HEX> - <VERSION>) could not be used due to the current database format version <NUM> (<HEX>).` |
| 20 | 627 | `<PROCESS_HEADER> {<GUID>}: The database engine (<VERSION>) is starting a new instance (<NUM>).` |

---

## 5. Veri Sınırlılıkları (Data Limitations)

1. **Güvenlik Olay Günlüğü (Security.evtx) Yoğunluğu**: Veri seti çoğunlukla `Application` ve `System` loglarını içermekte olup, derin Windows `Security` (ör. Event ID 4688 Process Creation with Command Line, 4624 Detailed Logon Types) loglarının tüm varyantlarını kapsamamaktadır.
2. **Kullanıcı Kimlikleri (User SIDs)**: Birçok olay mesajında kullanıcı hesap adı yer almamakta; servis seviyesinde anonim sistem olayları bulunmaktadır.
3. **Ağ Trafik Bilgisi (Network Netflow)**: IP adresleri log mesajlarının içinden regex ile çıkarılmakta olup, harici Firewall/NetFlow telemetrisi veri setine dahil değildir.
4. **Coğrafi Konum Verisi**: Ham CSV dosyasında IP bazlı GeoIP bilgisi bulunmamaktadır; bu sebeple R005 Coğrafi Tutarsızlık kuralı simüle edilmiş sentetik demo olarak (`is_demo: True`) işaretlenmiştir.
5. **Zaman Boşlukları**: Makinelerden toplanan loglar kesintisiz 7/24 telemetri olmayıp belirli dönemlerde yoğunlaşan aralıklı veri dökümleridir.
