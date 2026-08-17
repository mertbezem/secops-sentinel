import os
import hashlib
import pandas as pd
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.ingestion.template_extractor import TemplateExtractor


def run_profiling(csv_path: str, output_doc: str):
    print(f"Loading dataset from: {csv_path}...")
    df = pd.read_csv(csv_path)

    total_rows = len(df)
    unique_machines = df['MachineName'].nunique()
    machine_counts = df['MachineName'].value_counts().to_dict()

    entry_type_counts = df['EntryType'].value_counts().to_dict()
    top_30_sources = df['Source'].value_counts().head(30).to_dict()

    # TimeGenerated analysis
    df['parsed_ts'] = pd.to_datetime(df['TimeGenerated'], utc=True, errors='coerce')
    min_ts = df['parsed_ts'].min()
    max_ts = df['parsed_ts'].max()
    null_ts_count = df['parsed_ts'].isnull().sum()

    # Deduplication analysis
    df['dedup_str'] = (
        df['MachineName'].fillna('') + '|' +
        df['Source'].fillna('') + '|' +
        df['EntryType'].fillna('') + '|' +
        df['Message'].fillna('') + '|' +
        df['TimeGenerated'].fillna('')
    )
    df['dedup_hash'] = df['dedup_str'].apply(lambda s: hashlib.sha256(s.encode('utf-8')).hexdigest())
    unique_dedup_hashes = df['dedup_hash'].nunique()
    exact_duplicates = total_rows - unique_dedup_hashes

    # Template Extractor profiling
    print("Running TemplateExtractor on unique messages...")
    unique_messages = df['Message'].dropna().unique()
    template_hashes = set()

    for msg in unique_messages:
        tmpl_text, tmpl_hash, _ = TemplateExtractor.extract_template(msg)
        template_hashes.add(tmpl_hash)

    unique_templates_count = len(template_hashes)
    reduction_ratio = total_rows / unique_templates_count if unique_templates_count > 0 else 0

    print("Data Profiling Summary:")
    print(f"Total Rows: {total_rows:,}")
    print(f"Unique Machines: {unique_machines}")
    print(f"Exact Duplicates: {exact_duplicates:,}")
    print(f"Unique Templates: {unique_templates_count:,}")
    print(f"Template Reduction Ratio: {reduction_ratio:.2f}:1")

    # Build Markdown Document
    markdown_content = f"""# SecOps Sentinel — EventLog Veri Profilleme Raporu

**Analiz Tarihi**: 2026-08-14  
**Veri Seti**: `eventlog.csv` ({total_rows:,} satır)

---

## 1. Genel Özet & Makine Dağılımı

- **Toplam Olay Satırı**: `{total_rows:,}`
- **Benzersiz Makine Sayısı**: `{unique_machines}`
- **Birebir Çift (Duplicate) Satır Sayısı**: `{exact_duplicates:,}` ({exact_duplicates / total_rows * 100:.2f}%)
- **Benzersiz Deduplication Hash Sayısı**: `{unique_dedup_hashes:,}`
- **Benzersiz Mesaj Şablonu (Templates)**: `{unique_templates_count:,}`
- **Şablon İndirgeme Oranı**: **`{reduction_ratio:.2f} : 1`** (Hedef $\\ge 50:1$)

### Makine Başına Olay Dağılımı

| Makine Adı | Olay Sayısı | Oran (%) |
| :--- | :--- | :--- |
"""

    for machine_name, count in machine_counts.items():
        percentage = (count / total_rows) * 100
        markdown_content += f"| `{machine_name}` | {count:,} | {percentage:.2f}% |\n"

    markdown_content += f"""
---

## 2. EntryType & Top 30 Source Dağılımı

### EntryType Dağılımı

| EntryType | Satır Sayısı | Oran (%) |
| :--- | :--- | :--- |
"""

    for etype, count in entry_type_counts.items():
        percentage = (count / total_rows) * 100
        markdown_content += f"| `{etype}` | {count:,} | {percentage:.2f}% |\n"

    markdown_content += f"""
### En Sık Geçen 30 Olay Kaynağı (Source)

| Sıra | Kaynak (Source) | Satır Sayısı | Oran (%) |
| :--- | :--- | :--- | :--- |
"""

    for idx, (source_name, count) in enumerate(top_30_sources.items(), 1):
        percentage = (count / total_rows) * 100
        markdown_content += f"| {idx} | `{source_name}` | {count:,} | {percentage:.2f}% |\n"

    markdown_content += f"""
---

## 3. TimeGenerated Zaman Analizi & UTC Parse Kararı

- **En Erken Olay Zamanı (Min)**: `{min_ts}`
- **En Geç Olay Zamanı (Max)**: `{max_ts}`
- **Parse Edilemeyen Geçersiz Zaman Satır Sayısı**: `{null_ts_count}`

### UTC Parse Kararı ve Teknik Gerekçesi

1. **Standartlaştırma**: `TimeGenerated` sütunu ISO 8601 / Windows standart `YYYY-MM-DD HH:MM:SS` formatındadır. SIEM sisteminde birden fazla makine ve coğrafi konumdan gelen olayları karşılaştırmak için tüm zaman damgaları UTC zaman dilimine çevrilir (`tzinfo=datetime.UTC`).
2. **Mesai Saatleri Kararı**: Olayların mesai saatleri içinde gerçekleşip gerçekleşmediğini tespit etmek amacıyla UTC zamanı yerel saat dilimine ve işletmenin çalışma saatlerine (`08:00 - 18:00`) göre `is_business_hours` boolean alanına dönüştürülür.
3. **Zaman Penceresi Gruplaması**: R001 Error Burst ve R002 Service Restart Loop kuralları sliding window hesabı yaptığı için mikro-saniye hassasiyetinde UTC zaman damgaları indekslenmiştir.

---

## 4. Deduplication Hash & Şablon Analizi

### Deduplication Hash Hesabı

Olay teilleme `dedup_hash` değeri şu alanların birleşimi ile SHA-256 hash'i olarak hesaplanır:
```
SHA256(MachineName | Source | EntryType | Message | TimeGenerated)
```

- Veri setinde tespit edilen **{exact_duplicates:,} adet tekrarlayan satır**, veritabanına aktarılırken `dedup_hash` benzersizlik kısıtı (UNIQUE constraint) sayesinde otomatik olarak elenir.

### Şablon İndirgeme Verimliliği

`TemplateExtractor` modülü değişken parametreleri (`<IP>`, `<GUID>`, `<HEX>`, `<PATH>`, `<UNC_PATH>`, `<TIMESTAMP>`, `<NUM>`) maskeleyerek **{total_rows:,} olay mesajını {unique_templates_count:,} benzersiz şablona** düşürmüştür. Bu da **{reduction_ratio:.2f}:1** oranında yüksek sıkıştırma verimliliği sağlamıştır.
"""

    with open(output_doc, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"Data profile documentation generated successfully at: {output_doc}")


if __name__ == "__main__":
    csv_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "eventlog.csv"))
    doc_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "data-profile.md"))
    run_profiling(csv_file, doc_file)
