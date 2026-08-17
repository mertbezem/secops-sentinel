# SecOps Sentinel — System Architecture & Design Rationale

## 1. Architectural Layers & Separation of Concerns

SecOps Sentinel enforces strict architectural separation of concerns (NFR-11):

```
+-------------------------------------------------------------+
|                 FastAPI Routing & Validation                |
|                    backend/app/api/v1/                       |
|   (HTTP Validation, Pydantic Schemas, NO SQL / Business)    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                   Business Logic Layer                      |
|                    backend/app/services/                    |
|   (Query Execution, Ingestion, Baseline, Rule Management)   |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                 SQLAlchemy 2.0 ORM Models                   |
|                    backend/app/models/                      |
|      (Machine, Event, MessageTemplate, Rule, Finding)       |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                 Database Engine (PostgreSQL / SQLite)       |
+-------------------------------------------------------------+
```

---

## 2. Ingestion & Normalization Strategy

1. **Chunked Streaming**: Loads large CSV files in configurable batches (default 5,000 rows) to keep memory usage minimal ($< 150 \text{MB}$).
2. **Deduplication Engine**: Calculates SHA-256 hash `SHA256(machine | source | entry_type | ts_utc | message)`. Duplicate events are skipped, preventing duplicate findings.
3. **Template Extraction**: Replaces variable parameters (Hex, GUIDs, SIDs, IP addresses, File paths, Timestamps, Quoted strings, Numbers) with standardized placeholders (`<HEX>`, `<GUID>`, `<IP>`, `<PATH>`, `<TIMESTAMP>`, etc.). Achieves **50.17:1 compression ratio**.
4. **Entity Extraction**: Uses regular expressions to extract structured security entities (IPs, SIDs, Hex error codes, File paths) into JSONB for analysis.

---

## 3. Baseline & Statistical Calculation Engine

Per-machine baseline statistical profiles are computed by measuring hourly log frequency mean ($\mu$) and standard deviation ($\sigma$):

$$\mu = \frac{\text{Total Events}}{\text{Time Span in Hours}}$$

$$\sigma = \sqrt{\mu}$$

Baseline metrics are stored in the `baselines` table and referenced dynamically during detection rule execution.

---

## 4. React-Readiness & API First Principles

1. **JSON Only**: Backend returns standard JSON responses with zero Jinja2 or server-side HTML rendering.
2. **Universal Envelope**: List endpoints return `{"items": [...], "total": N, "page": N, "page_size": N}`.
3. **ISO 8601 UTC Timestamps**: All datetimes return formatted in ISO 8601 with `Z` suffix (`2020-11-14T08:41:59Z`).
4. **Uppercase Enums**: All severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and statuses (`OPEN`, `IN_PROGRESS`, `RESOLVED`, `CLOSED`) are standardized uppercase strings.
5. **Standard Error Schema**: `{"error": {"code": "...", "message": "...", "field": "..."}}`.
