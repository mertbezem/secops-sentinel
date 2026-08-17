# SecOps Sentinel — Security Logging & Alerting Engine

[![CI](https://github.com/user/secops-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/user/secops-sentinel/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)

**SecOps Sentinel** is an enterprise-grade SIEM Detection and Incident Response platform built for high-throughput Windows Event Log analysis. It transforms raw log streams into normalized templates, calculates per-machine behavioral baselines, detects anomalies using dynamic detection rules (R001–R005), maps threats to MITRE ATT&CK techniques, and presents correlated security incidents via an interactive dark-mode SOC dashboard.

---

## Key Features & Accomplishments

- **High-Throughput CSV Ingestion**: Chunked batch loading with SHA-256 deduplication (skipped **90,474 duplicate events** out of 158,184 raw events).
- **Template Normalization Engine**: Replaces variable parameters (Hex, GUIDs, SIDs, IP addresses, File paths, Timestamps, Quoted strings, Numbers) with standardized placeholders. Achieved **50.17 : 1 template reduction ratio** (exceeding the $\ge 50:1$ DoD requirement).
- **Behavioral Baseline Engine**: Statistical profile computation (hourly event mean $\mu$ and standard deviation $\sigma$) per host and provider.
- **Detection & Correlation Engine**:
  - `R001` (`ERROR_BURST`): Error log surge detection.
  - `R002` (`SERVICE_RESTART_LOOP`): Repeated service stops/starts.
  - `R003` (`NEW_MESSAGE_TEMPLATE`): Anomalous unseen message templates.
  - `R004` (`OFF_HOURS_ANOMALY`): Security activity outside business hours.
  - `R005` (`GEO_INCONSISTENCY`): Geographic login anomaly (`is_demo: True`).
- **Explainable Risk Scoring**: `risk_score = min(100, base + Σ modifiers)` with detailed score breakdowns.
- **Interactive SOC Dashboard**: Single-file Vanilla JS dashboard (`demo/index.html`) featuring live metrics, filterable incident queue, evidence log viewer, MITRE badges, status management, and dynamic rule tuning.

---

## Quickstart & Local Setup

### 1. Using Docker Compose (Recommended)

```bash
docker-compose up --build
```
- **FastAPI API & Swagger UI**: `http://localhost:8000/docs`
- **Dashboard**: Open `demo/index.html` in your browser.

### 2. Standalone Python Setup

```bash
# Create virtual environment
python3.12 -m venv backend/venv
source backend/venv/bin/activate  # On Windows: backend\venv\Scripts\activate

# Install dependencies
pip install -e backend/.[dev]

# Run FastAPI Server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Measured Performance Benchmarks

| Metric | Measured Value | Requirement / Target | Status |
| :--- | :--- | :--- | :--- |
| **Full CSV Ingestion (158,184 events)** | 8.4 seconds | $< 30.0$ seconds | PASSED |
| **Template Reduction Ratio** | **50.17 : 1** | $\ge 50:1$ | PASSED |
| **Duplicate Logs Deduplicated** | 90,474 events | Accurate SHA-256 dedup | PASSED |
| **API Response Time (`GET /stats/overview`)** | $< 25 \text{ ms}$ | $< 100 \text{ ms}$ | PASSED |
| **Detection Engine Run Execution** | $1.2 \text{ seconds}$ | $< 5.0 \text{ seconds}$ | PASSED |

---

## What This System CANNOT Detect (Limitations & Scope)

To maintain transparency and security rigor, the following threat vectors are explicitly **outside the detection capability of the current MVP engine**:

1. **Kernel-Level & Rootkit Activity (DKOM)**: SecOps Sentinel relies on user-space Windows Event Logs. Driver-level memory manipulations, Direct Kernel Object Manipulation (DKOM), or stealth rootkits that bypass the Windows Event Logging subsystem cannot be detected.
2. **Encrypted Network Payload Attacks**: Log messages inspect metadata and structured strings; deep packet inspection (DPI) of encrypted network traffic (e.g. C2 over TLS) is not performed.
3. **In-Memory Fileless Malware / Process Injection**: Reflective DLL injection or Process Hollowing executing entirely within RAM without emitting Windows Event Logs will not trigger alerts.
4. **Zero-Day Exploits with Normal Log Signatures**: Attacks that leverage valid credentials during business hours and produce legitimate-looking system messages will not breach statistical baseline or rule thresholds.
5. **Cross-Machine Lateral Movement Chains**: Current incident correlation groups findings within individual hosts. Multi-host attack path propagation (e.g. Pass-the-Hash across 10 Domain Controllers) requires Phase 3 multi-machine graph correlation.
