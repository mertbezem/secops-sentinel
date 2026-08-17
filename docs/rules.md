# SecOps Sentinel — Detection Rules Specification

This document details the logic, threshold parameters, MITRE ATT&CK technique mappings, and known false positive scenarios for detection rules **R001–R005**.

---

## R001: `ERROR_BURST` (Error Log Surge)

- **Description**: Detects a sudden spike of `Error` or `FailureAudit` event log entries on a machine within a short sliding time window.
- **Logic**: Evaluates whether $\ge N$ error events occur within $T$ minutes.
- **Parameters**:
  - `threshold_count`: 5
  - `time_window_minutes`: 10
- **MITRE ATT&CK Mapping**: `T1078` (Valid Accounts), `T1489` (Service Stop)
- **Known False Positive Scenarios**:
  - Scheduled system maintenance or Windows Update installations generating temporary error surges.
  - Faulty application configuration causing noisy logging upon startup.

---

## R002: `SERVICE_RESTART_LOOP` (Repeated Service Restarts)

- **Description**: Detects repeated service stopping, starting, or re-start scheduling on a machine within a short window.
- **Logic**: Filters events from `Service Control Manager`, `Software Protection Platform Service`, or messages containing restart keywords. Triggers if count $\ge N$ within $T$ minutes.
- **Parameters**:
  - `threshold_count`: 3
  - `time_window_minutes`: 15
- **MITRE ATT&CK Mapping**: `T1489` (Service Stop / Denial of Service)
- **Known False Positive Scenarios**:
  - Windows Software Protection Service automatically scheduling re-starts during legitimate license rule checks.
  - Developers debugging a local Windows service by manually restarting it.

---

## R003: `NEW_MESSAGE_TEMPLATE` (Anomalous Message Template)

- **Description**: Identifies log messages whose normalized template has never been recorded in the machine's historical baseline.
- **Logic**: Triggers when a log event matches a template with occurrence count $\le 5$.
- **Parameters**:
  - `min_confidence`: 0.70
- **MITRE ATT&CK Mapping**: `T1068` (Exploitation for Privilege Escalation)
- **Known False Positive Scenarios**:
  - Initial deployment of new software or system upgrades introducing new standard log messages.

---

## R004: `OFF_HOURS_ANOMALY` (Off-Hours Activity)

- **Description**: Detects `Error` or `Warning` events generated outside normal business hours (08:00–18:00 UTC, Mon-Fri).
- **Logic**: Evaluates `is_business_hours == False` flag.
- **Parameters**:
  - `start_hour`: 8
  - `end_hour`: 18
  - `weekend_off`: True
- **MITRE ATT&CK Mapping**: `T1078` (Valid Accounts / Off-Hours Activity)
- **Known False Positive Scenarios**:
  - Overnight automated backups, batch jobs, or maintenance scripts.

---

## R005: `GEO_INCONSISTENCY` (Geographic Anomaly — DEMO)

- **Description**: Tagged with `is_demo: True`. Simulates or detects multiple geographic cities/countries associated with events for a single host.
- **Logic**: Triggers when multiple city metadata attributes are associated with a single machine.
- **Parameters**:
  - `time_window_hours`: 1
- **MITRE ATT&CK Mapping**: `T1078.004` (Unusual Geographic Location)
- **Known False Positive Scenarios**:
  - Users connected to multi-region VPN nodes or dynamic IP shifts.
