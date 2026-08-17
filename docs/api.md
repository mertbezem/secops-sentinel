# SecOps Sentinel — REST API Reference

All API endpoints are mounted under `/api/v1`.

## Endpoints Summary

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/ingest/csv` | Ingest Windows Event Log CSV file |
| `GET` | `/api/v1/ingest/jobs/{id}` | Check ingestion job status |
| `GET` | `/api/v1/events` | List events (paginated & filterable) |
| `GET` | `/api/v1/events/{id}` | Get single event by ID |
| `GET` | `/api/v1/machines` | List monitored machines |
| `GET` | `/api/v1/machines/{id}` | Get machine details |
| `GET` | `/api/v1/machines/{id}/timeline` | Get unified timeline of events & findings |
| `POST` | `/api/v1/detection/run` | Execute detection pipeline across all data |
| `GET` | `/api/v1/incidents` | List correlated incidents |
| `GET` | `/api/v1/incidents/{id}` | Get detailed incident breakdown |
| `PATCH` | `/api/v1/incidents/{id}` | Update incident status/assignee |
| `GET` | `/api/v1/rules` | List detection rules |
| `PATCH` | `/api/v1/rules/{code}` | Dynamically update rule parameters |
| `GET` | `/api/v1/stats/overview` | Dashboard summary metrics |
| `GET` | `/api/v1/stats/timeseries` | Time-series event & incident counts |
| `GET` | `/api/v1/healthz` | System health check |

---

## Response Envelope Standard

All list endpoints return the standard envelope:

```json
{
  "items": [],
  "total": 100,
  "page": 1,
  "page_size": 50
}
```

## Error Response Standard

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "status: Invalid status 'INVALID'. Must be one of: CLOSED, IN_PROGRESS, OPEN, RESOLVED",
    "field": "status"
  }
}
```
