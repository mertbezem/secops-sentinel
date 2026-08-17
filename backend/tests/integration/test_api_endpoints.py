import io


def test_healthz_endpoint(client):
    response = client.get("/api/v1/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ingest_csv_and_query_events(client):
    csv_content = """MachineName,Category,EntryType,Message,Source,TimeGenerated,country,regionName,city
LAPTOP-TEST,(0),Error,Service failed to start unexpectedly,Service Control Manager,2020-11-14 08:41:59,India,Gujarat,Ahmedabad
LAPTOP-TEST,(0),Error,Service failed to start unexpectedly,Service Control Manager,2020-11-14 08:41:59,India,Gujarat,Ahmedabad
"""
    files = {"file": ("test.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
    ingest_res = client.post("/api/v1/ingest/csv", files=files)
    assert ingest_res.status_code == 200
    ingest_json = ingest_res.json()
    assert ingest_json["total_processed"] == 2
    assert ingest_json["new_events"] == 1
    assert ingest_json["duplicates_skipped"] == 1

    # List events
    events_res = client.get("/api/v1/events")
    assert events_res.status_code == 200
    events_json = events_res.json()
    assert events_json["total"] == 1
    assert events_json["items"][0]["machine_name"] == "LAPTOP-TEST"


def test_trigger_detection_pipeline_and_incidents(client):
    # Ingest error burst events
    csv_lines = ["MachineName,Category,EntryType,Message,Source,TimeGenerated,country,regionName,city"]
    for i in range(6):
        csv_lines.append(f"LAPTOP-BURST,(0),Error,Application crashed error #{i},Application Error,2020-11-14 08:4{i}:00,India,Gujarat,Ahmedabad")

    csv_content = "\n".join(csv_lines)
    files = {"file": ("burst.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
    client.post("/api/v1/ingest/csv", files=files)

    # Run detection
    det_res = client.post("/api/v1/detection/run")
    assert det_res.status_code == 200
    det_json = det_res.json()
    assert det_json["findings_created"] >= 1

    # List Incidents
    inc_res = client.get("/api/v1/incidents")
    assert inc_res.status_code == 200
    inc_json = inc_res.json()
    assert inc_json["total"] >= 1
    inc_id = inc_json["items"][0]["id"]

    # Incident Detail
    detail_res = client.get(f"/api/v1/incidents/{inc_id}")
    assert detail_res.status_code == 200
    detail_json = detail_res.json()
    assert detail_json["id"] == inc_id
    assert len(detail_json["findings"]) >= 1

    # Update Incident status
    patch_res = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "IN_PROGRESS", "assignee": "Alice"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "IN_PROGRESS"


def test_invalid_incident_status_transition_returns_400(client):
    patch_res = client.patch("/api/v1/incidents/99999", json={"status": "INVALID_STATUS"})
    assert patch_res.status_code == 400


def test_stats_overview_and_timeseries(client):
    csv_content = """MachineName,Category,EntryType,Message,Source,TimeGenerated,country,regionName,city
LAPTOP-STATS,(0),Information,Normal health check,Service Control Manager,2020-11-14 09:00:00,India,Gujarat,Ahmedabad
"""
    files = {"file": ("stats.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
    client.post("/api/v1/ingest/csv", files=files)

    res = client.get("/api/v1/stats/overview")
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "severity_breakdown" in data
    assert "top_sources" in data

    ts_res = client.get("/api/v1/stats/timeseries?buckets=10")
    assert ts_res.status_code == 200
    ts_data = ts_res.json()
    assert "buckets" in ts_data
    assert isinstance(ts_data["buckets"], list)


def test_machines_api_and_timeline(client):
    # Ingest event for a machine
    csv_content = """MachineName,Category,EntryType,Message,Source,TimeGenerated,country,regionName,city
LAPTOP-TIMELINE,(0),Information,User logon initiated,Security,2020-11-14 09:00:00,India,Gujarat,Ahmedabad
"""
    files = {"file": ("machine.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")}
    client.post("/api/v1/ingest/csv", files=files)

    # List machines
    m_res = client.get("/api/v1/machines")
    assert m_res.status_code == 200
    m_data = m_res.json()
    assert m_data["total"] >= 1
    target_machine = next((m for m in m_data["items"] if m["name"] == "LAPTOP-TIMELINE"), m_data["items"][0])
    m_id = target_machine["id"]

    # Get single machine
    single_res = client.get(f"/api/v1/machines/{m_id}")
    assert single_res.status_code == 200
    assert single_res.json()["id"] == m_id

    # Get machine timeline
    timeline_res = client.get(f"/api/v1/machines/{m_id}/timeline?limit=50")
    assert timeline_res.status_code == 200
    timeline_data = timeline_res.json()
    assert "timeline" in timeline_data
    assert len(timeline_data["timeline"]) >= 1


def test_rules_api_list_and_patch(client):
    # List rules
    rules_res = client.get("/api/v1/rules")
    assert rules_res.status_code == 200
    rules_data = rules_res.json()
    assert rules_data["total"] >= 5

    # Patch rule R001
    patch_res = client.patch("/api/v1/rules/R001", json={"enabled": True, "weight": 1.5, "params": {"threshold_count": 8}})
    assert patch_res.status_code == 200
    patched_rule = patch_res.json()
    assert patched_rule["code"] == "R001"
    assert patched_rule["weight"] == 1.5
    assert patched_rule["params"]["threshold_count"] == 8


def test_api_info_and_dashboard_routes(client):
    info_res = client.get("/api/info")
    assert info_res.status_code == 200
    assert "version" in info_res.json()

    dash_res = client.get("/dashboard")
    assert dash_res.status_code == 200
