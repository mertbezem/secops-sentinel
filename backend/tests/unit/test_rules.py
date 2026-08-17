import datetime

from app.detection.rules.r001_error_burst import ErrorBurstRule
from app.detection.rules.r002_service_restart_loop import ServiceRestartLoopRule
from app.detection.rules.r003_new_template import NewMessageTemplateRule
from app.detection.rules.r004_off_hours import OffHoursAnomalyRule
from app.detection.rules.r005_geo_inconsistency import GeoInconsistencyRule
from app.models.models import Event, Machine, MessageTemplate


def test_r001_error_burst_trigger():
    rule = ErrorBurstRule(params={"threshold_count": 3, "time_window_minutes": 10})
    m = Machine(id=1, name="TEST-PC")
    now = datetime.datetime.now(datetime.UTC)

    events = [
        Event(id=i, machine_id=1, source="App", entry_type="Error", message="Err", ts_utc=now + datetime.timedelta(minutes=i))
        for i in range(4)
    ]

    findings = rule.evaluate(machine=m, events=events, baselines={})
    assert len(findings) == 1
    assert findings[0]["rule_code"] == "R001"


def test_r002_service_restart_trigger():
    rule = ServiceRestartLoopRule(params={"threshold_count": 3, "time_window_minutes": 15})
    m = Machine(id=1, name="TEST-PC")
    now = datetime.datetime.now(datetime.UTC)

    events = [
        Event(id=i, machine_id=1, source="Service Control Manager", entry_type="Information", message="Service stopped", ts_utc=now + datetime.timedelta(minutes=i))
        for i in range(3)
    ]

    findings = rule.evaluate(machine=m, events=events, baselines={})
    assert len(findings) == 1
    assert findings[0]["rule_code"] == "R002"


def test_r003_new_template_trigger():
    rule = NewMessageTemplateRule(params={"min_confidence": 0.8})
    m = Machine(id=1, name="TEST-PC")
    now = datetime.datetime.now(datetime.UTC)
    tmpl = MessageTemplate(id=1, template_hash="abc", template_text="tmpl", occurrence_count=2)

    events = [
        Event(id=1, machine_id=1, source="App", entry_type="Information", message="msg", template=tmpl, ts_utc=now)
    ]

    findings = rule.evaluate(machine=m, events=events, baselines={})
    assert len(findings) == 1
    assert findings[0]["rule_code"] == "R003"


def test_r004_off_hours_trigger():
    rule = OffHoursAnomalyRule()
    m = Machine(id=1, name="TEST-PC")
    now = datetime.datetime.now(datetime.UTC)

    events = [
        Event(id=1, machine_id=1, source="App", entry_type="Error", message="err", is_business_hours=False, ts_utc=now)
    ]

    findings = rule.evaluate(machine=m, events=events, baselines={})
    assert len(findings) == 1
    assert findings[0]["rule_code"] == "R004"


def test_r005_geo_inconsistency_demo_trigger():
    rule = GeoInconsistencyRule()
    assert rule.is_demo is True
    m = Machine(id=1, name="TEST-PC")
    now = datetime.datetime.now(datetime.UTC)

    events = [
        Event(id=1, machine_id=1, source="App", entry_type="Information", message="login", city="Ahmedabad", ts_utc=now),
        Event(id=2, machine_id=1, source="App", entry_type="Information", message="login", city="Surat", ts_utc=now)
    ]

    findings = rule.evaluate(machine=m, events=events, baselines={})
    assert len(findings) == 1
    assert findings[0]["rule_code"] == "R005"
