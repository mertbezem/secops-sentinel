from app.ingestion.entity_extractor import EntityExtractor


def test_extract_ip_addresses():
    res = EntityExtractor.extract_entities("Connection from 192.168.1.100 and 10.0.0.1")
    assert "ip_addresses" in res
    assert set(res["ip_addresses"]) == {"192.168.1.100", "10.0.0.1"}


def test_extract_service_and_account_name():
    res = EntityExtractor.extract_entities("The spooler service failed to start. Account Name: SYSTEM")
    assert res.get("service_name") == "spooler"
    assert res.get("account_name") == "SYSTEM"


def test_extract_file_paths():
    res = EntityExtractor.extract_entities("Failed to open C:\\Windows\\System32\\config.dll")
    assert "file_paths" in res
    assert "C:\\Windows\\System32\\config.dll" in res["file_paths"]
