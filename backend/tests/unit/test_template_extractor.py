from app.ingestion.template_extractor import TemplateExtractor


def test_empty_message():
    tmpl, hash_val, count = TemplateExtractor.extract_template("")
    assert tmpl == "<EMPTY>"
    assert count == 0
    assert len(hash_val) == 64


def test_none_message():
    tmpl, _, count = TemplateExtractor.extract_template(None)
    assert tmpl == "<EMPTY>"
    assert count == 0


def test_simple_static_text():
    tmpl, _, count = TemplateExtractor.extract_template("Software Protection service has started.")
    assert tmpl == "Software Protection service has started."
    assert count == 0


def test_ipv4_replacement():
    tmpl, _, count = TemplateExtractor.extract_template("Connection from 192.168.1.100 port 443")
    assert "<IP>" in tmpl
    assert "192.168.1.100" not in tmpl
    assert count >= 1


def test_guid_replacement():
    tmpl, _, _ = TemplateExtractor.extract_template("Report Id: {1828384C-7EC9-2D5A-B686-2A90970D16EC}")
    assert "<GUID>" in tmpl
    assert "1828384C" not in tmpl


def test_hex_code_replacement():
    tmpl, _, _ = TemplateExtractor.extract_template("Error code 0x800704C7 occurred in module")
    assert "<HEX>" in tmpl
    assert "0x800704C7" not in tmpl


def test_timestamp_replacement():
    tmpl, _, _ = TemplateExtractor.extract_template("Scheduled restart at 2020-11-14T11:28:59Z")
    assert "<TIMESTAMP>" in tmpl
    assert "2020-11-14T11:28:59Z" not in tmpl


def test_windows_file_path_replacement():
    tmpl, _, _ = TemplateExtractor.extract_template("Failed to load file C:\\Windows\\System32\\config.dll")
    assert "<PATH>" in tmpl


def test_unc_path_replacement():
    tmpl, _, _ = TemplateExtractor.extract_template("Access denied to \\\\SERVER01\\Share\\file.txt")
    assert "<UNC_PATH>" in tmpl


def test_number_replacement():
    tmpl, _, count = TemplateExtractor.extract_template("Event ID 1004 occurred 5 times")
    assert "<NUM>" in tmpl
    assert count >= 2


def test_multiple_whitespace_normalization():
    tmpl, _, _ = TemplateExtractor.extract_template("  Multiple   spaces    here  \n\t")
    assert tmpl == "Multiple spaces here"
