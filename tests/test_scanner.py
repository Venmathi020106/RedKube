
from redkube.scanner import scan_path


def test_scans_risky_yaml_file():
    result = scan_path("examples/risky-pod.yaml")

    assert result["files_scanned"] == 1
    assert result["findings"]
    assert any(
        item["rule_id"] == "RK-CTR-001"
        for item in result["findings"]
    )


def test_scans_yaml_directory():
    result = scan_path("examples")

    assert result["files_scanned"] >= 1
    assert result["findings"]


def test_reports_missing_path():
    result = scan_path("examples/does-not-exist.yaml")

    assert result["files_scanned"] == 0
    assert result["errors"]
