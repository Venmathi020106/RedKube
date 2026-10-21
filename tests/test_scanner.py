from pathlib import Path

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


def test_secure_pod_has_no_findings():
    result = scan_path("examples/secure-pod.yaml")

    assert result["files_scanned"] == 1
    assert result["findings"] == []
    assert result["errors"] == []


def test_reports_invalid_yaml(tmp_path):
    invalid_file = tmp_path / "invalid.yaml"
    invalid_file.write_text("invalid: [yaml", encoding="utf-8")

    result = scan_path(str(invalid_file))

    assert result["files_scanned"] == 1
    assert result["errors"]
