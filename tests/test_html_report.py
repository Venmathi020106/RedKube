
from redkube.reporting.html_report import generate_html_report


def test_generates_html_security_report(tmp_path):
    results = {
        "target": "examples/",
        "files_scanned": 1,
        "errors": [],
        "findings": [
            {
                "rule_id": "RK-CTR-001",
                "severity": "HIGH",
                "resource": "Pod/test-pod",
                "message": "Container is privileged.",
                "evidence": "securityContext.privileged is true",
                "remediation": "Disable privileged mode.",
                "risk_score": 75,
                "file": "examples/risky-pod.yaml",
                "document": "1",
            }
        ],
    }

    output = tmp_path / "security-report.html"
    generated = generate_html_report(results, output)

    assert generated == output
    assert output.exists()

    html = output.read_text(encoding="utf-8")

    assert "RedKube Security Report" in html
    assert "RK-CTR-001" in html
    assert "Container is privileged." in html
    assert "securityContext.privileged is true" in html
    assert "Disable privileged mode." in html
    assert "75/100" in html


def test_generates_html_report_with_no_findings(tmp_path):
    results = {
        "target": "examples/secure-pod.yaml",
        "files_scanned": 1,
        "errors": [],
        "findings": [],
    }

    output = tmp_path / "secure-report.html"
    generate_html_report(results, output)

    html = output.read_text(encoding="utf-8")

    assert "No security findings were detected" in html
    assert "TOTAL FINDINGS" in html
