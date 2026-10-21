#!/usr/bin/env python3
"""Validate RedKube using risky and secure Kubernetes YAML examples."""

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from redkube.scanner import scan_path


def main():
    examples_dir = ROOT / "examples"
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    if not examples_dir.is_dir():
        print(f"ERROR: Examples directory not found: {examples_dir}")
        return 1

    result = scan_path(examples_dir)
    findings = result.get("findings", [])
    errors = result.get("errors", [])

    # Group the scanner's findings by YAML filename.
    findings_by_file = defaultdict(list)
    for finding in findings:
        file_name = Path(finding.get("file", "unknown")).name
        findings_by_file[file_name].append(finding)

    # Include every YAML file, even when it has zero findings.
    yaml_files = sorted(
        path for path in examples_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}
    )

    file_results = []
    for path in yaml_files:
        name = path.name
        file_findings = findings_by_file.get(name, [])

        file_results.append({
            "file": str(path.relative_to(ROOT)),
            "finding_count": len(file_findings),
            "findings": [
                {
                    "rule_id": item.get("rule_id"),
                    "severity": item.get("severity"),
                    "resource": item.get("resource"),
                    "message": item.get("message"),
                }
                for item in file_findings
            ],
        })

    severity_summary = {}
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN").upper()
        severity_summary[severity] = severity_summary.get(severity, 0) + 1

    report = {
        "files_scanned": result.get("files_scanned", len(yaml_files)),
        "total_findings": len(findings),
        "severity_summary": severity_summary,
        "file_results": file_results,
        "errors": errors,
    }

    report_path = reports_dir / "validation-report.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("RedKube — Example Validation")
    print("=" * 40)

    for item in file_results:
        print(f"\n{item['file']}: {item['finding_count']} finding(s)")
        for finding in item["findings"]:
            print(
                f"  [{finding['severity']}] "
                f"{finding['rule_id']}: {finding['message']}"
            )

    print("\n" + "=" * 40)
    print(f"Files scanned: {report['files_scanned']}")
    print(f"Total findings: {report['total_findings']}")
    print(f"Severity summary: {report['severity_summary']}")
    print(f"Errors: {len(errors)}")
    print(f"Report saved: {report_path.relative_to(ROOT)}")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
