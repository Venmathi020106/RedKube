#!/usr/bin/env python3
"""Validate RedKube against all example Kubernetes YAML files."""

import json
import sys
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
    files = result.get("files", [])
    findings = result.get("findings", [])
    errors = result.get("errors", [])

    summary = {
        "files_scanned": result.get("files_scanned", len(files)),
        "total_findings": len(findings),
        "severity_summary": {},
        "file_results": [],
        "errors": errors,
    }

    for finding in findings:
        severity = finding.get("severity", "UNKNOWN").upper()
        summary["severity_summary"][severity] = (
            summary["severity_summary"].get(severity, 0) + 1
        )

    for item in files:
        file_name = Path(item.get("file", "")).name
        item_findings = item.get("findings", [])

        summary["file_results"].append({
            "file": file_name,
            "status": item.get("status", "unknown"),
            "finding_count": len(item_findings),
            "findings": item_findings,
        })

        print(f"\n{file_name}: {len(item_findings)} finding(s)")
        for finding in item_findings:
            print(
                f"  [{finding.get('severity', 'UNKNOWN')}] "
                f"{finding.get('rule_id', 'UNKNOWN')} - "
                f"{finding.get('message', '')}"
            )

    output_file = reports_dir / "validation-report.json"
    output_file.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print("\n=== RedKube Validation Summary ===")
    print(f"Files scanned: {summary['files_scanned']}")
    print(f"Total findings: {summary['total_findings']}")
    print(f"Severity summary: {summary['severity_summary']}")
    print(f"Errors: {len(errors)}")
    print(f"Report saved: {output_file.relative_to(ROOT)}")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
