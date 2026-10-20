"""Command-line interface for RedKube."""

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from redkube.graph import build_attack_graph
from redkube.risk import prioritize_findings
from redkube.scanner import scan_path


def format_text_report(result: dict[str, Any]) -> str:
    """Format prioritized scan results as readable text."""
    findings = result["findings"]
    counts = Counter(
        str(item.get("severity", "INFO")).upper()
        for item in findings
    )

    lines = [
        "RedKube — Kubernetes Security Audit",
        "=" * 42,
        f"Target: {result['target']}",
        f"YAML files scanned: {result['files_scanned']}",
        f"Total findings: {len(findings)}",
        (
            "Severity summary: "
            f"CRITICAL={counts.get('CRITICAL', 0)}, "
            f"HIGH={counts.get('HIGH', 0)}, "
            f"MEDIUM={counts.get('MEDIUM', 0)}, "
            f"LOW={counts.get('LOW', 0)}"
        ),
        "",
    ]

    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        resource = finding.get("resource", "Unknown resource")
        rule_id = finding.get("rule_id", "UNKNOWN")
        risk_score = finding.get("risk_score", 0)

        lines.extend([
            f"[{severity}] [Risk: {risk_score}/100] "
            f"{rule_id} - {resource}",
            f"  Finding: {finding.get('message', '')}",
            f"  Evidence: {finding.get('evidence', '')}",
            f"  Remediation: {finding.get('remediation', '')}",
        ])

        if finding.get("file"):
            lines.append(f"  File: {finding['file']}")
        if finding.get("document"):
            lines.append(f"  YAML document: {finding['document']}")

        lines.append("")

    if result["errors"]:
        lines.append("Scan errors:")
        for error in result["errors"]:
            lines.append(f"  - {error}")
        lines.append("")

    lines.append(
        "Note: Findings indicate configuration risks, "
        "not confirmed compromise."
    )
    return "\n".join(lines)


def write_report(report: str, output: str | None) -> int:
    """Write a report to a file or standard output."""
    if not output:
        print(report)
        return 0

    output_path = Path(output)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report + "\n", encoding="utf-8")
    except OSError as error:
        print(f"Error writing report: {error}")
        return 2

    print(f"Report saved to {output_path}")
    return 0


def main() -> int:
    """Parse arguments and run the requested command."""
    parser = argparse.ArgumentParser(
        prog="redkube",
        description="Audit Kubernetes YAML files for security risks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a YAML file or directory.",
    )
    scan_parser.add_argument("path", help="YAML file or directory.")
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Report format (default: text).",
    )
    scan_parser.add_argument(
        "--output",
        help="Save the report to a file.",
    )

    graph_parser = subparsers.add_parser(
        "graph",
        help="Build a resource relationship graph from YAML.",
    )
    graph_parser.add_argument("path", help="YAML file or directory.")
    graph_parser.add_argument(
        "--output",
        help="Save graph data as JSON to this file.",
    )

    args = parser.parse_args()

    if args.command == "scan":
        result = scan_path(args.path)
        result["findings"] = prioritize_findings(result["findings"])

        report = (
            json.dumps(result, indent=2)
            if args.format == "json"
            else format_text_report(result)
        )
        write_status = write_report(report, args.output)

        if write_status:
            return write_status
        if result["errors"]:
            return 2
        if result["findings"]:
            return 1
        return 0

    if args.command == "graph":
        result = build_attack_graph(args.path)
        report = json.dumps(result, indent=2)
        write_status = write_report(report, args.output)

        if write_status:
            return write_status
        if result["errors"]:
            return 2
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
