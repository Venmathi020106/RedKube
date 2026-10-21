
"""Generate a standalone HTML security report for RedKube."""

from collections import Counter
from html import escape
from pathlib import Path
from typing import Any


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def generate_html_report(
    results: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Generate a standalone HTML report from RedKube scan results."""
    findings = results.get("findings", [])
    errors = results.get("errors", [])

    counts = Counter(
        str(item.get("severity", "INFO")).upper()
        for item in findings
    )

    cards = "".join(
        f'<div class="stat"><span>{severity}</span>'
        f'<strong>{counts.get(severity, 0)}</strong></div>'
        for severity in SEVERITY_ORDER
    )

    rows = []
    for index, finding in enumerate(findings, start=1):
        severity = str(finding.get("severity", "INFO")).upper()
        safe_severity = escape(severity.lower())
        risk_score = escape(str(finding.get("risk_score", "N/A")))

        fields = (
            ("rule_id", "N/A"),
            ("resource", "N/A"),
            ("message", "No description provided"),
            ("evidence", "No evidence provided"),
            ("remediation", "No remediation provided"),
            ("file", "N/A"),
            ("document", "N/A"),
        )
        values = {
            key: escape(str(finding.get(key, default)))
            for key, default in fields
        }

        rows.append(f"""
        <tr>
            <td>{index}</td>
            <td><span class="severity {safe_severity}">
                {escape(severity)}</span><br>
                <small>Risk: {risk_score}/100</small></td>
            <td><code>{values["rule_id"]}</code></td>
            <td>{values["resource"]}</td>
            <td>
                <strong>{values["message"]}</strong>
                <details><summary>Evidence</summary>
                    {values["evidence"]}
                </details>
                <details><summary>Remediation</summary>
                    {values["remediation"]}
                </details>
            </td>
            <td>{values["file"]}<br>
                <small>Document {values["document"]}</small></td>
        </tr>
        """)

    if not rows:
        rows.append("""
        <tr><td colspan="6" class="empty">
        No security findings were detected by the current rules.
        </td></tr>
        """)

    error_section = ""
    if errors:
        error_items = "".join(
            f"<li>{escape(str(error))}</li>" for error in errors
        )
        error_section = f"""
        <section class="panel">
            <h2>Scan errors</h2>
            <ul>{error_items}</ul>
        </section>
        """

    target = escape(str(results.get("target", "Unknown")))
    files_scanned = escape(str(results.get("files_scanned", 0)))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RedKube Security Report</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    margin: 0; background: #f3f6fa; color: #172033;
    font-family: Arial, Helvetica, sans-serif;
}}
header {{ background: #111827; color: white; padding: 28px 5%; }}
header h1 {{ margin: 0 0 8px; }}
header p {{ margin: 0; color: #cbd5e1; }}
main {{ max-width: 1500px; margin: auto; padding: 24px; }}
.summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(125px, 1fr));
    gap: 12px; margin-bottom: 22px;
}}
.stat, .panel {{
    background: white; border: 1px solid #e2e8f0;
    border-radius: 10px; padding: 18px;
}}
.stat span {{ display: block; color: #64748b; font-size: 12px;
    font-weight: bold; }}
.stat strong {{ display: block; font-size: 30px; margin-top: 8px; }}
.details {{ overflow-wrap: anywhere; line-height: 1.8; }}
.panel {{ margin-bottom: 22px; }}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ padding: 12px; text-align: left; vertical-align: top;
    border-bottom: 1px solid #e2e8f0; }}
th {{ background: #f8fafc; white-space: nowrap; }}
td {{ min-width: 100px; overflow-wrap: anywhere; }}
.severity {{ display: inline-block; padding: 5px 7px;
    border-radius: 5px; font-size: 11px; font-weight: bold; }}
.critical {{ background: #fee2e2; color: #991b1b; }}
.high {{ background: #ffedd5; color: #9a3412; }}
.medium {{ background: #fef3c7; color: #92400e; }}
.low {{ background: #e2e8f0; color: #334155; }}
.info {{ background: #dbeafe; color: #1e40af; }}
details {{ margin-top: 8px; }}
summary {{ cursor: pointer; color: #1d4ed8; font-weight: bold; }}
code {{ background: #f1f5f9; padding: 3px; }}
small {{ color: #64748b; }}
.empty {{ padding: 28px; text-align: center; }}
footer {{ padding: 20px; text-align: center; color: #64748b;
    font-size: 12px; }}
@media print {{
    body {{ background: white; }}
    header {{ background: white; color: #111827;
        border-bottom: 2px solid #111827; }}
    header p {{ color: #475569; }}
    main {{ max-width: none; padding: 8px; }}
    .panel, .stat {{ break-inside: avoid; }}
    details > * {{ display: block; }}
}}
</style>
</head>
<body>
<header>
    <h1>RedKube Security Report</h1>
    <p>Kubernetes YAML configuration security analysis</p>
</header>
<main>
    <section class="summary">
        <div class="stat"><span>FILES SCANNED</span>
            <strong>{files_scanned}</strong></div>
        <div class="stat"><span>TOTAL FINDINGS</span>
            <strong>{len(findings)}</strong></div>
        {cards}
    </section>
    <section class="panel details">
        <h2>Scan details</h2>
        <strong>Target:</strong> {target}<br>
        <strong>Scan errors:</strong> {len(errors)}<br>
        <strong>Analysis type:</strong> Static YAML configuration analysis
    </section>
    <section class="panel">
        <h2>Security findings</h2>
        <div class="table-wrap"><table>
            <thead><tr>
                <th>#</th><th>Severity / Risk</th><th>Rule</th>
                <th>Resource</th><th>Finding details</th><th>Source file</th>
            </tr></thead>
            <tbody>{"".join(rows)}</tbody>
        </table></div>
    </section>
    {error_section}
</main>
<footer>
    Generated by RedKube. Findings cover implemented rules only;
    they do not confirm exploitation or compromise.
</footer>
</body>
</html>
"""

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(html, encoding="utf-8")
    return destination
