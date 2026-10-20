"""Risk scoring and prioritization for RedKube findings."""

from typing import Any


SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 10,
}


def score_finding(finding: dict[str, Any]) -> int:
    """Return a baseline risk score based on finding severity."""
    severity = str(finding.get("severity", "INFO")).upper()
    return SEVERITY_SCORES.get(severity, SEVERITY_SCORES["INFO"])


def prioritize_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return copied findings ordered from highest to lowest risk."""
    prioritized = []

    for finding in findings:
        item = dict(finding)
        item["risk_score"] = score_finding(item)
        prioritized.append(item)

    return sorted(
        prioritized,
        key=lambda item: item["risk_score"],
        reverse=True,
    )
