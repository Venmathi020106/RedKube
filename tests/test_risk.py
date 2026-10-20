from redkube.risk import score_finding, prioritize_findings


def test_scores_severity_levels():
    assert score_finding({"severity": "CRITICAL"}) == 100
    assert score_finding({"severity": "HIGH"}) == 75
    assert score_finding({"severity": "MEDIUM"}) == 50
    assert score_finding({"severity": "LOW"}) == 25


def test_prioritizes_highest_risk_first():
    findings = [
        {"rule_id": "RK-LOW", "severity": "LOW"},
        {"rule_id": "RK-CRITICAL", "severity": "CRITICAL"},
        {"rule_id": "RK-HIGH", "severity": "HIGH"},
    ]

    result = prioritize_findings(findings)

    assert [item["rule_id"] for item in result] == [
        "RK-CRITICAL",
        "RK-HIGH",
        "RK-LOW",
    ]
    assert [item["risk_score"] for item in result] == [100, 75, 25]


def test_prioritization_does_not_modify_original_findings():
    findings = [{"rule_id": "RK-001", "severity": "HIGH"}]

    prioritize_findings(findings)

    assert "risk_score" not in findings[0]
