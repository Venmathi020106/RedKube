
"""Kubernetes RBAC security checks."""

from typing import Any


def check_rbac_security(
    document: dict[str, Any],
) -> list[dict[str, str]]:
    """Identify potentially excessive Kubernetes RBAC permissions."""
    if not isinstance(document, dict):
        return []

    kind = document.get("kind", "")
    metadata = document.get("metadata") or {}
    name = metadata.get("name", "unnamed")
    namespace = metadata.get("namespace", "default")
    resource = f"{kind}/{name}"
    findings: list[dict[str, str]] = []

    def add(rule_id, severity, message, evidence, remediation):
        findings.append({
            "rule_id": rule_id,
            "severity": severity,
            "resource": resource,
            "message": message,
            "evidence": evidence,
            "remediation": remediation,
        })

    if kind in {"Role", "ClusterRole"}:
        rules = document.get("rules") or []

        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue

            verbs = rule.get("verbs") or []
            resources = rule.get("resources") or []
            api_groups = rule.get("apiGroups") or []

            wildcard_fields = []

            if "*" in verbs:
                wildcard_fields.append("verbs")
            if "*" in resources:
                wildcard_fields.append("resources")
            if "*" in api_groups:
                wildcard_fields.append("apiGroups")

            if wildcard_fields:
                add(
                    "RK-RBAC-001",
                    "HIGH",
                    "RBAC rule contains wildcard permissions.",
                    (
                        f"rules[{index}] has wildcard values in: "
                        + ", ".join(wildcard_fields)
                    ),
                    "Replace wildcard permissions with the minimum required verbs, resources, and API groups.",
                )

            if "*" in verbs and "*" in resources:
                add(
                    "RK-RBAC-002",
                    "HIGH",
                    "RBAC rule allows all verbs on all resources.",
                    f"rules[{index}] contains verbs=['*'] and resources=['*']",
                    "Restrict both verbs and resources to the specific operations required.",
                )

    elif kind in {"RoleBinding", "ClusterRoleBinding"}:
        role_ref = document.get("roleRef") or {}
        subjects = document.get("subjects") or []

        if (
            kind == "ClusterRoleBinding"
            and role_ref.get("kind") == "ClusterRole"
            and role_ref.get("name") == "cluster-admin"
        ):
            add(
                "RK-RBAC-003",
                "CRITICAL",
                "ClusterRoleBinding grants the cluster-admin role.",
                "roleRef references ClusterRole/cluster-admin",
                "Review every subject and remove cluster-wide administrator access unless explicitly required.",
            )

        for subject in subjects:
            if not isinstance(subject, dict):
                continue

            if (
                subject.get("kind") == "ServiceAccount"
                and subject.get("name") == "default"
            ):
                add(
                    "RK-RBAC-004",
                    "MEDIUM",
                    "A binding references the default service account.",
                    (
                        f"Subject is ServiceAccount/default; "
                        f"namespace={subject.get('namespace', namespace)}"
                    ),
                    "Consider a dedicated service account with narrowly scoped permissions.",
                )

    return findings
