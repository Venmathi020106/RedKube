
import sys
from pathlib import Path

import yaml


def audit_document(document):
    """Return security findings for a Kubernetes YAML document."""
    findings = []

    if not isinstance(document, dict):
        return findings

    kind = document.get("kind", "Unknown")
    metadata = document.get("metadata") or {}
    name = metadata.get("name", "unnamed")

    spec = document.get("spec") or {}

    # Support Pods and common workload resources.
    if kind == "Pod":
        pod_spec = spec
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        pod_template = spec.get("template") or {}
        pod_spec = pod_template.get("spec") or {}
    elif kind == "CronJob":
        job_template = (
            spec.get("jobTemplate") or {}
        ).get("spec") or {}
        pod_template = job_template.get("template") or {}
        pod_spec = pod_template.get("spec") or {}
    else:
        return findings

    pod_security = pod_spec.get("securityContext") or {}

    if pod_security.get("runAsNonRoot") is not True:
        findings.append(
            ("MEDIUM", "POD-001",
             "Pod does not explicitly require a non-root user.")
        )

    for container in pod_spec.get("containers", []):
        container_name = container.get("name", "unnamed")
        security = container.get("securityContext") or {}

        if security.get("privileged") is True:
            findings.append(
                ("HIGH", "CTR-001",
                 f"Container '{container_name}' is privileged.")
            )

        if security.get("allowPrivilegeEscalation") is True:
            findings.append(
                ("HIGH", "CTR-002",
                 f"Container '{container_name}' allows privilege escalation.")
            )

        if security.get("runAsUser") == 0:
            findings.append(
                ("HIGH", "CTR-003",
                 f"Container '{container_name}' explicitly runs as root.")
            )

        if security.get("readOnlyRootFilesystem") is not True:
            findings.append(
                ("LOW", "CTR-004",
                 f"Container '{container_name}' does not explicitly use a read-only root filesystem.")
            )

    return [
        (severity, rule_id, f"{kind}/{name}: {message}")
        for severity, rule_id, message in findings
    ]


def audit_file(file_path):
    """Audit all YAML documents in a file."""
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            documents = yaml.safe_load_all(file)
            for document in documents:
                findings.extend(audit_document(document))
    except (OSError, yaml.YAMLError) as error:
        print(f"Error reading {file_path}: {error}", file=sys.stderr)
        return None

    return findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python -m redkube.main <kubernetes-yaml-file>")
        return 2

    file_path = Path(sys.argv[1])

    findings = audit_file(file_path)
    if findings is None:
        return 2

    print(f"\nRedKube Security Audit: {file_path}")
    print("-" * 55)

    if not findings:
        print("No configured checks were flagged.")
        print("This does not prove the resource is secure.")
        return 0

    for severity, rule_id, message in findings:
        print(f"[{severity}] {rule_id}: {message}")

    print(f"\nTotal findings: {len(findings)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
