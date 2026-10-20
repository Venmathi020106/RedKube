
"""Security checks for Kubernetes Pod specifications."""

from typing import Any


def check_pod_security(document: dict[str, Any]) -> list[dict[str, str]]:
    """Inspect a Pod or supported workload for risky configuration."""
    if not isinstance(document, dict):
        return []

    kind = document.get("kind", "")
    metadata = document.get("metadata") or {}
    resource_name = metadata.get("name", "unnamed")

    spec = document.get("spec") or {}

    if kind == "Pod":
        pod_spec = spec
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        pod_spec = (spec.get("template") or {}).get("spec") or {}
    elif kind == "CronJob":
        job_spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        pod_spec = (job_spec.get("template") or {}).get("spec") or {}
    else:
        return []

    if not isinstance(pod_spec, dict):
        return []

    findings: list[dict[str, str]] = []

    def add(
        rule_id: str,
        severity: str,
        message: str,
        evidence: str,
        remediation: str,
    ) -> None:
        findings.append({
            "rule_id": rule_id,
            "severity": severity,
            "resource": f"{kind}/{resource_name}",
            "message": message,
            "evidence": evidence,
            "remediation": remediation,
        })

    pod_security = pod_spec.get("securityContext") or {}

    if pod_security.get("runAsNonRoot") is not True:
        add(
            "RK-POD-001",
            "MEDIUM",
            "Non-root execution is not explicitly required.",
            "spec.securityContext.runAsNonRoot is not true",
            "Set runAsNonRoot: true and configure a compatible non-root user.",
        )

    if pod_spec.get("hostNetwork") is True:
        add(
            "RK-POD-002",
            "HIGH",
            "The Pod uses the host network namespace.",
            "spec.hostNetwork is true",
            "Disable host networking unless it is required and approved.",
        )

    if pod_spec.get("hostPID") is True:
        add(
            "RK-POD-003",
            "HIGH",
            "The Pod shares the host process namespace.",
            "spec.hostPID is true",
            "Disable hostPID unless there is a documented requirement.",
        )

    if pod_spec.get("hostIPC") is True:
        add(
            "RK-POD-004",
            "HIGH",
            "The Pod shares the host IPC namespace.",
            "spec.hostIPC is true",
            "Disable hostIPC unless it is required and approved.",
        )

    volumes = pod_spec.get("volumes") or []
    for volume in volumes:
        if not isinstance(volume, dict):
            continue

        host_path = volume.get("hostPath")
        if host_path:
            path = host_path.get("path", "unspecified")
            add(
                "RK-POD-005",
                "HIGH",
                "The Pod mounts a path from the host.",
                f"spec.volumes contains hostPath: {path}",
                "Prefer a suitable Kubernetes volume; restrict hostPath mounts when unavoidable.",
            )

    for container_type in ("containers", "initContainers", "ephemeralContainers"):
        containers = pod_spec.get(container_type) or []

        for container in containers:
            if not isinstance(container, dict):
                continue

            container_name = container.get("name", "unnamed")
            security = container.get("securityContext") or {}
            prefix = f"{container_type}[{container_name}]"

            if security.get("privileged") is True:
                add(
                    "RK-CTR-001",
                    "HIGH",
                    f"Container {container_name} is privileged.",
                    f"{prefix}.securityContext.privileged is true",
                    "Disable privileged mode unless there is a documented, tightly controlled need.",
                )

            if security.get("allowPrivilegeEscalation") is True:
                add(
                    "RK-CTR-002",
                    "HIGH",
                    f"Container {container_name} allows privilege escalation.",
                    f"{prefix}.securityContext.allowPrivilegeEscalation is true",
                    "Set allowPrivilegeEscalation: false where compatible.",
                )

            if security.get("runAsUser") == 0:
                add(
                    "RK-CTR-003",
                    "HIGH",
                    f"Container {container_name} explicitly runs as root.",
                    f"{prefix}.securityContext.runAsUser is 0",
                    "Use a dedicated non-root user and verify application compatibility.",
                )

            if security.get("readOnlyRootFilesystem") is not True:
                add(
                    "RK-CTR-004",
                    "LOW",
                    f"Container {container_name} does not explicitly use a read-only root filesystem.",
                    f"{prefix}.securityContext.readOnlyRootFilesystem is not true",
                    "Enable readOnlyRootFilesystem: true where the application permits it.",
                )

            capabilities = security.get("capabilities") or {}
            added_capabilities = set(capabilities.get("add") or [])
            dangerous = added_capabilities.intersection({
                "SYS_ADMIN",
                "SYS_PTRACE",
                "NET_ADMIN",
                "DAC_OVERRIDE",
            })

            for capability in sorted(dangerous):
                add(
                    "RK-CTR-005",
                    "HIGH",
                    f"Container {container_name} adds capability {capability}.",
                    f"{prefix}.securityContext.capabilities.add includes {capability}",
                    f"Remove {capability} unless the workload has a justified requirement.",
                )

            resources = container.get("resources") or {}
            limits = resources.get("limits") or {}

            if not limits.get("cpu") or not limits.get("memory"):
                add(
                    "RK-CTR-006",
                    "LOW",
                    f"Container {container_name} lacks an explicit CPU or memory limit.",
                    f"{prefix}.resources.limits does not specify both cpu and memory",
                    "Define appropriate CPU and memory limits based on workload testing.",
                )

    return findings
