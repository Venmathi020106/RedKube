"""Build an evidence-based relationship graph from Kubernetes YAML."""

from pathlib import Path
from typing import Any

import networkx as nx
import yaml


def _resource_id(kind: str, name: str, namespace: str = "") -> str:
    """Create a stable ID for a Kubernetes resource."""
    return f"{kind}/{namespace + '/' if namespace else ''}{name}"


def build_attack_graph(path: str | Path) -> dict[str, Any]:
    """Build a static graph of resource relationships and security findings.

    Potential paths are configuration-based leads for review, not proof
    of exploitability or confirmed compromise.
    """
    target = Path(path)
    graph = nx.DiGraph()
    errors: list[str] = []

    if not target.exists():
        return {
            "target": str(target),
            "nodes": [],
            "edges": [],
            "potential_paths": [],
            "errors": [f"Path does not exist: {target}"],
        }

    if target.is_file():
        files = [target] if target.suffix.lower() in {".yaml", ".yml"} else []
    elif target.is_dir():
        files = sorted(
            item for item in target.rglob("*")
            if item.is_file() and item.suffix.lower() in {".yaml", ".yml"}
        )
    else:
        files = []

    for file_path in files:
        try:
            with file_path.open("r", encoding="utf-8") as stream:
                documents = yaml.safe_load_all(stream)
                for document in documents:
                    if not isinstance(document, dict):
                        continue

                    kind = document.get("kind")
                    metadata = document.get("metadata") or {}
                    name = metadata.get("name")
                    namespace = metadata.get("namespace", "")

                    if not kind or not name:
                        continue

                    resource_id = _resource_id(kind, name, namespace)
                    graph.add_node(
                        resource_id,
                        kind=kind,
                        name=name,
                        namespace=namespace,
                        source=str(file_path),
                        node_type="resource",
                    )

                    # Connect RBAC bindings to their subjects and referenced roles.
                    if kind in {"RoleBinding", "ClusterRoleBinding"}:
                        role_ref = document.get("roleRef") or {}
                        role_kind = role_ref.get("kind", "Role")
                        role_name = role_ref.get("name")

                        if role_name:
                            role_id = _resource_id(
                                role_kind,
                                role_name,
                                namespace if role_kind == "Role" else "",
                            )
                            graph.add_node(
                                role_id,
                                kind=role_kind,
                                name=role_name,
                                node_type="referenced_resource",
                            )
                            graph.add_edge(
                                resource_id,
                                role_id,
                                relationship="REFERENCES_ROLE",
                            )

                        for subject in document.get("subjects") or []:
                            subject_kind = subject.get("kind", "Unknown")
                            subject_name = subject.get("name")
                            subject_ns = subject.get("namespace", namespace)

                            if not subject_name:
                                continue

                            subject_id = _resource_id(
                                subject_kind, subject_name, subject_ns
                            )
                            graph.add_node(
                                subject_id,
                                kind=subject_kind,
                                name=subject_name,
                                namespace=subject_ns,
                                node_type="identity",
                            )
                            graph.add_edge(
                                subject_id,
                                resource_id,
                                relationship="SUBJECT_OF_BINDING",
                            )

                    # Mark broad permissions on roles as review-worthy edges.
                    if kind in {"Role", "ClusterRole"}:
                        for index, rule in enumerate(document.get("rules") or []):
                            if not isinstance(rule, dict):
                                continue

                            verbs = rule.get("verbs") or []
                            resources = rule.get("resources") or []
                            api_groups = rule.get("apiGroups") or []

                            if "*" in verbs or "*" in resources or "*" in api_groups:
                                permission_id = (
                                    f"WildcardPermission/{name}/{index}"
                                )
                                graph.add_node(
                                    permission_id,
                                    node_type="permission",
                                    verbs=verbs,
                                    resources=resources,
                                    apiGroups=api_groups,
                                )
                                graph.add_edge(
                                    resource_id,
                                    permission_id,
                                    relationship="GRANTS_WILDCARD_PERMISSION",
                                )

        except (OSError, yaml.YAMLError) as error:
            errors.append(f"{file_path}: {error}")

    # Add scanner findings to the graph.
    from redkube.scanner import scan_path

    scan_result = scan_path(target)
    errors.extend(scan_result.get("errors", []))

    for index, finding in enumerate(scan_result.get("findings", []), start=1):
        resource = finding.get("resource", "Unknown resource")
        finding_id = f"Finding/{finding.get('rule_id', 'UNKNOWN')}/{index}"

        graph.add_node(
            finding_id,
            node_type="finding",
            rule_id=finding.get("rule_id", "UNKNOWN"),
            severity=finding.get("severity", "INFO"),
            message=finding.get("message", ""),
            risk_score={
                "CRITICAL": 100,
                "HIGH": 75,
                "MEDIUM": 50,
                "LOW": 25,
            }.get(str(finding.get("severity", "INFO")).upper(), 10),
        )

        # Match findings to resources by their Kind/name label.
        matched_resource = None
        for node_id, attributes in graph.nodes(data=True):
            if attributes.get("node_type") != "resource":
                continue
            expected = f"{attributes.get('kind')}/{attributes.get('name')}"
            if resource == expected:
                matched_resource = node_id
                break

        if matched_resource:
            graph.add_edge(
                matched_resource,
                finding_id,
                relationship="HAS_FINDING",
            )

    # Report only configuration-based candidate paths.
    potential_paths = []
    for subject, binding, role in (
        (source, middle, destination)
        for source, middle, edge1 in graph.edges(data=True)
        if edge1.get("relationship") == "SUBJECT_OF_BINDING"
        for _, destination, edge2 in graph.out_edges(middle, data=True)
        if edge2.get("relationship") == "REFERENCES_ROLE"
    ):
        role_attributes = graph.nodes[role]
        if role_attributes.get("name") == "cluster-admin":
            potential_paths.append({
                "nodes": [subject, binding, role],
                "reason": "Binding references the cluster-admin role.",
                "status": "potential_configuration_path",
            })

    nodes = [
        {"id": node_id, **attributes}
        for node_id, attributes in graph.nodes(data=True)
    ]
    edges = [
        {"source": source, "target": destination, **attributes}
        for source, destination, attributes in graph.edges(data=True)
    ]

    return {
        "target": str(target),
        "nodes": nodes,
        "edges": edges,
        "potential_paths": potential_paths,
        "errors": sorted(set(errors)),
    }
