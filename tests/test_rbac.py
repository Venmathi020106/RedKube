
from redkube.rbac import check_rbac_security


def test_detects_wildcard_permissions():
    document = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "broad-role"},
        "rules": [
            {
                "apiGroups": ["*"],
                "resources": ["*"],
                "verbs": ["*"],
            }
        ],
    }

    findings = check_rbac_security(document)
    rule_ids = {item["rule_id"] for item in findings}

    assert "RK-RBAC-001" in rule_ids
    assert "RK-RBAC-002" in rule_ids


def test_detects_cluster_admin_binding():
    document = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "admin-binding"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "cluster-admin",
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": "default",
                "namespace": "default",
            }
        ],
    }

    findings = check_rbac_security(document)
    rule_ids = {item["rule_id"] for item in findings}

    assert "RK-RBAC-003" in rule_ids
    assert "RK-RBAC-004" in rule_ids


def test_ignores_narrow_rbac_role():
    document = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "read-config"},
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["configmaps"],
                "verbs": ["get"],
            }
        ],
    }

    assert check_rbac_security(document) == []
