
from redkube.rules import check_pod_security


def test_detects_host_access_and_dangerous_capability():
    document = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "risky-demo"},
        "spec": {
            "hostNetwork": True,
            "hostPID": True,
            "volumes": [
                {"name": "host-data", "hostPath": {"path": "/var/log"}}
            ],
            "containers": [
                {
                    "name": "app",
                    "image": "example:1.0",
                    "securityContext": {
                        "capabilities": {"add": ["SYS_ADMIN"]}
                    },
                }
            ],
        },
    }

    findings = check_pod_security(document)
    rule_ids = {finding["rule_id"] for finding in findings}

    assert "RK-POD-002" in rule_ids
    assert "RK-POD-003" in rule_ids
    assert "RK-POD-005" in rule_ids
    assert "RK-CTR-005" in rule_ids


def test_ignores_unrelated_resource_kind():
    document = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "app-config"},
        "data": {"MODE": "test"},
    }

    assert check_pod_security(document) == []


def test_detects_deployment_container_settings():
    document = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "web"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "web",
                            "securityContext": {"privileged": True},
                        }
                    ]
                }
            }
        },
    }

    findings = check_pod_security(document)

    assert any(
        finding["rule_id"] == "RK-CTR-001"
        for finding in findings
    )
