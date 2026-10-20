from redkube.main import audit_document


def test_detects_risky_pod_settings():
    document = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "test-pod"},
        "spec": {
            "containers": [
                {
                    "name": "test-container",
                    "image": "nginx:latest",
                    "securityContext": {
                        "privileged": True,
                        "runAsUser": 0,
                        "allowPrivilegeEscalation": True,
                    },
                }
            ]
        },
    }

    findings = audit_document(document)
    rule_ids = {finding[1] for finding in findings}

    assert rule_ids == {
        "POD-001",
        "CTR-001",
        "CTR-002",
        "CTR-003",
        "CTR-004",
    }


def test_accepts_hardened_pod_configuration():
    document = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "hardened-pod"},
        "spec": {
            "securityContext": {"runAsNonRoot": True},
            "containers": [
                {
                    "name": "app",
                    "image": "nginx:latest",
                    "securityContext": {
                        "privileged": False,
                        "runAsUser": 10001,
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                    },
                }
            ],
        },
    }

    assert audit_document(document) == []
