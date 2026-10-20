from redkube.graph import build_attack_graph


def test_graph_contains_rbac_relationships():
    result = build_attack_graph("examples/risky-rbac.yaml")

    assert not result["errors"]
    relationships = {edge["relationship"] for edge in result["edges"]}

    assert "SUBJECT_OF_BINDING" in relationships
    assert "REFERENCES_ROLE" in relationships
    assert "GRANTS_WILDCARD_PERMISSION" in relationships


def test_graph_marks_cluster_admin_path_as_potential():
    result = build_attack_graph("examples/risky-rbac.yaml")

    assert any(
        path["status"] == "potential_configuration_path"
        for path in result["potential_paths"]
    )


def test_graph_reports_missing_path():
    result = build_attack_graph("examples/does-not-exist.yaml")

    assert result["nodes"] == []
    assert result["errors"]
