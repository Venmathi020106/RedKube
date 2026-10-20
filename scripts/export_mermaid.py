"""Export a RedKube JSON graph as a Mermaid flowchart."""

import json
import sys
from pathlib import Path


def safe_label(value: object) -> str:
    """Make text safe for use inside a Mermaid node label."""
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("|", "&#124;")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("[", "(")
        .replace("]", ")")
    )


def export_mermaid(source: Path, destination: Path) -> None:
    data = json.loads(source.read_text(encoding="utf-8"))
    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    lines = [
        "flowchart LR",
        '  %% RedKube configuration relationship graph',
    ]

    node_ids = {}

    for index, node in enumerate(nodes):
        node_id = f"n{index}"
        node_ids[node["id"]] = node_id

        node_type = node.get("node_type", "resource")
        if node_type == "finding":
            label = (
                f"{node.get('severity', 'INFO')} "
                f"{node.get('rule_id', 'UNKNOWN')}"
            )
        elif node_type == "permission":
            label = f"Wildcard permission: {node.get('name', node['id'])}"
        else:
            label = node.get("id", "Unknown")

        lines.append(f'  {node_id}["{safe_label(label)}"]')

    for edge in edges:
        source_id = node_ids.get(edge.get("source"))
        target_id = node_ids.get(edge.get("target"))

        if source_id is None or target_id is None:
            continue

        relationship = safe_label(
            edge.get("relationship", "RELATED_TO").replace("_", " ")
        )
        lines.append(
            f"  {source_id} -->|{relationship}| {target_id}"
        )

    lines.extend([
        "",
        "  %% Potential paths are hypotheses for review, not proof of exploitation.",
    ])

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: python scripts/export_mermaid.py "
            "<input-graph.json> <output-graph.mmd>"
        )
        return 2

    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])

    if not source.is_file():
        print(f"Graph JSON file not found: {source}")
        return 2

    try:
        export_mermaid(source, destination)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Could not export graph: {error}")
        return 2

    print(f"Mermaid graph saved to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
