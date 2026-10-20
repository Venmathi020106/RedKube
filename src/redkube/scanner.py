
"""File and directory scanning for RedKube."""

from pathlib import Path
from typing import Any

import yaml

from redkube.rules import check_pod_security
from redkube.rbac import check_rbac_security


def scan_file(file_path: Path) -> dict[str, Any]:
    """Scan a YAML file and return structured results."""
    result: dict[str, Any] = {
        "file": str(file_path),
        "status": "ok",
        "findings": [],
        "error": None,
    }

    try:
        with file_path.open("r", encoding="utf-8") as stream:
            for document_number, document in enumerate(
                yaml.safe_load_all(stream), start=1
            ):
                if document is None:
                    continue

                if not isinstance(document, dict):
                    result["status"] = "error"
                    result["error"] = (
                        f"Document {document_number} must be a YAML mapping."
                    )
                    return result

                checkers = (
                    check_pod_security,
                    check_rbac_security,
                )

                for checker in checkers:
                    for finding in checker(document):
                        finding["file"] = str(file_path)
                        finding["document"] = str(document_number)
                        result["findings"].append(finding)

    except (OSError, yaml.YAMLError) as error:
        result["status"] = "error"
        result["error"] = str(error)

    return result


def scan_path(path: str | Path) -> dict[str, Any]:
    """Scan a YAML file or recursively scan a directory."""
    target = Path(path)

    if not target.exists():
        return {
            "target": str(target),
            "files_scanned": 0,
            "findings": [],
            "errors": [f"Path does not exist: {target}"],
        }

    if target.is_file():
        if target.suffix.lower() not in {".yaml", ".yml"}:
            return {
                "target": str(target),
                "files_scanned": 0,
                "findings": [],
                "errors": [
                    f"Expected a .yaml or .yml file: {target}"
                ],
            }

        files = [target]

    elif target.is_dir():
        files = sorted(
            file
            for file in target.rglob("*")
            if file.is_file()
            and file.suffix.lower() in {".yaml", ".yml"}
        )

    else:
        return {
            "target": str(target),
            "files_scanned": 0,
            "findings": [],
            "errors": [
                f"Not a regular file or directory: {target}"
            ],
        }

    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    for file_path in files:
        result = scan_file(file_path)
        findings.extend(result["findings"])

        if result["status"] == "error":
            errors.append(
                f"{file_path}: {result['error']}"
            )

    return {
        "target": str(target),
        "files_scanned": len(files),
        "findings": findings,
        "errors": errors,
    }

