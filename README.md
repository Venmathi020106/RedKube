# RedKube
### Kubernetes Attack-Path Emulation & Detection Lab

RedKube is a Python-based defensive security project that audits
Kubernetes YAML manifests for risky workload settings and RBAC
configurations. It prioritizes findings and builds a graph of
configuration relationships for security review.

> RedKube analyzes configuration files. Its findings and potential
> paths are not proof of a live vulnerability, successful exploitation,
> or a confirmed compromise.

## Features

- Kubernetes Pod and workload security checks
- Detection of privileged containers and root execution
- Host namespace and hostPath checks
- Dangerous Linux capability checks
- CPU and memory limit checks
- RBAC wildcard permission detection
- Detection of ClusterRoleBinding references to cluster-admin
- Default ServiceAccount binding checks
- Severity-based risk scoring
- Text and JSON scan reports
- Resource relationship graph exported as JSON
- Mermaid flowchart export for documentation
- Automated tests with pytest

## Requirements

- Python 3.10 or newer
- PyYAML
- NetworkX
- pytest (for development and testing)

## Setup

Activate your virtual environment, then install the dependencies:

```bash
python -m pip install PyYAML networkx pytest
```

## Run a scan

```bash
PYTHONPATH=src python -m redkube scan examples/
```

Export a JSON scan report:

```bash
PYTHONPATH=src python -m redkube scan examples/ \
  --format json --output reports/scan-report.json
```

## Export the relationship graph

```bash
PYTHONPATH=src python -m redkube graph examples/ \
  --output reports/attack-graph.json
```

Export Mermaid diagram source:

```bash
python scripts/export_mermaid.py \
  reports/attack-graph.json reports/attack-graph.mmd
```

## Run tests

```bash
PYTHONPATH=src pytest -v
```

## Risk scoring

RedKube currently uses baseline severity scores:

| Severity | Score |
|---|---:|
| Critical | 100 |
| High | 75 |
| Medium | 50 |
| Low | 25 |
| Informational or unknown | 10 |

These scores are a prioritization aid, not CVSS scores.

## Project structure

```text
redkube/
├── examples/
│   ├── risky-pod.yaml
│   └── risky-rbac.yaml
├── reports/
├── scripts/
│   └── export_mermaid.py
├── src/redkube/
│   ├── main.py
│   ├── rules.py
│   ├── rbac.py
│   ├── scanner.py
│   ├── risk.py
│   ├── graph.py
│   └── cli.py
└── tests/
```

## Safety

The example manifests are intentionally risky test fixtures. Do not
apply them to a real cluster. Test only against files and environments
you are authorized to assess.

## Roadmap

- Expand graph relationship analysis and validation
- Improve structured and HTML reporting
- Add tests for additional Kubernetes resource types
- Improve packaging and command-line installation
