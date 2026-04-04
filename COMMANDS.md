# 🛡️ KubeAttackViz v2.0 — Full Command Reference

This document provides the exhaustive breakdown of all CLI commands, including both **Live Cluster** and **Offline (JSON)** usage modes.

---

## 🏗️ 1. Global Data Source Modes
Almost every command requires one of these to provide context:
- **`--kubectl` / `-k`**: Directly query the live Kubernetes cluster.
- **`--input <file.json>` / `-i`**: Use a previously exported JSON attack graph.

---

## 🔎 2. Core Security Audits

### `full-report` (The Kill Chain Audit)
Generates a comprehensive security audit. 
- **Live Cluster Mode**:
  ```bash
  python main.py full-report --kubectl --output-json report.json
  ```
- **Offline / From Snapshot Mode**:
  ```bash
  python main.py full-report --input snapshot.json --output report.txt
  ```

### `rbac-audit`
Identifies dangerous RBAC configurations (wildcards, cluster-admin, etc.).
- **Live Cluster Mode**:
  ```bash
  python main.py rbac-audit --kubectl -o rbac.txt
  ```
- **From JSON Mode**:
  ```bash
  python main.py rbac-audit --input cluster.json -o rbac-audit.txt
  ```

---

## 🛠️ 3. Targeted Analysis Tools

### `shortest-path`
Finds the single most dangerous (minimum-weight) path between two nodes. 
- **Offline Mode Example**:
  ```bash
  python main.py shortest-path --input data.json -s "internet" -t "secret-db"
  ```

### `blast-radius`
Computes all nodes reachable from a specific entry point via BFS.
- **Offline Mode Example**:
  ```bash
  python main.py blast-radius --input snapshot.json -s "internet" --depth 4
  ```

### `node-risk`
Amplifies risk scores based on "Path Centrality" (how many attack paths pass through them).
- **Offline Mode Example**:
  ```bash
  python main.py node-risk --input data.json --top 10
  ```

### `cycles`
Detects privilege escalation loops using Depth-First Search (DFS).
- **Offline Mode Example**:
  ```bash
  python main.py cycles --input snapshot.json
  ```

---

## 📦 4. Data Persistence & Tooling

### `export-graph`
Saves the live cluster state (inclusive of NVD enrichment) to a persistent JSON file.
- **Usage**: `python main.py export-graph --kubectl -o master-snapshot.json`

### `export-frontend`
Generates the specialized `graph-data.json` required by the D3.js web visualizer.
- **Usage**: `python main.py export-frontend --kubectl -o visualizer/graph-data.json`

### `diff`
Compares two cluster graph snapshots to identify security regressions.
- **Usage**: `diff <old.json> <new.json>`
- **Example**: `python main.py diff baseline.json current.json`

---

## 🧠 5. Intelligence Toggles (v2.0)
These flags are available on nearly all analysis commands.

| Flag | Default | Description |
| :--- | :--- | :--- |
| **`--enrich / --no-enrich`** | **Enrich** | Fetch live scores from NIST NVD API for any CVE/Image found. |
| **`--cvss-weights / --no-cvss-weights`** | **Weights** | Automatically reduce edge weights for high-severity vulnerabilities. |

---

## ⚖️ 6. Industry Risk Model
**Risk = (Likelihood / 10.0) * Impact**
- **Impact:** Inherent value of the resource (e.g., Database = 10, Secret = 9).
- **Likelihood:** Probability of exploit based on exposure, configuration, and CVSS.

---

## 🧪 7. Validation
### `run-tests`
Runs the built-in validation suite to ensure algorithm and risk engine accuracy.
- **Example**: `python main.py run-tests`
