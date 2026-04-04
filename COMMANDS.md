# 🛡️ KubeAttackViz v2.0 — Full Command Reference

This document provides a detailed breakdown of all available CLI commands, flags, and usage examples for the production-grade Kubernetes Attack Path Visualizer.

---

## 🏗️ 1. Core Concepts & Defaults (v2.0)

### 🧠 Algorithm: Weight Intelligence
Every analysis command now supports a **CVSS Weight Intelligence** toggle:
- **`--cvss-weights` (Default)**: Automatically reduces edge weights for high-CVSS vulnerabilities. A path with a CVSS 10.0 exploit is treated as much "shorter" (easier) than a path with low-CVSS or no CVE.
- **`--no-cvss-weights`**: Disables this intelligence.

### 🌐 Live CVE Enrichment (NVD API v2.0)
- **`--enrich` (Default)**: Automatically queries the NIST NVD API for any CVE ID or Container Image found in your cluster to get real-time CVSS scores.
- **`--no-enrich`**: Skips network calls (Offline mode).

### 📊 Industry Standard Risk Model
All nodes now use a **Risk = Likelihood × Impact** model. 
- **Impact**: Determined by resource type (e.g., Secrets = 9, Databases = 10).
- **Likelihood**: Derived from exposure (`is_source`), configuration (`privileged`), and `CVSS` scores.

---

## 🔎 2. Analysis Commands

### `full-report` (The Kill Chain Audit)
Generates a comprehensive security audit. Defaults to saving a text report.
- **Flags**:
  - `--output` / `-o`: Save human-readable report (Default: `report.txt`).
  - `--output-json`: Export machine-readable results (Default: None).
  - `--no-enrich`: Skip NIST NVD real-time enrichment.
- **Example**:
  ```bash
  # Standard run (Automated CVE fetch + save to report.txt)
  python main.py full-report --kubectl

  # Full audit saved for machine ingestion
  python main.py full-report --kubectl --output-json audit.json
  ```

### `shortest-path`
Finds the single most dangerous (minimum-weight) path between two nodes.
- **Example**:
  ```bash
  python main.py shortest-path --kubectl --source "internet" --target "secret-db" --output path.txt
  ```

### `rbac-audit`
Identifies dangerous RBAC configurations (wildcards, cluster-admin, etc.).
- **Example**:
  ```bash
  python main.py rbac-audit --kubectl --output rbac-audit.txt
  ```

### `node-risk`
Amplifies risk scores based on "Path Centrality" (how many attack paths pass through them).
- **Example**:
  ```bash
  python main.py node-risk --kubectl --top 10 --output risk-map.txt
  ```

### `blast-radius`
Computes the "Blast Radius" (reachable nodes) from a specific source via BFS.
- **Example**:
  ```bash
  python main.py blast-radius --kubectl --source "internet" --depth 4 -o radius.txt
  ```

---

## 📦 3. Data & Persistence

### `export-graph`
Saves the live cluster state (from kubectl) to our transformed JSON format. 
**Note:** Since `--enrich` is default, this JSON will have NIST CVSS scores baked into it!
- **Example**:
  ```bash
  python main.py export-graph --kubectl --output master-snapshot.json
  ```

### `export-frontend`
Generates the specialized `graph-data.json` required by the D3.js web visualizer.
- **Example**:
  ```bash
  python main.py export-frontend --kubectl --output visualizer/graph-data.json
  ```

### `diff`
Compares two cluster graph snapshots to identify security regressions.
- **Usage**: `diff <old.json> <new.json>`
- **Example**:
  ```bash
  python main.py diff baseline.json current.json
  ```

### `dump-raw`
Queries core resources and dumps the raw, un-transformed JSON for diagnostics.
- **Example**:
  ```bash
  python main.py dump-raw --output raw-k8s-state.json
  ```

---

## 🧪 4. Validation
Run the built-in test suite to ensure graph algorithms are functioning correctly.
```bash
python main.py run-tests
```
