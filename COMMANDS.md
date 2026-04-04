# 🛡️ KubeAttackViz v2.0 — Full Command Reference

This document provides a detailed breakdown of all available CLI commands, flags, and usage examples.

---

## 🏗️ General Usage Notes

Every analysis command (except `diff`, `run-tests`, and `dump-raw`) requires a data source:
- **`--input <file.json>`**: Point to a local JSON graph file.
- **`--kubectl`**: Query a live Kubernetes cluster.

### 🧠 Algorithm Toggle (v2.0)
Most commands now support a **CVSS Weight Intelligence** toggle:
- **`--cvss-weights` (Default)**: Automatically reduces edge weights for high-CVSS vulnerabilities. A path with a CVSS 10.0 exploit is treated as much "shorter" (easier) than a path with low-CVSS or no CVE.
- **`--no-cvss-weights`**: Disables this intelligence. Dijkstra will only use the literal `weight` numbers provided in the JSON input. Use this for pure mathematical verification against a mock dataset.

---

## 🔎 1. Core Graph Analysis

### `full-report`
Generates a comprehensive security report containing all analysis results.
- **Flags**:
  - `--input <json>` / `--kubectl`: Source data.
  - `--blast-source <id/name>`: Focus blast radius on a specific entry point.
  - `--blast-depth <int>`: Max depth for the blast radius (default: 3).
  - `--no-cvss-weights`: Skip CVSS-based weight adjustment.
  - `--export json`: Save raw results to `report.json`.
- **Example**:
  ```bash
  python main.py full-report --input mock-cluster-graph-copy.json --export json --no-cvss-weights
  ```

### `blast-radius`
Computes the "Blast Radius" (reachable nodes) from a specific source via BFS.
- **Flags**:
  - `--source <id/name>`: (Mandatory) The node to start from.
  - `--depth <int>`: Max hops (default: 3).
  - `--no-cvss-weights`: Skip CVSS-based weight adjustment.
- **Example**:
  ```bash
  python main.py blast-radius --kubectl --source "internet" --depth 5 --no-cvss-weights
  ```

### `shortest-path`
Finds the single most dangerous (minimum-weight) path between two nodes using Dijkstra.
- **Flags**:
  - `--source <id/name>`: (Mandatory) Starting node.
  - `--target <id/name>`: (Mandatory) Target node.
  - `--no-cvss-weights`: Find the shortest path using ONLY literal JSON weights.
- **Example**:
  ```bash
  python main.py shortest-path --input mock-cluster-graph-copy.json --source "dev-1" --target "production-db" --no-cvss-weights
  ```

### `cycles`
Detects privilege escalation loops where an attacker can cycle through permissions.
- **Example**:
  ```bash
  python main.py cycles --input mock-cluster-graph-copy.json
  ```

### `critical-node`
Identifies "chokepoint" nodes via graph surgery. Removing these nodes eliminates the most attack paths.
- **Flags**:
  - `--top <int>`: Number of critical nodes to list (default: 5).
  - `--no-cvss-weights`: Skip CVSS-based weight adjustment during path calculation.
- **Example**:
  ```bash
  python main.py critical-node --kubectl --top 3 --no-cvss-weights
  ```

---

## 🧠 2. Advanced v2.0 Features

### `classify`
Categorizes attack paths into types like *Privilege Escalation*, *Lateral Movement*, or *Credential Theft*.
- **Flags**:
  - `--no-cvss-weights`: Skip CVSS-based weight adjustment.
- **Example**:
  ```bash
  python main.py classify --input mock-cluster-graph-copy.json --no-cvss-weights
  ```

### `rbac-audit`
Identifies dangerous RBAC configurations (wildcards, cluster-admin, etc.).
- **Flags**:
  - `--no-cvss-weights`: Skip CVSS-based weight adjustment.
  - `--output-json <path>`: Save findings to a file.
- **Example**:
  ```bash
  python main.py rbac-audit --kubectl --no-cvss-weights
  ```

### `explain`
Generates a natural language narrative describing an attack path in plain English.
- **Flags**:
  - `--source <id/name>`: (Mandatory) Starting node.
  - `--target <id/name>`: (Mandatory) Target node.
  - `--no-cvss-weights`: Skip CVSS-based weight adjustment.
- **Example**:
  ```bash
  python main.py explain --input mock-cluster-graph-copy.json --source "dev-1" --target "production-db" --no-cvss-weights
  ```

### `node-risk`
Amplifies node risk scores based on "Path Centrality" (how many attack paths pass through them).
- **Flags**:
  - `--top <int>`: Number of results to show (default: 10).
  - `--no-cvss-weights`: Skip CVSS-based weight adjustment.
- **Example**:
  ```bash
  python main.py node-risk --input mock-cluster-graph-copy.json --no-cvss-weights
  ```

### `diff`
Compares two cluster graph snapshots to identify new/removed nodes, edges, or attack paths.
- **Usage**: `diff <old.json> <new.json>`
- **Example**:
  ```bash
  python main.py diff baseline.json current.json
  ```

---

## 🌐 3. Data & Visualization

### `export-frontend`
Generates the specialized `graph-data.json` required by the D3.js web visualizer.
- **Flags**:
  - `--output <path>`: Default is `visualizer/graph-data.json`.
  - `--no-cvss-weights`: Export graph with original literal weights.
- **Example**:
  ```bash
  # Step 1: Export
  python main.py export-frontend --input mock-cluster-graph-copy.json --no-cvss-weights
  
  # Step 2: Open browser
  # Navigate to visualizer/index.html and click "Load Demo Data"
  ```

### `export-graph`
Saves the live cluster state (from kubectl) to our **transformed graph JSON** format.
- **Example**:
  ```bash
  python main.py export-graph --kubectl --output my-snapshot.json
  ```

### `dump-raw`
Saves the **original, un-transformed JSON** from `kubectl` (diagnostic use).
- **Flags**:
  - `--output <path>`: Default is `raw-k8s-state.json`.
- **Example**:
  ```bash
  python main.py dump-raw --output raw-state.json
  ```

### `graph-info`
Provides a high-level summary of the graph (counts, types, connectivity).
- **Example**:
  ```bash
  python main.py graph-info --kubectl
  ```

### `run-tests`
Executes the built-in 13-test validation suite to verify algorithmic accuracy.
- **Example**:
  ```bash
  python main.py run-tests
  ```

---

## 🛠️ Utility Flags (Applied to App)
- **`--version` / `-v`**: Show tool version.
- **`--help`**: Show documentation for any specific command.
  *   *Example:* `python main.py shortest-path --help`
