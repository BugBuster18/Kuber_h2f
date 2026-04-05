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
- **Offline / From Snapshot Mode (Recommended)**:
  ```bash
  python main.py full-report --input snapshot.json --output report.txt
  ```
- **Live Cluster Mode**:
  ```bash
  python main.py full-report --kubectl --output-json report.json
  ```

### `rbac-audit`
Identifies dangerous RBAC configurations (wildcards, cluster-admin, etc.).
- **From JSON Mode (Fastest)**:
  ```bash
  python main.py rbac-audit --input cluster.json -o rbac-audit.txt
  ```

---

## 🛠️ 3. Targeted Analysis Tools

### `shortest-path`
Finds the single most dangerous (minimum-weight) path between two nodes. 
- **Example**: `python main.py shortest-path --input data.json -s "internet" -t "secret-db"`

### `node-risk` & `critical-node`
Identifies high-impact nodes and chokepoints.
- **Example**: `python main.py node-risk --input data.json --top 10`

---

## 📦 4. Data Persistence & Frontend

### `export-graph`
Captures the live cluster state (inclusive of NVD enrichment) to a persistent JSON file.
- **Usage**: `python main.py export-graph --kubectl -o master-snapshot.json`

### `export-frontend`
Translates your security graph into the `graph-data.json` required by the D3 visualizer.
- **Usage (Recommended)**:
  ```bash
  # Build the frontend data from your existing snapshot
  python main.py export-frontend --input master-snapshot.json
  ```
- **Viewing**: Open **`visualizer/index.html`** in your browser. (No Python needed after this step).

---

## 🧠 5. Intelligence Toggles (v2.0)
- **`--enrich / --no-enrich`**: Fetch live NIST NVD scores. (Smart Default: Enabled for kubectl, Disabled for JSON).
- **`--cvss-weights / --no-cvss-weights`**: Favor high-severity exploits in pathfinding.

---

## ⚖️ 6. Industry Risk Model
**Risk = (Likelihood / 10.0) * Impact**
All nodes now store these separate components for transparent risk reasoning.

---

## 🧪 7. Validation
### `run-tests`
Runs the built-in 13-test validation suite to ensure algorithm accuracy.
```bash
python main.py run-tests
```

---

## 🕰️ 8. Temporal Analysis (Bonus 3)

KubeAttackViz v2.0 includes a sophisticated temporal analysis system to track cluster changes over time and alert on new attack vectors.

### Continuous Monitoring (Watch)
Monitor the cluster in real-time. It captures snapshots, diffs them, and alerts you if a new attack path is created.
```powershell
# Watch live cluster every 5 minutes
python main.py watch --interval 300 --source kubectl

# Watch with Neo4j export enabled
python main.py watch --interval 60 --source kubectl --neo4j-uri bolt://localhost:7687
```

### Manual Snapshots
Capture a point-in-time state of the cluster.
```powershell
# Snapshot live cluster
python main.py temporal-snapshot --kubectl

# Snapshot from a specific JSON file
python main.py temporal-snapshot --input cluster-graph.json
```

### History & Replay
View all stored snapshots and replay the diffs between them.
```powershell
# View snapshot list
python main.py temporal-history

# Recompute and show all diffs/alerts in history
python main.py temporal-history --diff-all
```

### Neo4j Visualization
The `watch`, `diff`, and `temporal-snapshot` commands all support the `--neo4j-uri` flag. This exports:
- **Snapshots**: Point-in-time nodes.
- **DiffEvents**: Structural changes (Added/Removed nodes and edges).
- **Alerts**: Security alerts linked to the specific change that triggered them.
- **Attack Paths**: Visualized as chains in Neo4j (NEW/REMOVED).
