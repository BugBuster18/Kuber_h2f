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
Runs the built-in 31-test validation suite to ensure algorithm accuracy.
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

---

## 🧠 9. Learned Edge Weights (ML)
Replace static edge weights with `-ln P(success)` from models trained on real CVE data.
```bash
python main.py ml-fetch-data                       # CISA KEV + NVD + EPSS → data/raw/
python main.py ml-train                            # train + write artifacts/MODEL_CARD.md
python main.py ml-info                             # metrics and provenance
python main.py ml-edges -i cluster.json            # learned vs static weight per edge
python main.py --weights learned full-report -i cluster.json
KAV_WEIGHTS=learned python main.py diff old.json new.json
```
Add `--online-cve` to fetch NVD records for CVEs not in the shipped score table.

---

## 🎬 10. Presentation Views (old vs ML weights, sample + live cluster)

The single entry point is `./demo/present.sh`: pick a cluster, then option 4. The script can also be run on its own:

```bash
./demo/views.sh            # live cluster = kav-prod (default)
./demo/views.sh bench      # live cluster = the public benchmark (Kubernetes Goat + Bad Pods)
./demo/views.sh dev        # use kav-dev as the live cluster instead
./demo/stop.sh             # stop the dashboard server afterwards
```

Starts the dashboard server, opens the browser, and shows a menu. Each key switches the browser view within a second:

| Key | View |
|---|---|
| `1` | Sample cluster (`mock-cluster-graph.json`) · old weights (paper-style, hand-set) |
| `2` | Sample cluster · ML weights (weight = −ln P(success)) |
| `3` | Live cluster · old weights |
| `4` | Live cluster · ML weights |

* The same four buttons are at the bottom of the graph in the browser.
* Top-4 paths are coloured #1 red, #2 orange, #3 purple, #4 green.
* Every path card shows its rank under the other weights (e.g. `▲ was #4 with old weights`).
* Old and ML views of one cluster use exactly the same node positions, so only the highlighted paths change.
* Views 3–4 rescan the live cluster every 15 s. A change shows up on its own, e.g.
  `./demo/drift.sh prod admin-sa` (undo with `./demo/drift.sh prod admin-sa revert`).

Under the hood: `python main.py --weights learned --scan-images serve --context kind-kav-prod --demo-sample mock-cluster-graph.json`
(API: `GET /api/demo`, `GET /api/demo/graph?view=N`, `POST /api/demo/view?view=N`).

---

## 📏 11. Benchmark: our paths vs documented attack paths

```bash
./demo/present.sh                                         # pick kav-bench, then option 5
# or directly:
./demo/setup.sh bench                                     # once: kind-kav-bench with Kubernetes Goat + Bad Pods
python main.py --scan-images benchmark -c kind-kav-bench  # compare
```

* **Input:** unmodified public manifests ([Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) and [Bad Pods](https://github.com/BishopFox/badPods)). The answer key is `demo/benchmark/expected.yaml`: every documented attack, with a link to where it is documented.
* **Output:** for each attack, under old weights and under ML weights:
  * whether we found the path;
  * its rank among all attack paths in the cluster;
  * for Bad Pods, whether we claim the pod can reach its node.
* Results are saved to `data/benchmark/latest.json`. Details are in `demo/benchmark/README.md`.
* **Live view:** after option 5, press Enter (or run `VIEW=4 TAB=bench ./demo/views.sh bench`). The dashboard opens at <http://127.0.0.1:8765/?tab=bench> on kav-bench with a **Benchmark: Goat + Bad Pods** tab: the same table, a source link per attack, and a click on a row highlights that documented path in the graph. Keys 3/4 switch old/ML weights (API: `GET /api/benchmark`).
