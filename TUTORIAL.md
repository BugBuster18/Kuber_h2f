# KubeAttackViz — Tutorial: From `git clone` to a Live Demo

This guide takes you from a fresh clone to a running three-cluster demo with ML-weighted attack
paths in your terminal and browser. Each step says **what to run** and **what you should see**.

| Part | What you get | Time | Needs |
|---|---|---|---|
| [1. Set up Python](#1-set-up-python) | the tool installed, tests passing | 5 min | Python |
| [2. Analyse sample graphs](#2-analyse-sample-graphs-offline) | reports, attack paths, ML weights — no cluster needed | 5 min | Part 1 |
| [3. Open the browser view](#3-open-the-browser-view) | interactive graph and dashboard | 2 min | Part 2 |
| [4. Install the cluster tools](#4-install-the-cluster-tools) | Docker, kind, kubectl, Trivy | 10–15 min | Linux/macOS/WSL2 |
| [5. Create the demo clusters](#5-create-the-three-demo-clusters) | three real Kubernetes clusters | 5–10 min | Part 4 |
| [6. Run the demo](#6-run-the-demo) | interactive menu, live monitor, browser dashboard | — | Part 5 |
| [7. Optional extras](#7-optional-extras) | retrain the model, validate against a real cluster | 5–25 min | Part 5 |

Parts 1–3 work on any machine. Parts 4–7 need Docker.

---

## 0. Requirements

| | Minimum | Notes |
|---|---|---|
| OS | Linux, macOS, or Windows with **WSL2** | Commands below are for Linux (x86-64); macOS differences are noted |
| Python | **3.10+** | tested with 3.13 |
| RAM | 8 GB (16 GB recommended) | each demo cluster uses about 0.8 GB |
| Disk | ~5 GB free | cluster node images, container images, Trivy database |
| Network | needed for installs, image pulls and the first Trivy scan | analysis itself works offline |

---

## 1. Set up Python

```bash
git clone https://github.com/BugBuster18/Kuber_h2f.git
cd Kuber_h2f
git checkout v5            # or whichever branch contains this version

python3 -m venv .venv
source .venv/bin/activate  # Windows WSL/Linux/macOS; on PowerShell: .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

Installed packages: `networkx` (graph algorithms), `typer` + `rich` (CLI and colours), `requests`
(NVD API), `scikit-learn` / `numpy` / `pandas` / `joblib` (ML model), `neo4j` (optional export).

> **scikit-learn version.** The shipped model was trained with scikit-learn **1.7.2**. If you see a
> version warning or the model fails to load, run `pip install "scikit-learn==1.7.2"` — or retrain
> it yourself (§7.1).

**Check the installation:**

```bash
python main.py run-tests
```

✅ **Expect:** 31 lines starting with `✅ PASS`, ending with

```
  Results: 31/31 passed, 0 failed
  🎉 ALL TESTS PASSED
```

```bash
python main.py --help
```

✅ **Expect:** a list of 26 commands (`full-report`, `shortest-path`, `serve`, `analyze`, `ml-edges`, …).

---

## 2. Analyse sample graphs (offline)

The repository ships sample cluster graphs, so you can try everything without Kubernetes.

### 2.1 Full report with the classic (static) weights

```bash
python main.py full-report -i mock-cluster-graph.json
```

✅ **Expect** a long colour report that starts with:

```
✓ Graph loaded: 41 nodes, 48 edges
...
  ATTACK PATHS (Sorted by Risk — Most Dangerous First)
  ─── Path #1 ───
  Path: loadbalancer-svc → api-server → sa-worker → pod-exec → worker-node-1
  Hops: 4 | Risk: 4.57/10 | Cost: 9.68 | Severity: MEDIUM
```

followed by remediation, blast radius, cycles, chokepoints, classification, RBAC audit, a
plain-English explanation and an executive summary. The same text is saved to `report.txt`.

### 2.2 The same graph with ML-learned weights

```bash
python main.py --weights learned full-report -i mock-cluster-graph.json
```

✅ **Expect** `(LEARNED weights: -ln P(success))` after "Graph loaded", and a different ranking:

```
  Path: cicd-bot → sa-cicd → cicd-deploy-token → production-db
  Hops: 3 | Risk: 5.24/10 | Cost: 0.65 | P(success): 52.4% | Severity: CRITICAL
```

Each path now has a **probability of success**, and the risk is *impact × probability*. The
credential chain rises to the top because it needs no exploit.

### 2.3 Individual analyses

```bash
python main.py --weights learned shortest-path -i mock-cluster-graph.json -s internet -t production-db
python main.py blast-radius -i mock-cluster-graph.json -s internet --depth 3
python main.py critical-node -i mock-cluster-graph.json
python main.py cycles -i mock-cluster-graph.json
python main.py rbac-audit -i mock-cluster-graph.json
python main.py explain -i mock-cluster-graph.json -s internet -t production-db
python main.py ml-edges -i mock-cluster-graph.json      # probability and weight of every edge
python main.py ml-info                                   # model card: data, metrics, limitations
```

✅ **Expect** for `shortest-path`: the path, then a natural-language explanation and remediation;
for `critical-node`: `#1 web-frontend` removing the most of 46 paths; for `ml-info`: a metrics table
in which the deployed gradient-boosting model has ROC-AUC 0.887.

### 2.4 Before/after a change (temporal diff)

```bash
python main.py --weights learned diff presentation-cluster.json presentation-cluster-drift.json
```

✅ **Expect** new nodes (`dev-debug-pod`, `debug-cluster-admin-binding`), a changed attack route
marked `▲ EASIER`, a causal explanation of what made it easier, and an alert.

---

## 3. Open the browser view

```bash
python main.py --weights learned export-frontend -i mock-cluster-graph.json
cd visualizer && python -m http.server 8080
```

Open **http://localhost:8080** in a browser. Stop the server with `Ctrl+C`, then `cd ..`.

✅ **Expect:**
- **Graph** tab — the attack graph; a `v2.0 · ML weights` badge; path cards on the right with
  `Risk` and `P` (probability). Click a path card to highlight it; click a node for its details.
- **Dashboard** tab — posture score, blast radius per entry point, chokepoints, a table of all
  paths with a `P(success)` column.
- **Timeline** tab — click **Load Timeline** to see a recorded change between two snapshots.
- The search bar accepts questions such as *"How can internet reach production-db?"*.

---

## 4. Install the cluster tools

### 4.1 Docker

Install Docker Engine (Linux) or Docker Desktop (macOS/Windows):
<https://docs.docker.com/get-docker/>

On Linux, allow your user to run Docker without `sudo`, then **log out and back in**:

```bash
sudo usermod -aG docker "$USER"
```

✅ **Check:** `docker run --rm hello-world` prints "Hello from Docker!".

### 4.2 kubectl

Official instructions: <https://kubernetes.io/docs/tasks/tools/>. On Linux x86-64:

```bash
mkdir -p ~/.local/bin
cd /tmp
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl.sha256"
echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check      # must print: kubectl: OK
install -m 0755 kubectl ~/.local/bin/kubectl
cd -
```

macOS: `brew install kubectl`.

### 4.3 kind (Kubernetes in Docker)

Official instructions: <https://kind.sigs.k8s.io/docs/user/quick-start/#installation>.
On Linux x86-64 (this project was tested with v0.33.0):

```bash
cd /tmp
curl -Lo kind https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64
curl -Lo kind.sha256sum https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64.sha256sum
echo "$(cut -d' ' -f1 kind.sha256sum)  kind" | sha256sum --check  # must print: kind: OK
install -m 0755 kind ~/.local/bin/kind
cd -
```

macOS: `brew install kind`.

### 4.4 Trivy (container image scanner — recommended)

Official project and install options: <https://github.com/aquasecurity/trivy>.
On Linux x86-64 (tested with v0.76.1):

```bash
cd /tmp
V=0.76.1
curl -LO https://github.com/aquasecurity/trivy/releases/download/v$V/trivy_${V}_Linux-64bit.tar.gz
curl -LO https://github.com/aquasecurity/trivy/releases/download/v$V/trivy_${V}_checksums.txt
grep " trivy_${V}_Linux-64bit.tar.gz$" trivy_${V}_checksums.txt | sha256sum --check   # must print: ... OK
tar -xzf trivy_${V}_Linux-64bit.tar.gz trivy
install -m 0755 trivy ~/.local/bin/trivy
cd -
```

macOS: `brew install trivy`. Without Trivy everything still works, but pods get no image CVEs, so
fewer edges use the ML model.

### 4.5 Make sure `~/.local/bin` is on your PATH

```bash
echo $PATH | tr ':' '\n' | grep -x "$HOME/.local/bin" || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc     # zsh users: use ~/.zshrc
```

✅ **Check all tools:**

```bash
docker version --format '{{.Server.Version}}'
kubectl version --client
kind version
trivy --version
```

### 4.6 Optional

- **kitty** terminal (<https://sw.kovidgoyal.net/kitty/>) — `./demo/start.sh` opens a multi-pane
  layout in it. Without kitty, use `./demo/present.sh` or `./demo/start.sh --here`.
- **Google Chrome** — opened automatically for the dashboard; otherwise your default browser is
  used via `xdg-open`.

---

## 5. Create the three demo clusters

```bash
./demo/setup.sh            # all three; or: ./demo/setup.sh dev
```

This creates three local Kubernetes clusters with kind and deploys the demo application. The
first run downloads the Kubernetes node image (~500 MB) and the container images.

✅ **Expect** (5–10 minutes the first time, ~1 minute afterwards), ending with:

```
• waiting for pods in kind-kav-prod
pod/api condition met
...
✓ demo clusters ready: kind-kav-dev kind-kav-staging kind-kav-prod
```

✅ **Check:**

```bash
kind get clusters                                   # kav-dev, kav-prod, kav-staging
docker ps --filter name=kav                         # one container per cluster
kubectl --context kind-kav-prod get pods -A         # all Running
```

| Cluster | Posture | Pods (app) | Graph nodes | Attack paths |
|---|---|---|---|---|
| `kav-dev` | loose | 5 | 20 | 16 |
| `kav-staging` | mixed | 5 | 19 | 11 |
| `kav-prod` | hardened | 9 | 19 | 19 |

These are **real** Kubernetes clusters (API server, scheduler, kubelet, containerd, network
plugin) running inside Docker on your machine. The tool only ever *reads* them.

---

## 6. Run the demo

### 6.1 Interactive menu (recommended for presentations)

```bash
./demo/present.sh
```

✅ **Expect** a colour menu:

```
╔════════════════════════════════════════════════════════════════════╗
║  KubeAttackViz · Kubernetes attack paths with ML-learned weights   ║
╚════════════════════════════════════════════════════════════════════╝

  #   CLUSTER      STATE      PODS   POSTURE
  1)  kav-dev      running    5      loose    cluster-admin CI + dev-bob, privileged pod, no NetworkPolicies
  2)  kav-staging  running    5      mixed    some NetworkPolicies, CI reads every secret, on-call edit
  3)  kav-prod     running    9      hardened PSS restricted, default-deny, no token mounts, break-glass only

  1-3) select a cluster    a) live monitor ALL clusters    c) create missing clusters    q) quit
```

Pick a cluster (e.g. `3`), then:

| Key | Action | What you see |
|---|---|---|
| `1` | Show pods | namespace, pod, status, ready ✔, ServiceAccount, image |
| `2` | RBAC & NetworkPolicies | who can do what (human users in red) and the policies in force |
| `3` | **ML attack-path analysis** | ① kubectl scan ② pods ③ Trivy CVEs per pod (e.g. "2 known-exploited (CISA KEV)") ④ ML edge weights ⑤ attack paths hop by hop with probability, basis and weakest link ⑥ blast radius ⑦ chokepoints |
| `4` | ML weight of every edge | table of P(success), learned weight and static weight per edge |
| `5` | **Live monitor + dashboard** | a clickable `http://127.0.0.1:8765/` link; the browser opens after the first scan; scan logs every 15 s; **Ctrl+C returns to the menu** |
| `6` | Inject / revert a misconfiguration | e.g. bind a ServiceAccount to cluster-admin |
| `b` | back | |

The first time option 3 runs, Trivy downloads its vulnerability database and scans each image
(1–3 minutes); later runs use the cache and take about 5 seconds.

### 6.2 Show detection live

1. In the menu, choose a cluster → `5` (live monitor). The browser opens the dashboard.
2. In a **second terminal**:

   ```bash
   ./demo/drift.sh prod admin-sa          # bind shop/frontend ServiceAccount to cluster-admin
   ```

3. ✅ **Expect** within one scan (≤ 15 s): in the monitor log
   `🚨 [kind-kav-prod] [HIGH] Privilege path: … → clusterrole:cluster/cluster-admin`, and a pop-up
   alert in the dashboard. On the **Timeline** tab, the change appears with its details.
4. Undo it:

   ```bash
   ./demo/drift.sh prod admin-sa revert
   ```

Other scenarios: `open-payments` (delete the payments NetworkPolicies) and `expose-redis` (expose
Redis as a NodePort). All are configuration changes only.

### 6.3 Other ways to start

```bash
./demo/start.sh               # kitty window (monitor · pods · events · drift shell) + browser
./demo/start.sh dev prod      # only some clusters
./demo/start.sh --here prod   # monitor in this terminal (no kitty)
./demo/stop.sh                # stop the monitor (clusters keep running)
```

Or call the CLI directly against any cluster in your kubeconfig:

```bash
python main.py --weights learned --scan-images analyze -c kind-kav-dev
python main.py --weights learned --scan-images serve            # all kind-kav-* clusters
KAV_KUBE_CONTEXT=kind-kav-prod python main.py --weights learned --scan-images full-report -k
```

### 6.4 Clean up

```bash
./demo/stop.sh                # stop the monitor
./demo/teardown.sh            # delete all three clusters (frees ~3 GB RAM)
```

---

## 7. Optional extras

### 7.1 Retrain the ML model from the public datasets

```bash
python main.py ml-fetch-data      # ~105 MB: CISA KEV, NVD 2010–today, FIRST EPSS → data/raw/
python main.py ml-train           # ~2 minutes
python main.py ml-info            # new metrics and data hashes
```

✅ **Expect** a temporal-split evaluation table in which the gradient-boosting model's ROC-AUC is
about 0.89 versus about 0.77 for the CVSS score alone. Sources:
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) ·
[NVD feeds (FKIE mirror)](https://github.com/fkie-cad/nvd-json-data-feeds) ·
[FIRST EPSS](https://www.first.org/epss/).

### 7.2 Validate the engine against a real cluster

```bash
kind create cluster --name kav-lab
python main.py lab-run --scenarios 25 --seed 7      # ~15–25 minutes
python main.py lab-report
kind delete cluster --name kav-lab
```

✅ **Expect** precision/recall/F1 = 1.000 for RBAC (≈21,000 checks) and token mounting, and for
network checks without host-network pods; all disagreements involve host-network pods (a
documented limitation).

### 7.3 Scan your own cluster

Point kubectl at it (EKS, GKE, AKS, …) and use a read-only identity:

```bash
kubectl apply -f deploy/scanner-rbac.yaml            # least-privilege scanner ServiceAccount
python main.py --weights learned --scan-images full-report -k
python main.py dump-raw -o my-cluster.raw.json       # save for offline analysis (no Secret values)
python main.py --weights learned full-report -i my-cluster.raw.json
```

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'typer'` | that terminal's `python3` has no project packages (e.g. conda not active). The demo scripts pick a Python that has them automatically; for direct `python main.py …` calls, activate your env (`source .venv/bin/activate` or `conda activate`) or run `pip install -r requirements.txt` in it. Force one with `PY=/path/to/python ./demo/present.sh` |
| `kubectl: command not found` / `kind: command not found` | `~/.local/bin` is not on PATH (§4.5) |
| `permission denied ... /var/run/docker.sock` | add yourself to the `docker` group and log out/in (§4.1) |
| `kind create cluster` fails with "too many open files" | `sudo sysctl fs.inotify.max_user_watches=524288 fs.inotify.max_user_instances=512` |
| Pods stuck in `ImagePullBackOff` | network or Docker Hub rate limit; wait and re-run `./demo/setup.sh` |
| `address already in use` on port 8765 | `./demo/stop.sh`, or `PORT=8780 ./demo/present.sh` |
| Model fails to load / version warning | `pip install "scikit-learn==1.7.2"` or retrain (§7.1) |
| No CVEs shown for pods | Trivy not installed or offline on its first run; `trivy --version` |
| Browser does not open | open the printed `http://127.0.0.1:8765/` link manually |
| Dashboard shows "first scan running…" | wait a few seconds; the first Trivy scan of new images takes longer |
| A demo cluster shows `stopped` after a reboot | choose it in `./demo/present.sh` (it is started automatically) or `docker start kav-<name>-control-plane` |

---

## 9. Where to read more

- [`README.md`](README.md) — architecture, algorithms, mathematics, ML model, datasets, validation
- [`COMMANDS.md`](COMMANDS.md) — command reference
- [`kube_attack_viz/ml/artifacts/MODEL_CARD.md`](kube_attack_viz/ml/artifacts/MODEL_CARD.md) — model data, metrics and limitations
- [`demo/clusters/`](demo/clusters) — the three demo clusters' manifests
