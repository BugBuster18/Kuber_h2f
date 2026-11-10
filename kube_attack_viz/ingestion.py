"""
Data Ingestion Module for KubeAttackViz.

Supports three ingestion modes:
  1. Graph JSON — a pre-built cluster graph (nodes/edges).
  2. Raw JSON — `dump-raw` output (resource lists); the graph is built with
     the exact feasibility engine in kube_attack_viz/k8s.
  3. kubectl — queries a live cluster, then as (2). Secret values are never
     fetched (names and types only).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .models import ClusterGraph, NodeData, EdgeData


def ingest_from_json(filepath: str | Path) -> ClusterGraph:
    """Ingest a cluster graph from a JSON file.

    Args:
        filepath: Path to the JSON file matching the ClusterGraph schema.

    Returns:
        Parsed ClusterGraph instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
        KeyError: If required schema fields are missing.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if is_raw_state(raw):
        return cluster_from_raw(raw)
    return ClusterGraph.from_dict(raw)


def export_graph_to_json(graph: ClusterGraph, filepath: str | Path) -> None:
    """Export a ClusterGraph to a JSON file.

    Args:
        graph: ClusterGraph instance to export.
        filepath: Output file path.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(graph.to_dict(), f, indent=2)


# ─── kubectl ingestion ───────────────────────────────────────────────────────

# kubectl resource name for each inventory key
KUBECTL_RESOURCES = {
    "namespaces": "namespaces",
    "nodes": "nodes",
    "pods": "pods",
    "services": "services",
    "ingresses": "ingresses.networking.k8s.io",
    "serviceaccounts": "serviceaccounts",
    "configmaps": "configmaps",
    "roles": "roles.rbac.authorization.k8s.io",
    "clusterroles": "clusterroles.rbac.authorization.k8s.io",
    "rolebindings": "rolebindings.rbac.authorization.k8s.io",
    "clusterrolebindings": "clusterrolebindings.rbac.authorization.k8s.io",
    "networkpolicies": "networkpolicies.networking.k8s.io",
}

# Secrets: names/types only. The values are never requested from the API.
_SECRET_COLUMNS = "NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type"


def _kubectl(args: list[str]) -> str:
    cmd = ["kubectl", *args]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except FileNotFoundError:
        raise RuntimeError("kubectl not found. Ensure kubectl is installed and in PATH.")
    if result.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args[:2])} failed: {result.stderr.strip()}")
    return result.stdout


def _run_kubectl(resource: str) -> dict[str, Any]:
    """`kubectl get <resource> --all-namespaces -o json`, parsed."""
    return json.loads(_kubectl(["get", resource, "--all-namespaces", "-o", "json"]))


def _secret_metadata() -> dict[str, Any]:
    out = _kubectl(["get", "secrets", "--all-namespaces", "--no-headers", "-o", f"custom-columns={_SECRET_COLUMNS}"])
    items = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            items.append({
                "metadata": {"namespace": parts[0], "name": parts[1]},
                "type": parts[2] if len(parts) > 2 else "Opaque",
            })
    return {"items": items}


def fetch_raw_state(log=None) -> dict[str, Any]:
    """Query the cluster for every resource the analysis needs.

    Resource types that are missing or forbidden for the current identity are
    recorded under "_errors" instead of aborting — a scan with partial
    permissions still produces a (partial) graph, and the gap is reported.
    """
    raw: dict[str, Any] = {"_errors": {}}
    for key, resource in KUBECTL_RESOURCES.items():
        try:
            raw[key] = _run_kubectl(resource)
        except RuntimeError as e:
            raw[key] = {"items": []}
            raw["_errors"][key] = str(e)
    try:
        raw["secrets"] = _secret_metadata()
    except RuntimeError as e:
        raw["secrets"] = {"items": []}
        raw["_errors"]["secrets"] = str(e)
    if log:
        for key, err in raw["_errors"].items():
            log(f"[WARN] could not list {key}: {err}")
    return raw


def is_raw_state(data: dict[str, Any]) -> bool:
    """True for `dump-raw` / fetch_raw_state() output (vs. a graph JSON)."""
    return isinstance(data.get("pods"), dict) or isinstance(data.get("nodes"), dict)


def cluster_from_raw(raw: dict[str, Any]) -> ClusterGraph:
    """Build the attack graph from raw resource JSON (exact feasibility)."""
    from .k8s.graph import build_cluster_graph
    from .k8s.inventory import parse_inventory

    return build_cluster_graph(parse_inventory(raw))


def ingest_from_kubectl() -> ClusterGraph:
    """Ingest cluster state directly from a live Kubernetes cluster via kubectl.

    Uses the current kubeconfig context. Grant the identity read-only access
    (get/list) to the resources in KUBECTL_RESOURCES; Secret values are never
    read, only their names and types.
    """
    return cluster_from_raw(fetch_raw_state(log=lambda m: print(m, file=sys.stderr)))


def dump_raw_kubernetes_state(filepath: str | Path) -> None:
    """Save raw resource JSON for offline analysis (`--input` accepts it).

    Contains no Secret values — Secrets are fetched as metadata only.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(fetch_raw_state(), f, indent=2)


def enrich_cluster_graph(cluster: ClusterGraph) -> int:
    """Scan cluster for CVEs and fetch live CVSS scores from NVD.

    Returns:
        Number of successfully enriched items.
    """
    from .cve_service import enricher
    from rich.progress import Progress

    enriched_count = 0
    cves_to_check = set()

    # Collect all CVEs
    for node in cluster.nodes:
        # 1. Existing CVEs
        for cve in node.cves:
            cves_to_check.add(cve)
        
        # 2. Dynamic Image Discovery
        if node.type == "pod" and node.image:
            discovered = enricher.discover_cves_for_image(node.image)
            for d in discovered:
                if d["id"] not in node.cves:
                    node.cves.append(d["id"])
                # Increase node risk by discovered CVSS
                node.risk_score = max(node.risk_score, d["cvss"])
                enriched_count += 1

    for edge in cluster.edges:
        if edge.cve:
            cves_to_check.add(edge.cve)

    if not cves_to_check:
        return 0

    with Progress() as progress:
        task = progress.add_task("[cyan]Enriching CVEs from NVD...", total=len(cves_to_check))
        
        cve_map = {}
        for cve in cves_to_check:
            score = enricher.get_cvss(cve)
            if score is not None:
                cve_map[cve] = score
                enriched_count += 1
            progress.update(task, advance=1)

    # Apply scores
    for node in cluster.nodes:
        # Update Node Likelihood based on CVSS
        max_cvss = 0.0
        for cve in node.cves:
            if cve in cve_map:
                max_cvss = max(max_cvss, cve_map[cve])
        
        if max_cvss > 0:
            # Shift likelihood up by up to 5 points (half of CVSS)
            node.likelihood = min(10.0, (node.likelihood or 0.1) + (max_cvss / 2.0))
            # Recalculate Risk Score: (L/10) * I
            node.risk_score = (node.likelihood / 10.0) * (node.impact or 1.0)

    for edge in cluster.edges:
        if edge.cve in cve_map:
            edge.cvss = cve_map[edge.cve]

    return enriched_count
