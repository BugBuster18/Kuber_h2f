"""
Data Ingestion Module for KubeAttackViz.

Supports JSON file ingestion — reads a pre-built cluster graph JSON
and parses it into the internal ClusterGraph model for analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ClusterGraph, NodeData, EdgeData


# ─── Weight heuristics ───────────────────────────────────────────────────────

_RELATIONSHIP_BASE_WEIGHTS: dict[str, float] = {
    "runs_as": 2.0,
    "binds_to": 3.0,
    "grants": 4.0,
    "accesses": 5.0,
    "mounts": 3.5,
    "exposes": 2.5,
    "connects_to": 2.0,
    "uses": 3.0,
    "escalates_to": 6.0,
    "has_secret": 4.5,
    "reads": 3.0,
    "writes": 4.0,
}

_RESOURCE_IMPACT_SCORES: dict[str, float] = {
    "pod": 4.0,
    "service": 3.0,
    "serviceaccount": 5.0,
    "role": 4.5,
    "clusterrole": 6.5,
    "rolebinding": 3.5,
    "clusterrolebinding": 6.0,
    "secret": 9.0,         # High value
    "configmap": 3.0,
    "namespace": 1.0,
    "database": 10.0,      # Maximum value target
    "node": 7.0,
    "ingress": 4.0,
}

_RESOURCE_BASE_LIKELIHOOD: dict[str, float] = {
    "pod": 2.0,
    "service": 3.0,
    "serviceaccount": 2.0,
    "role": 1.0,
    "secret": 1.5,
    "database": 1.0,
}


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
