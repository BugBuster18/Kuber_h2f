"""
Frontend Export Module for KubeAttackViz.

Exports the graph and analysis results in the exact JSON format
expected by the D3.js visualization frontend.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx

from .graph_builder import get_source_nodes, get_sink_nodes, get_node_name, graph_summary
from .algorithms.dijkstra import all_shortest_paths
from .algorithms.dfs import detect_cycles
from .algorithms.critical_node import critical_node_analysis
from .algorithms.bfs import blast_radius
from .classifier import classify_path, compute_advanced_score


def export_for_frontend(
    G: nx.DiGraph,
    output_path: str | Path,
    blast_depth: int = 3,
    cutoff: int = 15,
) -> None:
    """Export the full graph + analysis results for the D3.js frontend.

    Output format:
    {
        nodes: [...],
        edges: [...],
        attack_paths: [...],
        cycles: [...],
        critical_node: {...},
        blast_radius: [...],
        metadata: {...}
    }

    Args:
        G: The attack graph.
        output_path: Output JSON file path.
        blast_depth: Max BFS depth.
        cutoff: Max path length for critical node analysis.
    """
    # ── Nodes ────────────────────────────────────────────────────────────────
    nodes_data = []
    for node_id, data in G.nodes(data=True):
        nodes_data.append({
            "id": node_id,
            "name": data.get("name", node_id),
            "type": data.get("type", "unknown"),
            "namespace": data.get("namespace", ""),
            "risk_score": data.get("risk_score", 0.0),
            "is_source": data.get("is_source", False),
            "is_sink": data.get("is_sink", False),
            "cves": data.get("cves", []),
        })

    # ── Edges ────────────────────────────────────────────────────────────────
    edges_data = []
    for u, v, data in G.edges(data=True):
        edges_data.append({
            "source": u,
            "target": v,
            "relationship": data.get("relationship", ""),
            "weight": data.get("weight", 1.0),
            "cve": data.get("cve"),
            "cvss": data.get("cvss"),
        })

    # ── Attack paths ─────────────────────────────────────────────────────────
    paths = all_shortest_paths(G)
    paths_data = []
    for p in paths:
        categories = classify_path(G, p)
        score = compute_advanced_score(p)
        paths_data.append({
            "path_nodes": p.path_nodes,
            "path_names": p.path_names,
            "relationships": p.relationships,
            "cves": p.cves,
            "cvss_scores": p.cvss_scores,
            "hop_count": p.hop_count,
            "total_risk": p.total_risk,
            "severity": p.severity,
            "categories": categories,
            "advanced_score": round(score, 2),
        })

    # ── Cycles ───────────────────────────────────────────────────────────────
    cycle_result = detect_cycles(G)
    cycles_data = []
    for cycle, names in zip(cycle_result.cycles, cycle_result.cycle_names):
        cycles_data.append({
            "node_ids": cycle,
            "node_names": names,
        })

    # ── Critical node ────────────────────────────────────────────────────────
    cn = critical_node_analysis(G, top_n=5, cutoff=cutoff)
    critical_data = {
        "baseline_paths": cn.total_paths_baseline,
        "top_nodes": [
            {"id": n[0], "name": n[1], "paths_eliminated": n[2]}
            for n in cn.top_nodes
        ],
    }

    # ── Blast radius ─────────────────────────────────────────────────────────
    sources = get_source_nodes(G)
    blast_data = []
    for src in sources:
        br = blast_radius(G, src, max_depth=blast_depth)
        blast_data.append({
            "source": src,
            "source_name": get_node_name(G, src),
            "max_depth": br.max_depth,
            "total_affected": br.total_affected,
            "layers": {str(k): v for k, v in br.layers.items()},
        })

    # ── Assemble ─────────────────────────────────────────────────────────────
    export = {
        "metadata": {
            "tool": "KubeAttackViz",
            "version": "2.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "graph_summary": graph_summary(G),
        "nodes": nodes_data,
        "edges": edges_data,
        "attack_paths": paths_data,
        "cycles": cycles_data,
        "critical_node": critical_data,
        "blast_radius": blast_data,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, default=str)
