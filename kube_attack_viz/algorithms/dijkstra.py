"""
Dijkstra-based Shortest Attack Path.

Finds the minimum-weight path between a source and target node,
representing the easiest (least resistance) attack path.
"""

from __future__ import annotations

import networkx as nx

from ..models import AttackPath
from ..graph_builder import get_node_name


def _severity_label(total_risk: float) -> str:
    """Map total risk score to a severity label.

    Args:
        total_risk: Sum of edge weights along the path.

    Returns:
        Severity string: CRITICAL, HIGH, MEDIUM, or LOW.
    """
    if total_risk > 20:
        return "CRITICAL"
    elif total_risk > 10:
        return "HIGH"
    elif total_risk > 5:
        return "MEDIUM"
    else:
        return "LOW"


def shortest_attack_path(
    G: nx.DiGraph,
    source: str,
    target: str,
) -> AttackPath | None:
    """Find the shortest (minimum-weight) attack path using Dijkstra's algorithm.

    Uses edge weights to determine the minimum-cost path from source to target.
    This represents the path of least resistance for an attacker.

    Args:
        G: The attack graph (NetworkX DiGraph).
        source: Source node ID (attack entry point).
        target: Target node ID (high-value target).

    Returns:
        AttackPath with full path details, or None if no path exists.

    Raises:
        ValueError: If source or target node does not exist.
    """
    if source not in G.nodes:
        raise ValueError(f"Source node '{source}' not found in graph.")
    if target not in G.nodes:
        raise ValueError(f"Target node '{target}' not found in graph.")

    try:
        path_nodes: list[str] = nx.dijkstra_path(G, source, target, weight="weight")
        total_weight: float = nx.dijkstra_path_length(
            G, source, target, weight="weight"
        )
    except nx.NetworkXNoPath:
        return None

    # Extract path details
    path_names: list[str] = [get_node_name(G, n) for n in path_nodes]
    relationships: list[str] = []
    cves: list[str | None] = []
    cvss_scores: list[float | None] = []

    for i in range(len(path_nodes) - 1):
        edge_data = G.edges[path_nodes[i], path_nodes[i + 1]]
        relationships.append(edge_data.get("relationship", "unknown"))
        cves.append(edge_data.get("cve"))
        cvss_scores.append(edge_data.get("cvss"))

    hop_count = len(path_nodes) - 1
    severity = _severity_label(total_weight)

    return AttackPath(
        path_nodes=path_nodes,
        path_names=path_names,
        relationships=relationships,
        cves=cves,
        cvss_scores=cvss_scores,
        hop_count=hop_count,
        total_risk=total_weight,
        severity=severity,
    )


def all_shortest_paths(
    G: nx.DiGraph,
) -> list[AttackPath]:
    """Compute shortest paths from ALL source nodes to ALL sink nodes.

    Args:
        G: The attack graph.

    Returns:
        List of AttackPath objects, sorted by total risk ascending.
    """
    from ..graph_builder import get_source_nodes, get_sink_nodes

    sources = get_source_nodes(G)
    sinks = get_sink_nodes(G)
    paths: list[AttackPath] = []

    for src in sources:
        for sink in sinks:
            path = shortest_attack_path(G, src, sink)
            if path is not None:
                paths.append(path)

    # Sort by total risk ascending
    paths.sort(key=lambda p: p.total_risk)
    return paths


def format_attack_path(G: nx.DiGraph, path: AttackPath) -> str:
    """Format a single attack path for human-readable output.

    Args:
        G: The attack graph.
        path: AttackPath to format.

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    lines.append(f"  Path: {' → '.join(path.path_names)}")
    lines.append(f"  Hops: {path.hop_count} | Risk: {path.total_risk:.2f} | Severity: {path.severity}")

    for i in range(len(path.relationships)):
        src_name = path.path_names[i]
        tgt_name = path.path_names[i + 1]
        rel = path.relationships[i]
        cve = path.cves[i] if path.cves[i] else "—"
        cvss = f"{path.cvss_scores[i]:.1f}" if path.cvss_scores[i] else "—"
        lines.append(f"    {src_name} ──[{rel}]──▸ {tgt_name}  (CVE: {cve}, CVSS: {cvss})")

    return "\n".join(lines)


def format_all_paths(G: nx.DiGraph, paths: list[AttackPath]) -> str:
    """Format all attack paths for console output.

    Args:
        G: The attack graph.
        paths: List of AttackPaths.

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  ATTACK PATHS (Sorted by Risk — Ascending)")
    lines.append("=" * 70)

    if not paths:
        lines.append("  No attack paths found (no reachable source → sink paths).")
    else:
        for idx, path in enumerate(paths, 1):
            lines.append(f"\n  ─── Path #{idx} ───")
            lines.append(format_attack_path(G, path))

    lines.append("=" * 70)
    return "\n".join(lines)
