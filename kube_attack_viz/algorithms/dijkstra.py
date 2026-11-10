"""
Dijkstra-based Shortest Attack Path.

Finds the minimum-weight path between a source and target node,
representing the easiest (least resistance) attack path.
"""

from __future__ import annotations

import math

import networkx as nx

from ..models import AttackPath
from ..graph_builder import get_node_name


# ─── Risk model ──────────────────────────────────────────────────────────────
#
# Edge weights are *costs*: the effort an attacker spends on a hop (lower =
# easier; CVEs lower it further). A path is dangerous when it is CHEAP and
# leads to a VALUABLE target, so risk must go DOWN as cost goes UP:
#
#     total_risk = sink_impact / (1 + total_cost / RISK_COST_SCALE)
#
# sink_impact is the target node's risk_score (0-10), so total_risk is on a
# 0-10 scale. Keep in sync with computePathRisk() in visualizer/script.js.

RISK_COST_SCALE = 10.0
DEFAULT_SINK_IMPACT = 5.0

SEVERITY_THRESHOLDS = (
    (7.0, "CRITICAL"),
    (5.0, "HIGH"),
    (3.0, "MEDIUM"),
)

# Learned mode: risk = impact x P(path) is an expected impact, so bands are
# lower. E.g. CRITICAL = at least a 40% chance of reaching a 10-impact target.
LEARNED_SEVERITY_THRESHOLDS = (
    (4.0, "CRITICAL"),
    (1.5, "HIGH"),
    (0.5, "MEDIUM"),
)


def compute_path_risk(
    sink_impact: float | None,
    total_cost: float,
    weight_mode: str = "static",
) -> float:
    """Compute a path's danger score from its target value and traversal cost.

    static:  impact / (1 + cost / RISK_COST_SCALE)   (cost = effort units)
    learned: impact * exp(-cost)                       (cost = -ln P(path),
             so this is impact x probability the whole path succeeds)

    Args:
        sink_impact: risk_score of the path's final node (0-10).
        total_cost: Sum of effective edge weights along the path.
        weight_mode: "static" or "learned" (see graph_builder).

    Returns:
        Danger score on a 0-10 scale (higher = more dangerous).
    """
    impact = DEFAULT_SINK_IMPACT if sink_impact is None else float(sink_impact)
    cost = max(total_cost, 0.0)
    if weight_mode == "learned":
        return impact * math.exp(-cost)
    return impact / (1.0 + cost / RISK_COST_SCALE)


def _severity_label(total_risk: float, weight_mode: str = "static") -> str:
    """Map a path danger score (0-10) to a severity label.

    Args:
        total_risk: Path danger score (see compute_path_risk).
        weight_mode: "static" (CRITICAL >= 7, HIGH >= 5, MEDIUM >= 3) or
            "learned" (CRITICAL >= 4, HIGH >= 1.5, MEDIUM >= 0.5).

    Returns:
        Severity string: CRITICAL, HIGH, MEDIUM, or LOW.
    """
    bands = LEARNED_SEVERITY_THRESHOLDS if weight_mode == "learned" else SEVERITY_THRESHOLDS
    for threshold, label in bands:
        if total_risk >= threshold:
            return label
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
    weight_mode = G.graph.get("weight_mode", "static")
    sink = G.nodes[target]
    impact = sink.get("impact") if sink.get("impact") is not None else sink.get("risk_score")
    total_risk = compute_path_risk(impact, total_weight, weight_mode)
    severity = _severity_label(total_risk, weight_mode)

    return AttackPath(
        path_nodes=path_nodes,
        path_names=path_names,
        relationships=relationships,
        cves=cves,
        cvss_scores=cvss_scores,
        hop_count=hop_count,
        total_risk=total_risk,
        total_cost=total_weight,
        severity=severity,
        success_probability=math.exp(-total_weight) if weight_mode == "learned" else None,
    )


def all_shortest_paths(
    G: nx.DiGraph,
) -> list[AttackPath]:
    """Compute shortest paths from ALL source nodes to ALL sink nodes.

    Args:
        G: The attack graph.

    Returns:
        List of AttackPath objects, most dangerous first (risk descending).
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

    # Most dangerous first; ties broken by cheaper (easier) path
    paths.sort(key=lambda p: (-p.total_risk, p.total_cost))
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
    prob = (
        f" | P(success): {path.success_probability * 100:.1f}%"
        if path.success_probability is not None else ""
    )
    lines.append(
        f"  Hops: {path.hop_count} | Risk: {path.total_risk:.2f}/10 | "
        f"Cost: {path.total_cost:.2f}{prob} | Severity: {path.severity}"
    )

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
    lines.append("  ATTACK PATHS (Sorted by Risk — Most Dangerous First)")
    lines.append("=" * 70)

    if not paths:
        lines.append("  No attack paths found (no reachable source → sink paths).")
    else:
        for idx, path in enumerate(paths, 1):
            lines.append(f"\n  ─── Path #{idx} ───")
            lines.append(format_attack_path(G, path))

    lines.append("=" * 70)
    return "\n".join(lines)
