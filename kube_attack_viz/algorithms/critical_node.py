"""
Critical Node Analysis (Graph Surgery).

Identifies nodes whose removal eliminates the most source → sink paths.
Uses temporary node removal on a copy of the graph to compute path impact.
"""

from __future__ import annotations

import networkx as nx

from ..models import CriticalNodeResult
from ..graph_builder import get_source_nodes, get_sink_nodes, get_node_name


def _count_all_source_sink_paths(
    G: nx.DiGraph,
    sources: list[str],
    sinks: list[str],
    cutoff: int = 15,
) -> int:
    """Count all simple paths from any source to any sink.

    Args:
        G: The graph to analyze.
        sources: List of source node IDs.
        sinks: List of sink node IDs.
        cutoff: Maximum path length to prevent combinatorial explosion.

    Returns:
        Total number of simple paths found.
    """
    total = 0
    for src in sources:
        if src not in G.nodes:
            continue
        for sink in sinks:
            if sink not in G.nodes:
                continue
            try:
                paths = list(nx.all_simple_paths(G, src, sink, cutoff=cutoff))
                total += len(paths)
            except nx.NodeNotFound:
                continue
    return total


def critical_node_analysis(
    G: nx.DiGraph,
    top_n: int = 5,
    cutoff: int = 15,
) -> CriticalNodeResult:
    """Perform critical node analysis via graph surgery.

    For each non-source, non-sink node:
      1. Creates a copy of the graph.
      2. Removes the candidate node from the copy.
      3. Counts remaining source→sink paths.
      4. Computes how many paths were eliminated.

    The node whose removal eliminates the most paths is the most critical.

    Args:
        G: The attack graph (NetworkX DiGraph). NOT mutated.
        top_n: Number of top critical nodes to return (default: 5).
        cutoff: Maximum path length for all_simple_paths (default: 15).

    Returns:
        CriticalNodeResult with ranked critical nodes.
    """
    sources = get_source_nodes(G)
    sinks = get_sink_nodes(G)

    if not sources or not sinks:
        return CriticalNodeResult(top_nodes=[], total_paths_baseline=0)

    # Baseline: count paths in unmodified graph
    baseline = _count_all_source_sink_paths(G, sources, sinks, cutoff=cutoff)

    # Candidate nodes: skip sources and sinks
    candidates: list[str] = [
        n
        for n in G.nodes
        if not G.nodes[n].get("is_source", False)
        and not G.nodes[n].get("is_sink", False)
    ]

    node_impact: list[tuple[str, str, int]] = []

    for node_id in candidates:
        # Work on a copy — never mutate the original graph
        G_copy = G.copy()
        G_copy.remove_node(node_id)

        remaining_paths = _count_all_source_sink_paths(
            G_copy, sources, sinks, cutoff=cutoff
        )
        eliminated = baseline - remaining_paths

        if eliminated > 0:
            name = get_node_name(G, node_id)
            node_impact.append((node_id, name, eliminated))

    # Sort by paths eliminated descending
    node_impact.sort(key=lambda x: x[2], reverse=True)

    return CriticalNodeResult(
        top_nodes=node_impact[:top_n],
        total_paths_baseline=baseline,
    )


def format_critical_nodes(G: nx.DiGraph, result: CriticalNodeResult) -> str:
    """Format critical node analysis for human-readable console output.

    Args:
        G: The attack graph.
        result: CriticalNodeResult to format.

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  CRITICAL NODE ANALYSIS (Graph Surgery)")
    lines.append("=" * 70)
    lines.append(f"  Baseline Source→Sink Paths: {result.total_paths_baseline}")
    lines.append("-" * 70)

    if not result.top_nodes:
        lines.append("  No critical nodes identified.")
        lines.append("  (No intermediate nodes eliminate any source→sink paths.)")
    else:
        for rank, (node_id, name, eliminated) in enumerate(result.top_nodes, 1):
            node_type = G.nodes[node_id].get("type", "unknown") if node_id in G.nodes else "unknown"
            pct = (eliminated / result.total_paths_baseline * 100) if result.total_paths_baseline > 0 else 0
            lines.append(
                f"\n  #{rank} {name} [{node_type}]"
            )
            lines.append(
                f"      ID: {node_id}"
            )
            lines.append(
                f"      Paths Eliminated: {eliminated} / {result.total_paths_baseline} ({pct:.1f}%)"
            )
            lines.append(
                f"      ⚡ Remove this node → eliminates {eliminated} attack path(s)"
            )

    lines.append("=" * 70)
    return "\n".join(lines)
