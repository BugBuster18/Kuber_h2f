"""
BFS-based Blast Radius Analysis.

Computes the set of nodes reachable from a given source node within
a maximum hop depth, grouped by hop level.
"""

from __future__ import annotations

from collections import deque

import networkx as nx

from ..models import BlastRadiusResult
from ..graph_builder import get_node_name


def blast_radius(
    G: nx.DiGraph,
    source: str,
    max_depth: int = 3,
) -> BlastRadiusResult:
    """Compute the blast radius from a source node using BFS.

    Performs a breadth-first traversal from the source, grouping
    discovered nodes by their hop distance. Nodes are never revisited.

    Args:
        G: The attack graph (NetworkX DiGraph).
        source: Source node ID to start BFS from.
        max_depth: Maximum number of hops to traverse (default: 3).

    Returns:
        BlastRadiusResult containing layers of affected nodes.

    Raises:
        ValueError: If the source node does not exist in the graph.
    """
    if source not in G.nodes:
        raise ValueError(f"Source node '{source}' not found in graph.")

    visited: set[str] = {source}
    queue: deque[tuple[str, int]] = deque([(source, 0)])
    layers: dict[int, list[str]] = {}

    while queue:
        current, depth = queue.popleft()

        if depth > 0:
            if depth not in layers:
                layers[depth] = []
            layers[depth].append(current)

        if depth >= max_depth:
            continue

        for neighbor in G.successors(current):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, depth + 1))

    total_affected = sum(len(v) for v in layers.values())

    return BlastRadiusResult(
        source=source,
        max_depth=max_depth,
        layers=layers,
        total_affected=total_affected,
    )


def format_blast_radius(G: nx.DiGraph, result: BlastRadiusResult) -> str:
    """Format blast radius results for human-readable console output.

    Args:
        G: The attack graph.
        result: BlastRadiusResult to format.

    Returns:
        Formatted string representation.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  BLAST RADIUS ANALYSIS")
    lines.append("=" * 70)
    source_name = get_node_name(G, result.source)
    lines.append(f"  Source: {source_name} ({result.source})")
    lines.append(f"  Max Depth: {result.max_depth}")
    lines.append(f"  Total Affected Nodes: {result.total_affected}")
    lines.append("-" * 70)

    if not result.layers:
        lines.append("  No reachable nodes from source.")
    else:
        for depth in sorted(result.layers.keys()):
            nodes = result.layers[depth]
            lines.append(f"\n  Hop {depth} ({len(nodes)} node(s)):")
            for node_id in nodes:
                name = get_node_name(G, node_id)
                node_type = G.nodes[node_id].get("type", "unknown")
                risk = G.nodes[node_id].get("risk_score", 0.0)
                lines.append(f"    ├── {name} [{node_type}] (risk: {risk:.1f})")

    lines.append("=" * 70)
    return "\n".join(lines)
