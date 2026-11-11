"""
Critical Node Analysis (Graph Surgery).

Identifies nodes whose removal eliminates the most source → sink paths.
Uses temporary node removal on a copy of the graph to compute path impact.
"""

from __future__ import annotations

import networkx as nx

from ..models import CriticalNodeResult
from ..graph_builder import get_source_nodes, get_sink_nodes, get_node_name


# Simple-path counting is exponential in graph density. Real clusters (where
# e.g. cluster-admin can exec into every pod) blow up quickly, so counting is
# done under a work budget. Within budget the result is exact; beyond it the
# analysis falls back to a polynomial metric: how many (source, sink) PAIRS a
# node's removal disconnects. The result records which metric was used.
PATH_BUDGET = 20_000


class _BudgetExceeded(Exception):
    pass


def count_simple_paths(
    G: nx.DiGraph,
    sources: list[str],
    sinks: list[str],
    cutoff: int = 15,
    excluded: str | None = None,
    budget: int = PATH_BUDGET,
    per_node: dict[str, int] | None = None,
) -> int:
    """Count simple source→sink paths (≤ cutoff edges), optionally without
    `excluded`. Raises _BudgetExceeded after `budget` DFS expansions.
    If per_node is given, adds each counted path's nodes to it."""
    sink_set = set(sinks)
    left = [budget]
    total = 0
    path: list[str] = []
    on_path: set[str] = set()

    def walk(u: str, depth: int) -> None:
        nonlocal total
        left[0] -= 1
        if left[0] < 0:
            raise _BudgetExceeded()
        if depth >= cutoff:
            return
        for v in G.successors(u):
            if v == excluded or v in on_path:
                continue
            path.append(v)
            on_path.add(v)
            if v in sink_set:
                total += 1
                if per_node is not None:
                    for n in path:
                        per_node[n] = per_node.get(n, 0) + 1
            walk(v, depth + 1)
            path.pop()
            on_path.discard(v)

    for src in sources:
        if src not in G or src == excluded:
            continue
        path[:] = [src]
        on_path.clear()
        on_path.add(src)
        walk(src, 0)
    return total


def _reachable_pairs(G: nx.DiGraph, sources: list[str], sinks: list[str], excluded: str | None = None) -> int:
    sink_set = set(sinks)
    pairs = 0
    for src in sources:
        if src not in G or src == excluded:
            continue
        seen = {src}
        stack = [src]
        while stack:
            u = stack.pop()
            for v in G.successors(u):
                if v != excluded and v not in seen:
                    seen.add(v)
                    stack.append(v)
        pairs += len((seen - {src}) & sink_set)
    return pairs


def critical_node_analysis(
    G: nx.DiGraph,
    top_n: int = 5,
    cutoff: int = 15,
    budget: int = PATH_BUDGET,
) -> CriticalNodeResult:
    """Perform critical node analysis via graph surgery.

    For each non-source, non-sink node, remove it (logically — the graph is
    never mutated) and measure how much attack surface disappears:
      * metric "paths": simple source→sink paths eliminated (exact, used when
        counting fits the budget);
      * metric "reachable_pairs": (source, sink) pairs disconnected (used for
        dense graphs where path counting is intractable).

    Args:
        G: The attack graph (NetworkX DiGraph). NOT mutated.
        top_n: Number of top critical nodes to return (default: 5).
        cutoff: Maximum path length in edges (default: 15).
        budget: DFS expansions allowed per count before falling back.

    Returns:
        CriticalNodeResult with ranked critical nodes and the metric used.
    """
    sources = get_source_nodes(G)
    sinks = get_sink_nodes(G)

    if not sources or not sinks:
        return CriticalNodeResult(top_nodes=[], total_paths_baseline=0)

    candidates: list[str] = [
        n for n in G.nodes
        if not G.nodes[n].get("is_source", False) and not G.nodes[n].get("is_sink", False)
    ]

    try:
        baseline = count_simple_paths(G, sources, sinks, cutoff=cutoff, budget=budget)
        metric = "paths"

        def remaining(node_id: str) -> int:
            return count_simple_paths(G, sources, sinks, cutoff=cutoff, excluded=node_id, budget=budget)
    except _BudgetExceeded:
        baseline = _reachable_pairs(G, sources, sinks)
        metric = "reachable_pairs"

        def remaining(node_id: str) -> int:
            return _reachable_pairs(G, sources, sinks, excluded=node_id)

    node_impact: list[tuple[str, str, int]] = []
    for node_id in candidates:
        eliminated = baseline - remaining(node_id)
        if eliminated > 0:
            node_impact.append((node_id, get_node_name(G, node_id), eliminated))

    node_impact.sort(key=lambda x: x[2], reverse=True)
    return CriticalNodeResult(
        top_nodes=node_impact[:top_n],
        total_paths_baseline=baseline,
        metric=metric,
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
    unit = "Paths" if result.metric == "paths" else "Reachable Source→Sink Pairs"
    if result.metric != "paths":
        lines.append("  (graph too dense to enumerate paths — measuring disconnected source→sink pairs)")
    lines.append(f"  Baseline Source→Sink {unit}: {result.total_paths_baseline}")
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
                f"      {'Paths Eliminated' if result.metric == 'paths' else 'Pairs Disconnected'}: "
                f"{eliminated} / {result.total_paths_baseline} ({pct:.1f}%)"
            )
            lines.append(
                f"      ⚡ Remove this node → eliminates {eliminated} "
                f"{'attack path(s)' if result.metric == 'paths' else 'reachable source→sink pair(s)'}"
            )

    lines.append("=" * 70)
    return "\n".join(lines)
