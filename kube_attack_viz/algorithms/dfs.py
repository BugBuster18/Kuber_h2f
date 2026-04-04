"""
DFS-based Cycle Detection.

Detects ALL unique directed cycles in the attack graph.
Uses canonical normalization to avoid reporting duplicate cycles
(e.g., A→B→A and B→A→B are the same cycle).
"""

from __future__ import annotations

import networkx as nx

from ..models import CycleResult
from ..graph_builder import get_node_name


def _normalize_cycle(cycle: list[str]) -> tuple[str, ...]:
    """Normalize a cycle to its canonical (smallest rotation) form.

    This ensures that rotations of the same cycle are deduplicated.
    For example, [A, B, C] and [B, C, A] become the same canonical form.

    Args:
        cycle: List of node IDs forming a cycle.

    Returns:
        Tuple of node IDs in canonical rotation order.
    """
    if not cycle:
        return ()

    # Find the rotation starting with the lexicographically smallest element
    min_idx = cycle.index(min(cycle))
    rotated = cycle[min_idx:] + cycle[:min_idx]
    return tuple(rotated)


def detect_cycles(G: nx.DiGraph) -> CycleResult:
    """Detect all unique directed cycles in the attack graph using DFS.

    Uses NetworkX's simple_cycles() which implements Johnson's algorithm
    for finding all elementary circuits, then deduplicates them via
    canonical normalization.

    Args:
        G: The attack graph (NetworkX DiGraph).

    Returns:
        CycleResult containing all unique cycles as node ID and name lists.
    """
    raw_cycles = list(nx.simple_cycles(G))

    # Deduplicate using canonical form
    seen: set[tuple[str, ...]] = set()
    unique_cycles: list[list[str]] = []

    for cycle in raw_cycles:
        canonical = _normalize_cycle(cycle)
        if canonical not in seen:
            seen.add(canonical)
            unique_cycles.append(list(canonical))

    # Convert to names
    cycle_names: list[list[str]] = []
    for cycle in unique_cycles:
        names = [get_node_name(G, node_id) for node_id in cycle]
        cycle_names.append(names)

    return CycleResult(
        cycles=unique_cycles,
        cycle_names=cycle_names,
        total_cycles=len(unique_cycles),
    )


def format_cycles(G: nx.DiGraph, result: CycleResult) -> str:
    """Format cycle detection results for human-readable console output.

    Args:
        G: The attack graph.
        result: CycleResult to format.

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  CYCLE DETECTION (Privilege Escalation Loops)")
    lines.append("=" * 70)
    lines.append(f"  Total Unique Cycles: {result.total_cycles}")
    lines.append("-" * 70)

    if result.total_cycles == 0:
        lines.append("  No cycles detected — graph is a DAG.")
    else:
        for idx, (cycle, names) in enumerate(
            zip(result.cycles, result.cycle_names), 1
        ):
            cycle_path = " → ".join(names) + " → " + names[0]
            lines.append(f"\n  Cycle #{idx}: {cycle_path}")
            lines.append(f"    Length: {len(cycle)} nodes")

            # Show risk of cycle
            total_risk = 0.0
            for i in range(len(cycle)):
                src = cycle[i]
                tgt = cycle[(i + 1) % len(cycle)]
                if G.has_edge(src, tgt):
                    total_risk += G.edges[src, tgt].get("weight", 0.0)

            lines.append(f"    Cycle Risk: {total_risk:.2f}")

    lines.append("=" * 70)
    return "\n".join(lines)
