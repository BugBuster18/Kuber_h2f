"""
Node Risk Amplification Module for KubeAttackViz.

Computes amplified node risk scores based on:
  - Base risk score (from node data)
  - Path centrality (how many attack paths pass through this node)
  - Degree centrality (connectivity)
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from .graph_builder import get_node_name, get_source_nodes, get_sink_nodes


@dataclass
class NodeRiskEntry:
    """Risk entry for a single node.

    Attributes:
        node_id: Node identifier.
        name: Human-readable name.
        node_type: Kubernetes resource type.
        base_risk: Original risk score.
        paths_through: Number of source→sink paths passing through this node.
        amplified_risk: Final computed risk after amplification.
    """

    node_id: str
    name: str
    node_type: str
    base_risk: float
    paths_through: int
    amplified_risk: float

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "type": self.node_type,
            "base_risk": self.base_risk,
            "paths_through": self.paths_through,
            "amplified_risk": round(self.amplified_risk, 2),
        }


def compute_node_risk_amplification(
    G: nx.DiGraph,
    cutoff: int = 15,
) -> list[NodeRiskEntry]:
    """Compute amplified risk scores for all nodes.

    For each node, counts how many source→sink simple paths pass
    through it, then amplifies the base risk accordingly:

        amplified_risk = base_risk * (1 + log2(1 + paths_through))

    Args:
        G: The attack graph.
        cutoff: Max path length for all_simple_paths.

    Returns:
        List of NodeRiskEntry, sorted by amplified_risk descending.
    """
    import math

    sources = get_source_nodes(G)
    sinks = get_sink_nodes(G)

    # Count paths through each node
    path_counts: dict[str, int] = {n: 0 for n in G.nodes}

    for src in sources:
        for sink in sinks:
            try:
                for path in nx.all_simple_paths(G, src, sink, cutoff=cutoff):
                    for node_id in path:
                        path_counts[node_id] += 1
            except nx.NodeNotFound:
                continue

    # Compute amplified risk
    entries: list[NodeRiskEntry] = []
    for node_id, data in G.nodes(data=True):
        base_risk = data.get("risk_score", 0.0)
        pt = path_counts.get(node_id, 0)
        amplified = base_risk * (1 + math.log2(1 + pt))

        entries.append(
            NodeRiskEntry(
                node_id=node_id,
                name=data.get("name", node_id),
                node_type=data.get("type", "unknown"),
                base_risk=base_risk,
                paths_through=pt,
                amplified_risk=amplified,
            )
        )

    entries.sort(key=lambda e: e.amplified_risk, reverse=True)
    return entries


def format_node_risk(entries: list[NodeRiskEntry], top_n: int = 10) -> str:
    """Format node risk amplification results.

    Args:
        entries: List of NodeRiskEntry.
        top_n: Number of top nodes to show.

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  NODE RISK AMPLIFICATION (Path Centrality)")
    lines.append("=" * 70)
    lines.append(f"  {'Rank':<6}{'Name':<25}{'Type':<18}{'Base':>6}{'Paths':>7}{'Amplified':>10}")
    lines.append("  " + "-" * 66)

    for idx, entry in enumerate(entries[:top_n], 1):
        lines.append(
            f"  {idx:<6}{entry.name:<25}{entry.node_type:<18}"
            f"{entry.base_risk:>6.1f}{entry.paths_through:>7}"
            f"{entry.amplified_risk:>10.2f}"
        )

    lines.append("=" * 70)
    return "\n".join(lines)
