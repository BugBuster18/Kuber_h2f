"""
Graph Construction Module for KubeAttackViz.

Converts the ClusterGraph data model into a NetworkX DiGraph with
proper node/edge attributes for algorithmic analysis.
"""

from __future__ import annotations

import networkx as nx

from .models import ClusterGraph, NodeData, EdgeData


def build_attack_graph(cluster: ClusterGraph, use_cvss_weights: bool = True) -> nx.DiGraph:
    """Construct a NetworkX directed graph from parsed cluster data.

    Ensures:
      - All nodes have type, namespace, risk_score, cves, is_source, is_sink attributes.
      - All edges have relationship, weight, cve, cvss attributes.
      - No missing node references — edges with dangling node IDs are skipped.
      - No duplicate edges (same source, target, relationship).

    Args:
        cluster: Parsed ClusterGraph containing nodes and edges.
        use_cvss_weights: Whether to reduce edge weights based on CVSS scores.

    Returns:
        NetworkX DiGraph ready for algorithmic analysis.
    """
    G = nx.DiGraph()

    # ── Add nodes ────────────────────────────────────────────────────────────
    node_ids: set[str] = set()
    for node in cluster.nodes:
        node_ids.add(node.id)
        G.add_node(
            node.id,
            type=node.type,
            name=node.name,
            namespace=node.namespace,
            risk_score=node.risk_score,
            is_source=node.is_source,
            is_sink=node.is_sink,
            cves=node.cves,
        )

    # ── Add edges (skip dangling refs, deduplicate) ──────────────────────────
    seen_edges: set[tuple[str, str, str]] = set()
    skipped_edges = 0

    for edge in cluster.edges:
        # Guard: skip edges referencing missing nodes
        if edge.source not in node_ids:
            skipped_edges += 1
            continue
        if edge.target not in node_ids:
            skipped_edges += 1
            continue

        edge_key = (edge.source, edge.target, edge.relationship)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        # Dynamic Weight Adjustment:
        # Lower weight = Easier path for Dijkstra.
        base_cost = float(edge.weight)
        effective_cost = base_cost

        if use_cvss_weights and edge.cvss is not None:
            # Formula: weight reduced by CVSS percentage.
            reduction = edge.cvss / 10.0
            effective_cost = max(0.1, base_cost * (1.0 - reduction))

        G.add_edge(
            edge.source,
            edge.target,
            relationship=edge.relationship,
            weight=effective_cost,
            base_cost=base_cost,  # preserved for auditing
            cve=edge.cve,
            cvss=edge.cvss,
        )

    if skipped_edges > 0:
        import sys

        print(
            f"[WARN] Skipped {skipped_edges} edge(s) referencing missing nodes.",
            file=sys.stderr,
        )

    return G


def get_source_nodes(G: nx.DiGraph) -> list[str]:
    """Return all nodes flagged as attack entry points (is_source=True).

    Args:
        G: The attack graph.

    Returns:
        List of source node IDs.
    """
    return [n for n, d in G.nodes(data=True) if d.get("is_source", False)]


def get_sink_nodes(G: nx.DiGraph) -> list[str]:
    """Return all nodes flagged as high-value targets (is_sink=True).

    Args:
        G: The attack graph.

    Returns:
        List of sink node IDs.
    """
    return [n for n, d in G.nodes(data=True) if d.get("is_sink", False)]


def get_node_name(G: nx.DiGraph, node_id: str) -> str:
    """Get the human-readable name for a node.

    Args:
        G: The attack graph.
        node_id: Node identifier.

    Returns:
        Human-readable name, or the node_id itself if not found.
    """
    if node_id in G.nodes:
        return G.nodes[node_id].get("name", node_id)
    return node_id


def resolve_node_id(G: nx.DiGraph, identifier: str) -> str | None:
    """Resolve a user-provided identifier to a graph node ID.

    Supports matching by:
      - Exact node ID
      - Node name (case-insensitive)
      - Partial ID match

    Args:
        G: The attack graph.
        identifier: User-provided node name or ID.

    Returns:
        Matched node ID, or None if no match found.
    """
    # Exact ID match
    if identifier in G.nodes:
        return identifier

    # Name match (case-insensitive)
    for node_id, data in G.nodes(data=True):
        if data.get("name", "").lower() == identifier.lower():
            return node_id

    # Partial ID match
    matches = [n for n in G.nodes if identifier.lower() in n.lower()]
    if len(matches) == 1:
        return matches[0]

    return None


def graph_summary(G: nx.DiGraph) -> dict:
    """Generate a summary of the attack graph.

    Args:
        G: The attack graph.

    Returns:
        Dictionary with node/edge counts, type distributions, etc.
    """
    type_counts: dict[str, int] = {}
    for _, data in G.nodes(data=True):
        t = data.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    rel_counts: dict[str, int] = {}
    for _, _, data in G.edges(data=True):
        r = data.get("relationship", "unknown")
        rel_counts[r] = rel_counts.get(r, 0) + 1

    sources = get_source_nodes(G)
    sinks = get_sink_nodes(G)

    return {
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "node_types": type_counts,
        "relationship_types": rel_counts,
        "source_nodes": len(sources),
        "sink_nodes": len(sinks),
        "is_dag": nx.is_directed_acyclic_graph(G),
        "weakly_connected_components": nx.number_weakly_connected_components(G),
    }
