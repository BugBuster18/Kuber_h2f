"""
Temporal Analysis Module for KubeAttackViz.

Compares two cluster graph snapshots (old vs new) to detect:
  - New nodes added
  - Nodes removed
  - New edges added
  - Edges removed
  - New attack paths that didn't exist before
"""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass, field

from .ingestion import ingest_from_json
from .graph_builder import build_attack_graph, get_node_name, get_source_nodes, get_sink_nodes
from .algorithms.dijkstra import shortest_attack_path, _severity_label
from .models import AttackPath


@dataclass
class TemporalDiff:
    """Result of comparing two cluster graph snapshots.

    Attributes:
        new_nodes: List of (node_id, name, type) tuples for added nodes.
        removed_nodes: List of (node_id, name, type) tuples for removed nodes.
        new_edges: List of (source, target, relationship) tuples for added edges.
        removed_edges: List of (source, target, relationship) tuples for removed edges.
        new_attack_paths: Attack paths that exist in new but not old graph.
        removed_attack_paths: Attack paths that existed in old but not new graph.
    """

    new_nodes: list[tuple[str, str, str]] = field(default_factory=list)
    removed_nodes: list[tuple[str, str, str]] = field(default_factory=list)
    new_edges: list[tuple[str, str, str]] = field(default_factory=list)
    removed_edges: list[tuple[str, str, str]] = field(default_factory=list)
    new_attack_paths: list[AttackPath] = field(default_factory=list)
    removed_attack_paths: list[AttackPath] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize temporal diff result."""
        return {
            "new_nodes": [
                {"id": n[0], "name": n[1], "type": n[2]} for n in self.new_nodes
            ],
            "removed_nodes": [
                {"id": n[0], "name": n[1], "type": n[2]} for n in self.removed_nodes
            ],
            "new_edges": [
                {"source": e[0], "target": e[1], "relationship": e[2]}
                for e in self.new_edges
            ],
            "removed_edges": [
                {"source": e[0], "target": e[1], "relationship": e[2]}
                for e in self.removed_edges
            ],
            "new_attack_paths": [p.to_dict() for p in self.new_attack_paths],
            "removed_attack_paths": [p.to_dict() for p in self.removed_attack_paths],
        }


def temporal_diff(old_path: str | Path, new_path: str | Path) -> TemporalDiff:
    """Compare two cluster graph JSON snapshots.

    Args:
        old_path: Path to the old/baseline graph JSON.
        new_path: Path to the new/current graph JSON.

    Returns:
        TemporalDiff with all detected changes.
    """
    old_cluster = ingest_from_json(old_path)
    new_cluster = ingest_from_json(new_path)

    old_G = build_attack_graph(old_cluster)
    new_G = build_attack_graph(new_cluster)

    result = TemporalDiff()

    # ── Node diff ────────────────────────────────────────────────────────────
    old_node_ids = set(old_G.nodes)
    new_node_ids = set(new_G.nodes)

    for nid in new_node_ids - old_node_ids:
        data = new_G.nodes[nid]
        result.new_nodes.append((nid, data.get("name", nid), data.get("type", "unknown")))

    for nid in old_node_ids - new_node_ids:
        data = old_G.nodes[nid]
        result.removed_nodes.append((nid, data.get("name", nid), data.get("type", "unknown")))

    # ── Edge diff ────────────────────────────────────────────────────────────
    old_edges = set()
    for u, v, d in old_G.edges(data=True):
        old_edges.add((u, v, d.get("relationship", "")))

    new_edges = set()
    for u, v, d in new_G.edges(data=True):
        new_edges.add((u, v, d.get("relationship", "")))

    result.new_edges = list(new_edges - old_edges)
    result.removed_edges = list(old_edges - new_edges)

    # ── Attack path diff ─────────────────────────────────────────────────────
    old_path_keys = _compute_path_keys(old_G)
    new_path_keys = _compute_path_keys(new_G)

    # New paths: exist in new but not old
    for key, path in new_path_keys.items():
        if key not in old_path_keys:
            result.new_attack_paths.append(path)

    # Removed paths: existed in old but not new
    for key, path in old_path_keys.items():
        if key not in new_path_keys:
            result.removed_attack_paths.append(path)

    return result


def _compute_path_keys(G):
    """Compute all source→sink shortest paths and return keyed by (src, sink) tuple."""
    sources = get_source_nodes(G)
    sinks = get_sink_nodes(G)
    path_map = {}

    for src in sources:
        for sink in sinks:
            path = shortest_attack_path(G, src, sink)
            if path is not None:
                key = (src, sink)
                path_map[key] = path

    return path_map


def format_temporal_diff(diff: TemporalDiff) -> str:
    """Format temporal diff for human-readable console output.

    Args:
        diff: TemporalDiff result.

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  TEMPORAL ANALYSIS — CLUSTER DIFF")
    lines.append("=" * 70)

    # New nodes
    lines.append(f"\n  ➕ New Nodes: {len(diff.new_nodes)}")
    for nid, name, ntype in diff.new_nodes:
        lines.append(f"    + {name} [{ntype}]")

    # Removed nodes
    lines.append(f"\n  ➖ Removed Nodes: {len(diff.removed_nodes)}")
    for nid, name, ntype in diff.removed_nodes:
        lines.append(f"    - {name} [{ntype}]")

    # New edges
    lines.append(f"\n  ➕ New Edges: {len(diff.new_edges)}")
    for src, tgt, rel in diff.new_edges[:10]:  # Limit display
        lines.append(f"    + {src} ──[{rel}]──▸ {tgt}")
    if len(diff.new_edges) > 10:
        lines.append(f"    ... and {len(diff.new_edges) - 10} more")

    # Removed edges
    lines.append(f"\n  ➖ Removed Edges: {len(diff.removed_edges)}")
    for src, tgt, rel in diff.removed_edges[:10]:
        lines.append(f"    - {src} ──[{rel}]──▸ {tgt}")
    if len(diff.removed_edges) > 10:
        lines.append(f"    ... and {len(diff.removed_edges) - 10} more")

    # New attack paths
    lines.append(f"\n  🔴 New Attack Paths: {len(diff.new_attack_paths)}")
    for path in diff.new_attack_paths:
        lines.append(f"    ⚡ {' → '.join(path.path_names)} (risk: {path.total_risk:.2f}, severity: {path.severity})")

    # Removed attack paths
    lines.append(f"\n  ✅ Eliminated Attack Paths: {len(diff.removed_attack_paths)}")
    for path in diff.removed_attack_paths:
        lines.append(f"    ✓ {' → '.join(path.path_names)} (was risk: {path.total_risk:.2f})")

    lines.append("=" * 70)
    return "\n".join(lines)
