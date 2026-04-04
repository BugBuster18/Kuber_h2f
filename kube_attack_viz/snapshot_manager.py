"""
Snapshot Manager for KubeAttackViz.

Handles saving, loading, listing, and diffing timestamped JSON snapshots
of the cluster graph. Also generates the timeline data needed by the
HTML timeline visualizer.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import ClusterGraph
from .ingestion import ingest_from_json
from .graph_builder import build_attack_graph, graph_summary
from .temporal import temporal_diff, TemporalDiff


# ─── Default snapshot directory ──────────────────────────────────────────────

DEFAULT_SNAPSHOTS_DIR = Path("snapshots")


def _ensure_dir(directory: Path) -> Path:
    """Create directory if it doesn't exist."""
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def save_snapshot(
    graph: ClusterGraph,
    label: str = "",
    snapshots_dir: Path | str = DEFAULT_SNAPSHOTS_DIR,
    source: str = "manual",
    timestamp: Optional[str] = None,
) -> Path:
    """Save a timestamped snapshot of the cluster graph as JSON.

    Args:
        graph: ClusterGraph to snapshot.
        label: Human-readable label for this snapshot.
        snapshots_dir: Directory to save snapshots in.
        source: Source of the graph data ('json', 'kubectl', 'manual').
        timestamp: ISO format timestamp; defaults to now.

    Returns:
        Path to the saved snapshot file.
    """
    snapshots_dir = Path(snapshots_dir)
    _ensure_dir(snapshots_dir)

    ts = timestamp or datetime.now(timezone.utc).isoformat()
    # Make filesystem-safe timestamp
    safe_ts = ts.replace(":", "-").replace("+", "p").replace(".", "_")

    G = build_attack_graph(graph)
    summary = graph_summary(G)

    snapshot_data = {
        "timestamp": ts,
        "label": label or f"snapshot-{safe_ts}",
        "metadata": {
            "source": source,
            "node_count": summary["total_nodes"],
            "edge_count": summary["total_edges"],
            "source_nodes": summary["source_nodes"],
            "sink_nodes": summary["sink_nodes"],
            "node_types": summary["node_types"],
        },
        "graph": graph.to_dict(),
    }

    filename = f"snap_{safe_ts}.json"
    filepath = snapshots_dir / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(snapshot_data, f, indent=2, default=str)

    return filepath


def list_snapshots(
    snapshots_dir: Path | str = DEFAULT_SNAPSHOTS_DIR,
) -> list[dict]:
    """List all saved snapshots with metadata.

    Args:
        snapshots_dir: Directory containing snapshot files.

    Returns:
        List of dicts with timestamp, label, filename, node_count, edge_count.
        Sorted by timestamp ascending.
    """
    snapshots_dir = Path(snapshots_dir)
    if not snapshots_dir.exists():
        return []

    snapshots = []
    for fp in sorted(snapshots_dir.glob("snap_*.json")):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)
            snapshots.append({
                "timestamp": data.get("timestamp", ""),
                "label": data.get("label", ""),
                "filename": fp.name,
                "filepath": str(fp),
                "node_count": data.get("metadata", {}).get("node_count", 0),
                "edge_count": data.get("metadata", {}).get("edge_count", 0),
                "source": data.get("metadata", {}).get("source", "unknown"),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    return sorted(snapshots, key=lambda x: x["timestamp"])


def load_snapshot(snapshot_path: Path | str) -> dict:
    """Load a specific snapshot from file.

    Args:
        snapshot_path: Path to the snapshot JSON file.

    Returns:
        Full snapshot dict including timestamp, label, metadata, and graph.

    Raises:
        FileNotFoundError: If the file doesn't exist.
    """
    path = Path(snapshot_path)
    if not path.exists():
        raise FileNotFoundError(f"Snapshot file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_snapshot_graph(snapshot_path: Path | str) -> ClusterGraph:
    """Load a ClusterGraph from a snapshot file.

    Args:
        snapshot_path: Path to the snapshot JSON file.

    Returns:
        ClusterGraph from the snapshot.
    """
    data = load_snapshot(snapshot_path)
    return ClusterGraph.from_dict(data["graph"])


def diff_snapshots(
    snap_a_path: Path | str,
    snap_b_path: Path | str,
) -> dict:
    """Diff two snapshots and return structured change data.

    Args:
        snap_a_path: Path to the "before" snapshot.
        snap_b_path: Path to the "after" snapshot.

    Returns:
        Dict with new_nodes, removed_nodes, new_edges, removed_edges counts
        and details.
    """
    snap_a = load_snapshot(snap_a_path)
    snap_b = load_snapshot(snap_b_path)

    graph_a = ClusterGraph.from_dict(snap_a["graph"])
    graph_b = ClusterGraph.from_dict(snap_b["graph"])

    G_a = build_attack_graph(graph_a)
    G_b = build_attack_graph(graph_b)

    # Node diff
    nodes_a = set(G_a.nodes)
    nodes_b = set(G_b.nodes)

    new_nodes = []
    for nid in nodes_b - nodes_a:
        data = G_b.nodes[nid]
        new_nodes.append({
            "id": nid,
            "name": data.get("name", nid),
            "type": data.get("type", "unknown"),
        })

    removed_nodes = []
    for nid in nodes_a - nodes_b:
        data = G_a.nodes[nid]
        removed_nodes.append({
            "id": nid,
            "name": data.get("name", nid),
            "type": data.get("type", "unknown"),
        })

    # Edge diff
    edges_a = {(u, v, d.get("relationship", "")) for u, v, d in G_a.edges(data=True)}
    edges_b = {(u, v, d.get("relationship", "")) for u, v, d in G_b.edges(data=True)}

    new_edges = [
        {"source": e[0], "target": e[1], "relationship": e[2]}
        for e in edges_b - edges_a
    ]
    removed_edges = [
        {"source": e[0], "target": e[1], "relationship": e[2]}
        for e in edges_a - edges_b
    ]

    return {
        "from_timestamp": snap_a.get("timestamp", ""),
        "to_timestamp": snap_b.get("timestamp", ""),
        "from_label": snap_a.get("label", ""),
        "to_label": snap_b.get("label", ""),
        "new_nodes": new_nodes,
        "removed_nodes": removed_nodes,
        "new_edges": new_edges,
        "removed_edges": removed_edges,
        "summary": {
            "nodes_added": len(new_nodes),
            "nodes_removed": len(removed_nodes),
            "edges_added": len(new_edges),
            "edges_removed": len(removed_edges),
            "total_changes": len(new_nodes) + len(removed_nodes) + len(new_edges) + len(removed_edges),
        },
    }


def export_timeline_data(
    snapshots_dir: Path | str = DEFAULT_SNAPSHOTS_DIR,
    output_path: Path | str = "timeline/timeline-data.json",
) -> Path:
    """Generate the timeline data JSON for the HTML timeline visualizer.

    Creates a single JSON file containing all snapshots with their graphs
    and diffs between consecutive snapshots.

    Args:
        snapshots_dir: Directory containing snapshot files.
        output_path: Output JSON file path.

    Returns:
        Path to the generated timeline data file.
    """
    snapshots_dir = Path(snapshots_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    snapshot_list = list_snapshots(snapshots_dir)

    if not snapshot_list:
        # Write empty timeline
        timeline = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "snapshot_count": 0,
            },
            "snapshots": [],
            "diffs": [],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(timeline, f, indent=2)
        return output_path

    # Load all snapshots
    snapshots_data = []
    for snap_info in snapshot_list:
        snap = load_snapshot(snap_info["filepath"])
        graph = ClusterGraph.from_dict(snap["graph"])
        G = build_attack_graph(graph)

        # Build node/edge data for the visualizer
        nodes_viz = []
        for node_id, data in G.nodes(data=True):
            nodes_viz.append({
                "id": node_id,
                "name": data.get("name", node_id),
                "type": data.get("type", "unknown"),
                "namespace": data.get("namespace", ""),
                "risk_score": data.get("risk_score", 0.0),
                "is_source": data.get("is_source", False),
                "is_sink": data.get("is_sink", False),
            })

        edges_viz = []
        for u, v, data in G.edges(data=True):
            edges_viz.append({
                "source": u,
                "target": v,
                "relationship": data.get("relationship", ""),
                "weight": data.get("weight", 1.0),
            })

        snapshots_data.append({
            "timestamp": snap.get("timestamp", ""),
            "label": snap.get("label", ""),
            "metadata": snap.get("metadata", {}),
            "nodes": nodes_viz,
            "edges": edges_viz,
        })

    # Compute diffs between consecutive snapshots
    diffs = []
    for i in range(1, len(snapshot_list)):
        try:
            diff = diff_snapshots(
                snapshot_list[i - 1]["filepath"],
                snapshot_list[i]["filepath"],
            )
            diffs.append(diff)
        except Exception as e:
            diffs.append({
                "from_timestamp": snapshot_list[i - 1]["timestamp"],
                "to_timestamp": snapshot_list[i]["timestamp"],
                "error": str(e),
                "summary": {"total_changes": 0},
            })

    timeline = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_count": len(snapshots_data),
            "tool": "KubeAttackViz",
            "version": "2.0.0",
        },
        "snapshots": snapshots_data,
        "diffs": diffs,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2, default=str)

    return output_path
