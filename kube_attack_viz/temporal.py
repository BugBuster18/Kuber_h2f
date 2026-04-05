"""
Temporal Analysis Module for KubeAttackViz.

Industry-grade continuous monitoring system that:
  1. Periodically snapshots the cluster state from JSON files.
  2. Stores snapshots in-memory with automatic disk persistence.
  3. Diffs consecutive snapshots to detect:
       - New/removed nodes
       - New/removed edges
       - New/removed attack paths
  4. Generates alerts when new attack paths appear.
  5. Exports diff graphs to Neo4j for persistent investigation.

Architecture:
  SnapshotStore  — Manages ordered snapshots (in-memory + JSON on disk).
  TemporalDiff   — Result object for a single diff.
  AlertEngine    — Evaluates diffs and produces structured alerts.
  Neo4jExporter  — Pushes diff subgraphs into a Neo4j database.
  TemporalWatcher— Orchestrates periodic scan → diff → alert → export loop.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import time
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import networkx as nx

from .ingestion import ingest_from_json, export_graph_to_json
from .graph_builder import build_attack_graph, get_node_name, get_source_nodes, get_sink_nodes
from .algorithms.dijkstra import shortest_attack_path, _severity_label
from .models import AttackPath, ClusterGraph

logger = logging.getLogger("kubeattackviz.temporal")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Data Models                                                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@dataclass
class Snapshot:
    """A point-in-time capture of the cluster state.

    Attributes:
        snapshot_id: Unique identifier (SHA-256 of content + timestamp).
        timestamp: ISO-8601 capture time.
        cluster_data: Serialized ClusterGraph dictionary.
        graph_hash: Content hash for quick equality check.
        source: Origin of the snapshot ("json:<path>", etc.).
        metadata: Arbitrary metadata (cluster name, context, etc.).
    """

    snapshot_id: str
    timestamp: str
    cluster_data: dict
    graph_hash: str
    source: str = "unknown"
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Snapshot:
        return cls(**data)

    @classmethod
    def from_cluster(
        cls,
        cluster: ClusterGraph,
        source: str = "unknown",
        metadata: dict | None = None,
    ) -> Snapshot:
        """Create a snapshot from a live ClusterGraph."""
        data = cluster.to_dict()
        content = json.dumps(data, sort_keys=True)
        ts = datetime.now(timezone.utc).isoformat()
        graph_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        snapshot_id = hashlib.sha256(f"{ts}:{content}".encode()).hexdigest()[:24]
        return cls(
            snapshot_id=snapshot_id,
            timestamp=ts,
            cluster_data=data,
            graph_hash=graph_hash,
            source=source,
            metadata=metadata or {},
        )


@dataclass
class TemporalAlert:
    """A structured security alert produced from a temporal diff.

    Attributes:
        alert_id: Unique alert identifier.
        severity: CRITICAL | HIGH | MEDIUM | LOW | INFO.
        category: Alert category (NEW_ATTACK_PATH, NEW_NODE, REMOVED_CONTROL, etc.).
        title: Human-readable one-line summary.
        description: Detailed description.
        timestamp: When the alert was generated.
        diff_ref: Reference to the TemporalDiff that triggered this alert.
        details: Additional structured data for the alert.
    """

    alert_id: str
    severity: str
    category: str
    title: str
    description: str
    timestamp: str
    diff_ref: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TemporalDiff:
    """Result of comparing two cluster graph snapshots.

    Attributes:
        diff_id: Unique identifier for this diff.
        old_snapshot_id: ID of the baseline snapshot.
        new_snapshot_id: ID of the current snapshot.
        timestamp: When the diff was computed.
        new_nodes: List of (node_id, name, type) tuples for added nodes.
        removed_nodes: List of (node_id, name, type) tuples for removed nodes.
        new_edges: List of (source, target, relationship) tuples for added edges.
        removed_edges: List of (source, target, relationship) tuples for removed edges.
        new_attack_paths: Attack paths that exist in new but not old graph.
        removed_attack_paths: Attack paths that existed in old but not new graph.
        alerts: List of generated alerts.
        has_changes: Quick check for any structural changes.
    """

    diff_id: str = ""
    old_snapshot_id: str = ""
    new_snapshot_id: str = ""
    timestamp: str = ""
    new_nodes: list[tuple[str, str, str]] = field(default_factory=list)
    removed_nodes: list[tuple[str, str, str]] = field(default_factory=list)
    new_edges: list[tuple[str, str, str]] = field(default_factory=list)
    removed_edges: list[tuple[str, str, str]] = field(default_factory=list)
    new_attack_paths: list[AttackPath] = field(default_factory=list)
    removed_attack_paths: list[AttackPath] = field(default_factory=list)
    alerts: list[TemporalAlert] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_nodes
            or self.removed_nodes
            or self.new_edges
            or self.removed_edges
            or self.new_attack_paths
            or self.removed_attack_paths
        )

    def to_dict(self) -> dict:
        return {
            "diff_id": self.diff_id,
            "old_snapshot_id": self.old_snapshot_id,
            "new_snapshot_id": self.new_snapshot_id,
            "timestamp": self.timestamp,
            "has_changes": self.has_changes,
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
            "alerts": [a.to_dict() for a in self.alerts],
            "summary": {
                "new_nodes_count": len(self.new_nodes),
                "removed_nodes_count": len(self.removed_nodes),
                "new_edges_count": len(self.new_edges),
                "removed_edges_count": len(self.removed_edges),
                "new_attack_paths_count": len(self.new_attack_paths),
                "removed_attack_paths_count": len(self.removed_attack_paths),
                "alert_count": len(self.alerts),
            },
        }


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Snapshot Store                                                             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


class SnapshotStore:
    """Thread-safe, ordered storage for cluster snapshots.

    Supports:
      - In-memory storage with configurable max retention.
      - Automatic JSON persistence to disk.
      - Retrieval of latest, previous, and arbitrary snapshots.
    """

    def __init__(
        self,
        persist_dir: str | Path | None = None,
        max_snapshots: int = 100,
    ):
        self._snapshots: list[Snapshot] = []
        self._lock = threading.Lock()
        self._max = max_snapshots
        self._persist_dir: Path | None = None

        if persist_dir:
            self._persist_dir = Path(persist_dir)
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            self._load_from_disk()

    def _load_from_disk(self) -> None:
        """Hydrate store from persisted JSON files on disk."""
        if not self._persist_dir:
            return
        index_file = self._persist_dir / "snapshot_index.json"
        if not index_file.exists():
            return
        try:
            with open(index_file, "r", encoding="utf-8") as f:
                index = json.load(f)
            for entry in index.get("snapshots", []):
                snap_file = self._persist_dir / f"{entry['snapshot_id']}.json"
                if snap_file.exists():
                    with open(snap_file, "r", encoding="utf-8") as sf:
                        snap_data = json.load(sf)
                    self._snapshots.append(Snapshot.from_dict(snap_data))
            # Sort by timestamp
            self._snapshots.sort(key=lambda s: s.timestamp)
            logger.info(f"Loaded {len(self._snapshots)} snapshots from disk.")
        except Exception as e:
            logger.warning(f"Failed to load snapshots from disk: {e}")

    def _persist_snapshot(self, snapshot: Snapshot) -> None:
        """Write a single snapshot to disk."""
        if not self._persist_dir:
            return
        try:
            snap_file = self._persist_dir / f"{snapshot.snapshot_id}.json"
            with open(snap_file, "w", encoding="utf-8") as f:
                json.dump(snapshot.to_dict(), f, indent=2)
            self._save_index()
        except Exception as e:
            logger.warning(f"Failed to persist snapshot: {e}")

    def _save_index(self) -> None:
        """Update the snapshot index file."""
        if not self._persist_dir:
            return
        index = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(self._snapshots),
            "snapshots": [
                {
                    "snapshot_id": s.snapshot_id,
                    "timestamp": s.timestamp,
                    "graph_hash": s.graph_hash,
                    "source": s.source,
                }
                for s in self._snapshots
            ],
        }
        index_file = self._persist_dir / "snapshot_index.json"
        with open(index_file, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2)

    def add(self, snapshot: Snapshot) -> None:
        """Add a snapshot to the store."""
        with self._lock:
            self._snapshots.append(snapshot)
            # Evict oldest if over capacity
            if len(self._snapshots) > self._max:
                evicted = self._snapshots.pop(0)
                if self._persist_dir:
                    evicted_file = self._persist_dir / f"{evicted.snapshot_id}.json"
                    if evicted_file.exists():
                        evicted_file.unlink()
            self._persist_snapshot(snapshot)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._snapshots)

    @property
    def latest(self) -> Snapshot | None:
        with self._lock:
            return self._snapshots[-1] if self._snapshots else None

    @property
    def previous(self) -> Snapshot | None:
        with self._lock:
            return self._snapshots[-2] if len(self._snapshots) >= 2 else None

    def get_all(self) -> list[Snapshot]:
        with self._lock:
            return list(self._snapshots)

    def get_by_id(self, snapshot_id: str) -> Snapshot | None:
        with self._lock:
            for s in self._snapshots:
                if s.snapshot_id == snapshot_id:
                    return s
            return None

    def get_consecutive_pairs(self) -> list[tuple[Snapshot, Snapshot]]:
        """Return all consecutive (old, new) snapshot pairs."""
        with self._lock:
            pairs = []
            for i in range(len(self._snapshots) - 1):
                pairs.append((self._snapshots[i], self._snapshots[i + 1]))
            return pairs


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Diff Engine                                                                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def _compute_path_keys(G: nx.DiGraph) -> dict[tuple[str, str], AttackPath]:
    """Compute all source→sink shortest paths and return keyed by (src, sink)."""
    sources = get_source_nodes(G)
    sinks = get_sink_nodes(G)
    path_map = {}
    for src in sources:
        for sink in sinks:
            path = shortest_attack_path(G, src, sink)
            if path is not None:
                path_map[(src, sink)] = path
    return path_map


def temporal_diff(
    old_path: str | Path,
    new_path: str | Path,
) -> TemporalDiff:
    """Compare two cluster graph JSON snapshots (file-based API).

    Args:
        old_path: Path to the old/baseline graph JSON.
        new_path: Path to the new/current graph JSON.

    Returns:
        TemporalDiff with all detected changes and generated alerts.
    """
    old_cluster = ingest_from_json(old_path)
    new_cluster = ingest_from_json(new_path)
    return diff_clusters(old_cluster, new_cluster)


def diff_clusters(
    old_cluster: ClusterGraph,
    new_cluster: ClusterGraph,
    old_snapshot_id: str = "",
    new_snapshot_id: str = "",
) -> TemporalDiff:
    """Compare two ClusterGraph objects.

    Core diffing engine used by both file-based and snapshot-based workflows.

    Args:
        old_cluster: Baseline cluster graph.
        new_cluster: Current cluster graph.
        old_snapshot_id: Optional ID reference for the old snapshot.
        new_snapshot_id: Optional ID reference for the new snapshot.

    Returns:
        TemporalDiff with changes and alerts.
    """
    old_G = build_attack_graph(old_cluster)
    new_G = build_attack_graph(new_cluster)

    ts = datetime.now(timezone.utc).isoformat()
    diff_id = hashlib.sha256(
        f"{old_snapshot_id}:{new_snapshot_id}:{ts}".encode()
    ).hexdigest()[:16]

    result = TemporalDiff(
        diff_id=diff_id,
        old_snapshot_id=old_snapshot_id,
        new_snapshot_id=new_snapshot_id,
        timestamp=ts,
    )

    # ── Node diff ──────────────────────────────────────────────────────
    old_node_ids = set(old_G.nodes)
    new_node_ids = set(new_G.nodes)

    for nid in sorted(new_node_ids - old_node_ids):
        data = new_G.nodes[nid]
        result.new_nodes.append(
            (nid, data.get("name", nid), data.get("type", "unknown"))
        )

    for nid in sorted(old_node_ids - new_node_ids):
        data = old_G.nodes[nid]
        result.removed_nodes.append(
            (nid, data.get("name", nid), data.get("type", "unknown"))
        )

    # ── Edge diff ──────────────────────────────────────────────────────
    old_edges = set()
    for u, v, d in old_G.edges(data=True):
        old_edges.add((u, v, d.get("relationship", "")))

    new_edges = set()
    for u, v, d in new_G.edges(data=True):
        new_edges.add((u, v, d.get("relationship", "")))

    result.new_edges = sorted(new_edges - old_edges)
    result.removed_edges = sorted(old_edges - new_edges)

    # ── Attack path diff ───────────────────────────────────────────────
    old_path_keys = _compute_path_keys(old_G)
    new_path_keys = _compute_path_keys(new_G)

    for key, path in new_path_keys.items():
        if key not in old_path_keys:
            result.new_attack_paths.append(path)

    for key, path in old_path_keys.items():
        if key not in new_path_keys:
            result.removed_attack_paths.append(path)

    # ── Generate alerts ────────────────────────────────────────────────
    result.alerts = AlertEngine.evaluate(result)

    return result


def diff_snapshots(old: Snapshot, new: Snapshot) -> TemporalDiff:
    """Compare two Snapshot objects.

    Args:
        old: Baseline snapshot.
        new: Current snapshot.

    Returns:
        TemporalDiff with changes and alerts.
    """
    old_cluster = ClusterGraph.from_dict(old.cluster_data)
    new_cluster = ClusterGraph.from_dict(new.cluster_data)
    return diff_clusters(
        old_cluster,
        new_cluster,
        old_snapshot_id=old.snapshot_id,
        new_snapshot_id=new.snapshot_id,
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Alert Engine                                                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


class AlertEngine:
    """Evaluates a TemporalDiff and produces security alerts.

    Alert categories:
      - NEW_ATTACK_PATH: A new source→sink attack path has appeared.
      - NEW_HIGH_RISK_NODE: A sink or high-risk node was added.
      - SECURITY_CONTROL_REMOVED: A node/edge that was providing defense was removed.
      - ATTACK_SURFACE_EXPANDED: New edges increase the attack surface.
      - PRIVILEGE_PATH_ADDED: New edge with escalation relationship.
    """

    _ESCALATION_RELS = {
        "escalates_to", "grants", "accesses", "admin-over",
        "binds_to", "runs_as",
    }
    _SINK_TYPES = {"secret", "database", "node"}

    @classmethod
    def evaluate(cls, diff: TemporalDiff) -> list[TemporalAlert]:
        """Generate all applicable alerts from a diff."""
        alerts: list[TemporalAlert] = []
        ts = datetime.now(timezone.utc).isoformat()
        counter = 0

        def _make_id() -> str:
            nonlocal counter
            counter += 1
            return f"ALERT-{diff.diff_id[:8]}-{counter:03d}"

        # 1. New attack paths (most critical)
        for path in diff.new_attack_paths:
            severity = path.severity
            # Escalate alert severity for critical/high paths
            alert_sev = (
                "CRITICAL" if severity in ("CRITICAL", "HIGH") else
                "HIGH" if severity == "MEDIUM" else "MEDIUM"
            )
            alerts.append(TemporalAlert(
                alert_id=_make_id(),
                severity=alert_sev,
                category="NEW_ATTACK_PATH",
                title=f"New attack path: {' → '.join(path.path_names)}",
                description=(
                    f"A new {severity}-severity attack path has been detected "
                    f"with {path.hop_count} hops and total risk score {path.total_risk:.2f}. "
                    f"Path: {' → '.join(path.path_names)}."
                ),
                timestamp=ts,
                diff_ref=diff.diff_id,
                details=path.to_dict(),
            ))

        # 2. New high-value nodes (sinks, high-risk)
        for nid, name, ntype in diff.new_nodes:
            if ntype.lower() in cls._SINK_TYPES:
                alerts.append(TemporalAlert(
                    alert_id=_make_id(),
                    severity="HIGH",
                    category="NEW_HIGH_RISK_NODE",
                    title=f"New high-value target: {name} ({ntype})",
                    description=(
                        f"A new {ntype} node '{name}' has been added to the cluster. "
                        f"This resource type is considered a high-value target."
                    ),
                    timestamp=ts,
                    diff_ref=diff.diff_id,
                    details={"node_id": nid, "name": name, "type": ntype},
                ))

        # 3. Escalation edges added
        for src, tgt, rel in diff.new_edges:
            if rel in cls._ESCALATION_RELS:
                alerts.append(TemporalAlert(
                    alert_id=_make_id(),
                    severity="HIGH",
                    category="PRIVILEGE_PATH_ADDED",
                    title=f"Privilege path: {src} →[{rel}]→ {tgt}",
                    description=(
                        f"A new '{rel}' relationship was added from '{src}' to '{tgt}'. "
                        f"This may enable privilege escalation."
                    ),
                    timestamp=ts,
                    diff_ref=diff.diff_id,
                    details={"source": src, "target": tgt, "relationship": rel},
                ))

        # 4. Security controls removed (nodes gone that were intermediaries)
        for nid, name, ntype in diff.removed_nodes:
            if ntype.lower() in ("role", "clusterrole", "networkpolicy"):
                alerts.append(TemporalAlert(
                    alert_id=_make_id(),
                    severity="MEDIUM",
                    category="SECURITY_CONTROL_REMOVED",
                    title=f"Security control removed: {name} ({ntype})",
                    description=(
                        f"The {ntype} '{name}' has been removed from the cluster. "
                        f"Verify that access controls remain intact."
                    ),
                    timestamp=ts,
                    diff_ref=diff.diff_id,
                    details={"node_id": nid, "name": name, "type": ntype},
                ))

        # 5. Attack surface expansion (general new edges)
        non_escalation_new = [
            e for e in diff.new_edges if e[2] not in cls._ESCALATION_RELS
        ]
        if len(non_escalation_new) > 5:
            alerts.append(TemporalAlert(
                alert_id=_make_id(),
                severity="MEDIUM",
                category="ATTACK_SURFACE_EXPANDED",
                title=f"Attack surface expanded: {len(diff.new_edges)} new edges",
                description=(
                    f"The cluster added {len(diff.new_edges)} new edges "
                    f"({len(non_escalation_new)} non-escalation). "
                    f"Review for unintended access grants."
                ),
                timestamp=ts,
                diff_ref=diff.diff_id,
                details={"total_new_edges": len(diff.new_edges)},
            ))

        # 6. Info: Attack paths eliminated (positive)
        if diff.removed_attack_paths:
            alerts.append(TemporalAlert(
                alert_id=_make_id(),
                severity="INFO",
                category="ATTACK_PATH_ELIMINATED",
                title=f"{len(diff.removed_attack_paths)} attack path(s) eliminated",
                description=(
                    f"Good news: {len(diff.removed_attack_paths)} previously known "
                    f"attack paths are no longer reachable."
                ),
                timestamp=ts,
                diff_ref=diff.diff_id,
                details={
                    "paths": [
                        " → ".join(p.path_names) for p in diff.removed_attack_paths
                    ]
                },
            ))

        return alerts


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Neo4j Exporter                                                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


class Neo4jExporter:
    """Exports temporal diff graphs and alerts to a Neo4j database.

    Creates a layered temporal graph in Neo4j:
      - (:Snapshot {id, timestamp, source})
      - (:DiffEvent {id, timestamp, has_changes})
      - (:Alert {id, severity, category, title})
      - (:ClusterNode {id, name, type})  — with :NewNode / :RemovedNode labels
      - [:DIFF_FROM], [:DIFF_TO], [:TRIGGERED], [:ADDED], [:REMOVED]
      - [:ATTACK_PATH_ADDED], [:ATTACK_PATH_REMOVED]

    Thread-safe and connection-pooled for production use.
    """

    def __init__(
        self,
        uri: str = "neo4j+s://e64992c1.databases.neo4j.io",
        user: str = "e64992c1",
        password: str = "qdcx2SZBRb7alCDWJqn1up5ByNl527G-SUdnvcbC9m0",
        database: str | None = None,
    ):
        self._uri = uri
        self._user = user
        self._password = password
        self._database = None
        self._driver = None

    def _get_driver(self):
        """Lazy-initialize the Neo4j driver."""
        if self._driver is None:
            try:
                from neo4j import GraphDatabase
                self._driver = GraphDatabase.driver(
                    self._uri, auth=(self._user, self._password)
                )
                logger.info(f"Connected to Neo4j at {self._uri}")
            except ImportError:
                logger.error(
                    "neo4j package not installed. Run: pip install neo4j"
                )
                raise
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {e}")
                raise
        return self._driver

    def close(self):
        """Close the Neo4j driver connection."""
        if self._driver:
            self._driver.close()
            self._driver = None

    def ensure_constraints(self) -> None:
        """Create Neo4j indexes and constraints for optimal performance."""
        driver = self._get_driver()
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Snapshot) REQUIRE s.snapshot_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (d:DiffEvent) REQUIRE d.diff_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (n:ClusterNode) ON (n.node_id)",
            "CREATE INDEX IF NOT EXISTS FOR (a:Alert) ON (a.severity)",
            "CREATE INDEX IF NOT EXISTS FOR (d:DiffEvent) ON (d.timestamp)",
        ]
        with driver.session(database=self._database) as session:
            for cypher in constraints:
                session.run(cypher)

    def export_diff(
        self,
        diff: TemporalDiff,
        old_snapshot: Snapshot | None = None,
        new_snapshot: Snapshot | None = None,
    ) -> dict[str, int]:
        """Export a temporal diff to Neo4j.

        Returns:
            Dictionary with counts of created entities.
        """
        driver = self._get_driver()
        stats = {"snapshots": 0, "diffs": 0, "alerts": 0, "nodes": 0, "edges": 0}

        with driver.session(database=self._database) as session:
            # 1. Create/merge snapshot nodes
            if old_snapshot:
                session.run(
                    """
                    MERGE (s:Snapshot {snapshot_id: $sid})
                    ON CREATE SET s.timestamp = $ts, s.source = $src,
                                  s.graph_hash = $hash
                    """,
                    sid=old_snapshot.snapshot_id,
                    ts=old_snapshot.timestamp,
                    src=old_snapshot.source,
                    hash=old_snapshot.graph_hash,
                )
                stats["snapshots"] += 1

            if new_snapshot:
                session.run(
                    """
                    MERGE (s:Snapshot {snapshot_id: $sid})
                    ON CREATE SET s.timestamp = $ts, s.source = $src,
                                  s.graph_hash = $hash
                    """,
                    sid=new_snapshot.snapshot_id,
                    ts=new_snapshot.timestamp,
                    src=new_snapshot.source,
                    hash=new_snapshot.graph_hash,
                )
                stats["snapshots"] += 1

            # 2. Create DiffEvent node
            session.run(
                """
                MERGE (d:DiffEvent {diff_id: $did})
                ON CREATE SET d.timestamp = $ts,
                              d.has_changes = $changes,
                              d.new_nodes_count = $nn,
                              d.removed_nodes_count = $rn,
                              d.new_edges_count = $ne,
                              d.removed_edges_count = $re,
                              d.new_paths_count = $np,
                              d.removed_paths_count = $rp
                """,
                did=diff.diff_id,
                ts=diff.timestamp,
                changes=diff.has_changes,
                nn=len(diff.new_nodes),
                rn=len(diff.removed_nodes),
                ne=len(diff.new_edges),
                re=len(diff.removed_edges),
                np=len(diff.new_attack_paths),
                rp=len(diff.removed_attack_paths),
            )
            stats["diffs"] += 1

            # Link diff to snapshots
            if old_snapshot:
                session.run(
                    """
                    MATCH (d:DiffEvent {diff_id: $did})
                    MATCH (s:Snapshot {snapshot_id: $sid})
                    MERGE (d)-[:DIFF_FROM]->(s)
                    """,
                    did=diff.diff_id,
                    sid=old_snapshot.snapshot_id,
                )
            if new_snapshot:
                session.run(
                    """
                    MATCH (d:DiffEvent {diff_id: $did})
                    MATCH (s:Snapshot {snapshot_id: $sid})
                    MERGE (d)-[:DIFF_TO]->(s)
                    """,
                    did=diff.diff_id,
                    sid=new_snapshot.snapshot_id,
                )

            # 3. Create new/removed node entities
            for nid, name, ntype in diff.new_nodes:
                session.run(
                    """
                    MERGE (n:ClusterNode {node_id: $nid})
                    SET n.name = $name, n.type = $ntype, n:NewNode
                    WITH n
                    MATCH (d:DiffEvent {diff_id: $did})
                    MERGE (d)-[:ADDED]->(n)
                    """,
                    nid=nid, name=name, ntype=ntype, did=diff.diff_id,
                )
                stats["nodes"] += 1

            for nid, name, ntype in diff.removed_nodes:
                session.run(
                    """
                    MERGE (n:ClusterNode {node_id: $nid})
                    SET n.name = $name, n.type = $ntype, n:RemovedNode
                    WITH n
                    MATCH (d:DiffEvent {diff_id: $did})
                    MERGE (d)-[:REMOVED]->(n)
                    """,
                    nid=nid, name=name, ntype=ntype, did=diff.diff_id,
                )
                stats["nodes"] += 1

            # 4. Create edge-level diff relationships
            for src, tgt, rel in diff.new_edges:
                session.run(
                    """
                    MERGE (s:ClusterNode {node_id: $src})
                    MERGE (t:ClusterNode {node_id: $tgt})
                    MERGE (s)-[r:ATTACK_EDGE {relationship: $rel, diff_id: $did}]->(t)
                    SET r.status = 'ADDED'
                    """,
                    src=src, tgt=tgt, rel=rel, did=diff.diff_id,
                )
                stats["edges"] += 1

            for src, tgt, rel in diff.removed_edges:
                session.run(
                    """
                    MERGE (s:ClusterNode {node_id: $src})
                    MERGE (t:ClusterNode {node_id: $tgt})
                    MERGE (s)-[r:ATTACK_EDGE {relationship: $rel, diff_id: $did}]->(t)
                    SET r.status = 'REMOVED'
                    """,
                    src=src, tgt=tgt, rel=rel, did=diff.diff_id,
                )
                stats["edges"] += 1

            # 5. Create new attack path chains
            for idx, path in enumerate(diff.new_attack_paths):
                path_id = f"{diff.diff_id}-path-new-{idx}"
                session.run(
                    """
                    MATCH (d:DiffEvent {diff_id: $did})
                    CREATE (p:AttackPath {
                        path_id: $pid,
                        severity: $sev,
                        total_risk: $risk,
                        hop_count: $hops,
                        path_names: $names,
                        status: 'NEW'
                    })
                    MERGE (d)-[:ATTACK_PATH_ADDED]->(p)
                    """,
                    did=diff.diff_id,
                    pid=path_id,
                    sev=path.severity,
                    risk=path.total_risk,
                    hops=path.hop_count,
                    names=path.path_names,
                )

            for idx, path in enumerate(diff.removed_attack_paths):
                path_id = f"{diff.diff_id}-path-rem-{idx}"
                session.run(
                    """
                    MATCH (d:DiffEvent {diff_id: $did})
                    CREATE (p:AttackPath {
                        path_id: $pid,
                        severity: $sev,
                        total_risk: $risk,
                        hop_count: $hops,
                        path_names: $names,
                        status: 'REMOVED'
                    })
                    MERGE (d)-[:ATTACK_PATH_REMOVED]->(p)
                    """,
                    did=diff.diff_id,
                    pid=path_id,
                    sev=path.severity,
                    risk=path.total_risk,
                    hops=path.hop_count,
                    names=path.path_names,
                )

            # 6. Create alert nodes
            for alert in diff.alerts:
                session.run(
                    """
                    MATCH (d:DiffEvent {diff_id: $did})
                    CREATE (a:Alert {
                        alert_id: $aid,
                        severity: $sev,
                        category: $cat,
                        title: $title,
                        description: $desc,
                        timestamp: $ts
                    })
                    MERGE (d)-[:TRIGGERED]->(a)
                    """,
                    did=diff.diff_id,
                    aid=alert.alert_id,
                    sev=alert.severity,
                    cat=alert.category,
                    title=alert.title,
                    desc=alert.description,
                    ts=alert.timestamp,
                )
                stats["alerts"] += 1

        return stats


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Temporal Watcher (Continuous Monitor)                                      ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


class TemporalWatcher:
    """Orchestrates periodic cluster scanning, diffing, alerting, and export.

    Usage:
        watcher = TemporalWatcher(
            interval_seconds=300,
            source="json:cluster-graph.json",
            neo4j_uri="bolt://localhost:7687",
        )
        watcher.start()  # Runs in background thread
        # ... later ...
        watcher.stop()

    Or single-shot:
        watcher = TemporalWatcher(source="json:cluster-graph.json")
        diff = watcher.scan_once()
    """

    def __init__(
        self,
        interval_seconds: int = 300,
        source: str = "json:cluster-graph.json",
        persist_dir: str | Path | None = None,
        max_snapshots: int = 100,
        neo4j_uri: str | None = None,
        neo4j_user: str = "neo4j",
        neo4j_password: str = "password",
        neo4j_database: str = "neo4j",
        on_diff: Callable[[TemporalDiff], None] | None = None,
        on_alert: Callable[[TemporalAlert], None] | None = None,
    ):
        self.interval = interval_seconds
        self.source = source
        self.store = SnapshotStore(persist_dir=persist_dir, max_snapshots=max_snapshots)
        self._diff_history: list[TemporalDiff] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

        # Callbacks
        self._on_diff = on_diff
        self._on_alert = on_alert

        # Neo4j exporter (lazy)
        self._neo4j: Neo4jExporter | None = None
        if neo4j_uri:
            self._neo4j = Neo4jExporter(
                uri=neo4j_uri,
                user=neo4j_user,
                password=neo4j_password,
                database=neo4j_database,
            )

    def _capture_snapshot(self) -> Snapshot:
        """Capture a snapshot from the configured source (JSON file)."""
        if self.source.startswith("json:"):
            filepath = self.source[5:]
            cluster = ingest_from_json(filepath)
            return Snapshot.from_cluster(cluster, source=f"json:{filepath}")
        else:
            raise ValueError(
                f"Unknown source: {self.source}. "
                f"Use 'json:<path>' format (e.g. json:cluster-graph.json)."
            )

    def scan_once(self) -> TemporalDiff | None:
        """Perform a single scan → snapshot → diff → alert cycle.

        Returns:
            TemporalDiff if there was a previous snapshot to compare against,
            or None if this is the first scan.
        """
        logger.info(f"[Temporal] Scanning ({self.source})...")
        new_snap = self._capture_snapshot()

        old_snap = self.store.latest

        # Quick optimization: skip if graph hash is identical
        if old_snap and old_snap.graph_hash == new_snap.graph_hash:
            logger.info("[Temporal] No changes detected (hash match). Skipping diff.")
            # Still store the snapshot for timeline continuity
            self.store.add(new_snap)
            return TemporalDiff(
                diff_id="no-change",
                old_snapshot_id=old_snap.snapshot_id,
                new_snapshot_id=new_snap.snapshot_id,
                timestamp=new_snap.timestamp,
            )

        self.store.add(new_snap)

        if old_snap is None:
            logger.info("[Temporal] First snapshot captured. Waiting for next scan.")
            return None

        # Perform diff
        diff = diff_snapshots(old_snap, new_snap)

        with self._lock:
            self._diff_history.append(diff)

        # Fire callbacks
        if self._on_diff:
            self._on_diff(diff)
        if self._on_alert:
            for alert in diff.alerts:
                self._on_alert(alert)

        # Export to Neo4j if configured AND there are changes
        if self._neo4j and diff.has_changes:
            try:
                stats = self._neo4j.export_diff(diff, old_snap, new_snap)
                logger.info(
                    f"[Temporal] Exported to Neo4j: {stats}"
                )
            except Exception as e:
                logger.error(f"[Temporal] Neo4j export failed: {e}")

        return diff

    def _run_loop(self) -> None:
        """Background loop for continuous monitoring."""
        logger.info(
            f"[Temporal] Watcher started. Interval={self.interval}s, Source={self.source}"
        )
        while self._running:
            try:
                self.scan_once()
            except Exception as e:
                logger.error(f"[Temporal] Scan failed: {e}")
            # Sleep in small increments to allow responsive shutdown
            for _ in range(self.interval):
                if not self._running:
                    break
                time.sleep(1)
        logger.info("[Temporal] Watcher stopped.")

    def start(self) -> None:
        """Start the background watcher thread."""
        if self._running:
            logger.warning("[Temporal] Watcher is already running.")
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="temporal-watcher")
        self._thread.start()

    def stop(self) -> None:
        """Stop the background watcher thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def diff_history(self) -> list[TemporalDiff]:
        with self._lock:
            return list(self._diff_history)

    @property
    def snapshot_count(self) -> int:
        return self.store.count


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Formatters                                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def format_temporal_diff(diff: TemporalDiff) -> str:
    """Format temporal diff for human-readable console output."""
    lines: list[str] = []

    lines.append("=" * 70)
    lines.append("  TEMPORAL ANALYSIS — CLUSTER DIFF")
    lines.append("=" * 70)

    if diff.diff_id:
        lines.append(f"  Diff ID:  {diff.diff_id}")
    if diff.timestamp:
        lines.append(f"  Time:     {diff.timestamp}")
    if diff.old_snapshot_id:
        lines.append(f"  Old Snap: {diff.old_snapshot_id}")
    if diff.new_snapshot_id:
        lines.append(f"  New Snap: {diff.new_snapshot_id}")

    if not diff.has_changes:
        lines.append("\n  ✅ No changes detected between snapshots.")
        lines.append("=" * 70)
        return "\n".join(lines)

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
    for src, tgt, rel in diff.new_edges[:10]:
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
        lines.append(
            f"    ⚡ {' → '.join(path.path_names)} "
            f"(risk: {path.total_risk:.2f}, severity: {path.severity})"
        )

    # Removed attack paths
    lines.append(f"\n  ✅ Eliminated Attack Paths: {len(diff.removed_attack_paths)}")
    for path in diff.removed_attack_paths:
        lines.append(
            f"    ✓ {' → '.join(path.path_names)} "
            f"(was risk: {path.total_risk:.2f})"
        )

    # Alerts
    if diff.alerts:
        lines.append(f"\n  🚨 Alerts Generated: {len(diff.alerts)}")
        lines.append("  " + "-" * 50)
        for alert in diff.alerts:
            sev_icon = {
                "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                "LOW": "🔵", "INFO": "ℹ️",
            }.get(alert.severity, "❓")
            lines.append(f"    {sev_icon} [{alert.severity}] {alert.title}")
            lines.append(f"       {alert.description}")

    lines.append("=" * 70)
    return "\n".join(lines)


def format_alert_summary(alerts: list[TemporalAlert]) -> str:
    """Format a list of alerts into a concise summary."""
    if not alerts:
        return "  ✅ No alerts generated."

    lines = []
    lines.append("=" * 70)
    lines.append("  🚨 TEMPORAL SECURITY ALERTS")
    lines.append("=" * 70)

    # Group by severity
    by_severity: dict[str, list[TemporalAlert]] = {}
    for a in alerts:
        by_severity.setdefault(a.severity, []).append(a)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        group = by_severity.get(sev, [])
        if not group:
            continue
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}[sev]
        lines.append(f"\n  {icon} {sev} ({len(group)}):")
        for a in group:
            lines.append(f"    • {a.title}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def format_snapshot_history(store: SnapshotStore) -> str:
    """Format snapshot store contents for display."""
    snapshots = store.get_all()
    lines = []
    lines.append("=" * 70)
    lines.append("  📸 SNAPSHOT HISTORY")
    lines.append("=" * 70)
    lines.append(f"  Total snapshots: {len(snapshots)}")

    if not snapshots:
        lines.append("  (none)")
        lines.append("=" * 70)
        return "\n".join(lines)

    lines.append(f"\n  {'#':<4} {'Timestamp':<28} {'Hash':<18} {'Source':<20}")
    lines.append("  " + "-" * 66)
    for i, snap in enumerate(snapshots, 1):
        lines.append(
            f"  {i:<4} {snap.timestamp:<28} {snap.graph_hash:<18} {snap.source:<20}"
        )

    lines.append("=" * 70)
    return "\n".join(lines)
