"""
Neo4j Storage Layer for KubeAttackViz.

Persists the Kubernetes attack graph into Neo4j as native graph data,
supports snapshot versioning, and enables temporal diff queries.

Connection is configured via environment variables or explicit parameters:
  - NEO4J_URI   (default: bolt://localhost:7687)
  - NEO4J_USER  (default: neo4j)
  - NEO4J_PASSWORD (required)
"""

from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from typing import Optional

from .models import ClusterGraph, NodeData, EdgeData


# ─── Lazy import helper ──────────────────────────────────────────────────────

def _get_driver():
    """Lazy-import neo4j to avoid hard dependency at module level."""
    try:
        from neo4j import GraphDatabase
        return GraphDatabase
    except ImportError:
        raise ImportError(
            "neo4j Python driver is required for Neo4j integration.\n"
            "Install it with: pip install neo4j>=5.0"
        )


class Neo4jStore:
    """Manages Neo4j connection and graph/snapshot persistence.

    Usage:
        store = Neo4jStore(uri="bolt://localhost:7687", user="neo4j", password="secret")
        store.connect()
        store.store_graph(cluster_graph)
        loaded = store.load_graph()
        store.store_snapshot(cluster_graph, label="initial-scan")
        store.close()
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "")
        self._driver = None

    def connect(self) -> None:
        """Establish connection to Neo4j."""
        GraphDatabase = _get_driver()
        if not self.password:
            raise ValueError(
                "Neo4j password is required. Set NEO4J_PASSWORD env var "
                "or pass password= to Neo4jStore()."
            )
        self._driver = GraphDatabase.driver(
            self.uri, auth=(self.user, self.password)
        )
        # Verify connectivity
        self._driver.verify_connectivity()

    def close(self) -> None:
        """Close the Neo4j driver."""
        if self._driver:
            self._driver.close()
            self._driver = None

    def _session(self):
        """Get a session, raising if not connected."""
        if self._driver is None:
            raise RuntimeError("Not connected to Neo4j. Call connect() first.")
        return self._driver.session()

    # ─── Current Graph Operations ────────────────────────────────────────────

    def clear_graph(self) -> None:
        """Remove all current graph nodes and edges (not snapshots)."""
        with self._session() as session:
            session.run("MATCH (n:KubeNode) DETACH DELETE n")

    def store_graph(self, graph: ClusterGraph) -> dict:
        """Store/replace the current attack graph in Neo4j.

        Creates :KubeNode nodes and [:ATTACK_EDGE] relationships.

        Args:
            graph: ClusterGraph to persist.

        Returns:
            Dict with node_count and edge_count stored.
        """
        with self._session() as session:
            # Clear existing current graph
            session.run("MATCH (n:KubeNode) DETACH DELETE n")

            # Create indexes for performance
            session.run(
                "CREATE INDEX IF NOT EXISTS FOR (n:KubeNode) ON (n.node_id)"
            )

            # Batch create nodes
            node_count = 0
            for node in graph.nodes:
                session.run(
                    """
                    CREATE (n:KubeNode {
                        node_id: $node_id,
                        type: $type,
                        name: $name,
                        namespace: $namespace,
                        risk_score: $risk_score,
                        is_source: $is_source,
                        is_sink: $is_sink,
                        cves: $cves
                    })
                    """,
                    node_id=node.id,
                    type=node.type,
                    name=node.name,
                    namespace=node.namespace,
                    risk_score=node.risk_score,
                    is_source=node.is_source,
                    is_sink=node.is_sink,
                    cves=json.dumps(node.cves),
                )
                node_count += 1

            # Create edges
            edge_count = 0
            for edge in graph.edges:
                session.run(
                    """
                    MATCH (src:KubeNode {node_id: $source})
                    MATCH (tgt:KubeNode {node_id: $target})
                    CREATE (src)-[:ATTACK_EDGE {
                        relationship: $relationship,
                        weight: $weight,
                        cve: $cve,
                        cvss: $cvss
                    }]->(tgt)
                    """,
                    source=edge.source,
                    target=edge.target,
                    relationship=edge.relationship,
                    weight=edge.weight,
                    cve=edge.cve or "",
                    cvss=edge.cvss if edge.cvss is not None else -1.0,
                )
                edge_count += 1

        return {"node_count": node_count, "edge_count": edge_count}

    def load_graph(self) -> ClusterGraph:
        """Load the current attack graph from Neo4j.

        Returns:
            ClusterGraph reconstructed from Neo4j data.
        """
        nodes = []
        edges = []

        with self._session() as session:
            # Load nodes
            result = session.run("MATCH (n:KubeNode) RETURN n")
            for record in result:
                n = record["n"]
                cves_raw = n.get("cves", "[]")
                cves = json.loads(cves_raw) if isinstance(cves_raw, str) else cves_raw
                nodes.append(NodeData(
                    id=n["node_id"],
                    type=n["type"],
                    name=n["name"],
                    namespace=n["namespace"],
                    risk_score=float(n["risk_score"]),
                    is_source=bool(n["is_source"]),
                    is_sink=bool(n["is_sink"]),
                    cves=cves,
                ))

            # Load edges
            result = session.run(
                """
                MATCH (src:KubeNode)-[r:ATTACK_EDGE]->(tgt:KubeNode)
                RETURN src.node_id AS source, tgt.node_id AS target,
                       r.relationship AS relationship, r.weight AS weight,
                       r.cve AS cve, r.cvss AS cvss
                """
            )
            for record in result:
                cve = record["cve"] if record["cve"] != "" else None
                cvss = record["cvss"] if record["cvss"] != -1.0 else None
                edges.append(EdgeData(
                    source=record["source"],
                    target=record["target"],
                    relationship=record["relationship"],
                    weight=float(record["weight"]),
                    cve=cve,
                    cvss=float(cvss) if cvss is not None else None,
                ))

        return ClusterGraph(nodes=nodes, edges=edges)

    # ─── Snapshot Operations ─────────────────────────────────────────────────

    def store_snapshot(
        self,
        graph: ClusterGraph,
        label: str = "",
        timestamp: Optional[str] = None,
    ) -> str:
        """Store a timestamped snapshot of the graph in Neo4j.

        Creates a :Snapshot node linked to :SnapshotNode and :SnapshotEdge nodes.

        Args:
            graph: ClusterGraph to snapshot.
            label: Human-readable label for this snapshot.
            timestamp: ISO format timestamp; defaults to now.

        Returns:
            The snapshot ID (timestamp string).
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        with self._session() as session:
            # Create index
            session.run(
                "CREATE INDEX IF NOT EXISTS FOR (s:Snapshot) ON (s.timestamp)"
            )

            # Create snapshot node
            session.run(
                """
                CREATE (s:Snapshot {
                    timestamp: $ts,
                    label: $label,
                    node_count: $node_count,
                    edge_count: $edge_count,
                    graph_json: $graph_json
                })
                """,
                ts=ts,
                label=label,
                node_count=len(graph.nodes),
                edge_count=len(graph.edges),
                graph_json=json.dumps(graph.to_dict()),
            )

        return ts

    def list_snapshots(self) -> list[dict]:
        """List all snapshots stored in Neo4j.

        Returns:
            List of dicts with timestamp, label, node_count, edge_count.
        """
        snapshots = []
        with self._session() as session:
            result = session.run(
                """
                MATCH (s:Snapshot)
                RETURN s.timestamp AS timestamp, s.label AS label,
                       s.node_count AS node_count, s.edge_count AS edge_count
                ORDER BY s.timestamp ASC
                """
            )
            for record in result:
                snapshots.append({
                    "timestamp": record["timestamp"],
                    "label": record["label"],
                    "node_count": record["node_count"],
                    "edge_count": record["edge_count"],
                })
        return snapshots

    def load_snapshot(self, timestamp: str) -> Optional[ClusterGraph]:
        """Load a specific snapshot by timestamp.

        Args:
            timestamp: ISO format timestamp of the snapshot.

        Returns:
            ClusterGraph from the snapshot, or None if not found.
        """
        with self._session() as session:
            result = session.run(
                "MATCH (s:Snapshot {timestamp: $ts}) RETURN s.graph_json AS gj",
                ts=timestamp,
            )
            record = result.single()
            if record is None:
                return None
            return ClusterGraph.from_dict(json.loads(record["gj"]))

    def delete_snapshot(self, timestamp: str) -> bool:
        """Delete a specific snapshot.

        Args:
            timestamp: ISO format timestamp of the snapshot.

        Returns:
            True if deleted, False if not found.
        """
        with self._session() as session:
            result = session.run(
                """
                MATCH (s:Snapshot {timestamp: $ts})
                DELETE s
                RETURN count(s) AS deleted
                """,
                ts=timestamp,
            )
            record = result.single()
            return record["deleted"] > 0

    def clear_snapshots(self) -> int:
        """Delete all snapshots.

        Returns:
            Number of snapshots deleted.
        """
        with self._session() as session:
            result = session.run(
                "MATCH (s:Snapshot) DELETE s RETURN count(s) AS deleted"
            )
            record = result.single()
            return record["deleted"]
