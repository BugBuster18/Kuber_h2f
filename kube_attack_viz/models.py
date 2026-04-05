"""
Data models for KubeAttackViz.

Defines the strict schema for graph nodes, edges, and cluster state
following the specification exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class NodeData:
    """Represents a node in the Kubernetes attack graph.

    Attributes:
        id: Unique identifier for the node.
        type: Kubernetes resource type (pod, service, serviceaccount, role, secret, etc.).
        name: Human-readable name of the resource.
        namespace: Kubernetes namespace the resource belongs to.
        risk_score: Numeric risk score (0.0 - 10.0).
        is_sink: Whether this node is a high-value target.
        cves: List of CVE identifiers associated with this node.
        image: Container image name.
        likelihood: (New) Probability of exploitation (0-10).
        impact: (New) Potential damage if compromised (0-10).
    """

    id: str
    type: str
    name: str
    namespace: str
    risk_score: float
    is_source: bool = False
    is_sink: bool = False
    cves: list[str] = field(default_factory=list)
    image: Optional[str] = None
    likelihood: Optional[float] = None
    impact: Optional[float] = None

    def to_dict(self) -> dict:
        """Serialize node to dictionary matching the strict original schema."""
        return {
            "id": self.id,
            "type": self.type.capitalize() if self.type else "Unknown",
            "name": self.name,
            "namespace": self.namespace,
            "risk_score": round(float(self.risk_score), 2),
            "is_source": self.is_source,
            "is_sink": self.is_sink,
            "cves": self.cves,
        }

    @classmethod
    def from_dict(cls, data: dict) -> NodeData:
        """Deserialize node from dictionary."""
        return cls(
            id=data["id"],
            type=data["type"].lower(),
            name=data["name"],
            namespace=data["namespace"],
            risk_score=float(data["risk_score"]),
            is_source=bool(data.get("is_source", False)),
            is_sink=bool(data.get("is_sink", False)),
            cves=data.get("cves", []),
            image=data.get("image"),
            likelihood=data.get("likelihood"),
            impact=data.get("impact"),
        )


@dataclass
class EdgeData:
    """Represents a directed edge (attack vector) between two nodes.

    Attributes:
        source: Source node ID.
        target: Target node ID.
        relationship: Type of relationship (e.g., 'binds_to', 'mounts', 'accesses').
        weight: Edge weight representing traversal cost / exploitability.
        cve: Optional CVE associated with this edge.
        cvss: Optional CVSS score for the CVE.
    """

    source: str
    target: str
    relationship: str
    weight: float
    cve: Optional[str] = None
    cvss: Optional[float] = None

    def to_dict(self) -> dict:
        """Serialize edge to dictionary matching the strict original schema."""
        return {
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
            "weight": float(self.weight),
            "cve": self.cve,
            "cvss": self.cvss,
        }

    @classmethod
    def from_dict(cls, data: dict) -> EdgeData:
        """Deserialize edge from dictionary."""
        return cls(
            source=data["source"],
            target=data["target"],
            relationship=data["relationship"],
            weight=float(data["weight"]),
            cve=data.get("cve"),
            cvss=float(data["cvss"]) if data.get("cvss") is not None else None,
        )


@dataclass
class ClusterGraph:
    """Container for the full cluster attack graph.

    Attributes:
        nodes: List of graph nodes.
        edges: List of graph edges.
    """

    nodes: list[NodeData] = field(default_factory=list)
    edges: list[EdgeData] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize the entire graph to a dictionary."""
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict) -> ClusterGraph:
        """Deserialize graph from dictionary.

        Handles:
          - Comment-only edge entries (skipped gracefully)
          - PascalCase node types (normalized to lowercase)
        """
        nodes = [NodeData.from_dict(n) for n in data.get("nodes", [])]

        # Skip comment-only edge entries that lack required keys
        edges: list[EdgeData] = []
        for e in data.get("edges", []):
            if "source" not in e or "target" not in e:
                continue  # skip comment entries
            edges.append(EdgeData.from_dict(e))

        return cls(nodes=nodes, edges=edges)


@dataclass
class AttackPath:
    """Represents a single attack path through the graph.

    Attributes:
        path_nodes: Ordered list of node IDs in the path.
        path_names: Ordered list of node names in the path.
        relationships: List of relationship labels along the path.
        cves: List of CVEs encountered along the path.
        cvss_scores: List of CVSS scores along the path.
        hop_count: Number of hops in the path.
        total_risk: Sum of edge weights.
        severity: Severity label (CRITICAL, HIGH, MEDIUM, LOW).
    """

    path_nodes: list[str] = field(default_factory=list)
    path_names: list[str] = field(default_factory=list)
    relationships: list[str] = field(default_factory=list)
    cves: list[Optional[str]] = field(default_factory=list)
    cvss_scores: list[Optional[float]] = field(default_factory=list)
    hop_count: int = 0
    total_risk: float = 0.0
    severity: str = "LOW"

    def to_dict(self) -> dict:
        """Serialize path to dictionary."""
        return asdict(self)


@dataclass
class BlastRadiusResult:
    """Result of BFS blast radius analysis.

    Attributes:
        source: Source node ID.
        max_depth: Maximum BFS depth used.
        layers: Dictionary mapping depth level to list of node IDs.
        total_affected: Total number of affected nodes.
    """

    source: str
    max_depth: int
    layers: dict[int, list[str]] = field(default_factory=dict)
    total_affected: int = 0

    def to_dict(self) -> dict:
        """Serialize blast radius result."""
        return {
            "source": self.source,
            "max_depth": self.max_depth,
            "layers": {str(k): v for k, v in self.layers.items()},
            "total_affected": self.total_affected,
        }


@dataclass
class CycleResult:
    """Result of DFS cycle detection.

    Attributes:
        cycles: List of cycles, each cycle is a list of node IDs.
        cycle_names: List of cycles as node names.
        total_cycles: Total number of unique cycles found.
    """

    cycles: list[list[str]] = field(default_factory=list)
    cycle_names: list[list[str]] = field(default_factory=list)
    total_cycles: int = 0

    def to_dict(self) -> dict:
        """Serialize cycle result."""
        return {
            "cycles": self.cycles,
            "cycle_names": self.cycle_names,
            "total_cycles": self.total_cycles,
        }


@dataclass
class CriticalNodeResult:
    """Result of critic2al node analysis (graph surgery).

    Attributes:
        top_nodes: List of (node_id, node_name, paths_eliminated) tuples.
        total_paths_baseline: Total simple paths before any removal.
    """

    top_nodes: list[tuple[str, str, int]] = field(default_factory=list)
    total_paths_baseline: int = 0

    def to_dict(self) -> dict:
        """Serialize critical node result."""
        return {
            "top_nodes": [
                {"id": n[0], "name": n[1], "paths_eliminated": n[2]}
                for n in self.top_nodes
            ],
            "total_paths_baseline": self.total_paths_baseline,
        }
