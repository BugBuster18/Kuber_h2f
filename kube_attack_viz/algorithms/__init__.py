"""
Graph algorithms for Kubernetes attack path analysis.

Submodules:
  - bfs: Blast radius computation
  - dijkstra: Shortest (minimum-weight) attack path
  - dfs: Cycle detection
  - critical_node: Graph surgery for critical node identification
"""

from .bfs import blast_radius
from .dijkstra import shortest_attack_path
from .dfs import detect_cycles
from .critical_node import critical_node_analysis

__all__ = [
    "blast_radius",
    "shortest_attack_path",
    "detect_cycles",
    "critical_node_analysis",
]
