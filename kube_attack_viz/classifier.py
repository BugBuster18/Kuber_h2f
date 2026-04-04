"""
Attack Path Classification Engine for KubeAttackViz.

Classifies attack paths into well-known attack categories:
  - Privilege Escalation
  - Lateral Movement
  - Credential Theft
  - Data Exfiltration

Also computes advanced composite path scores.
"""

from __future__ import annotations

from typing import Optional

import networkx as nx

from .models import AttackPath
from .graph_builder import get_node_name


# ─── Classification rules ────────────────────────────────────────────────────

_PRIV_ESCALATION_RELS = {"escalates_to", "grants", "binds_to"}
_LATERAL_MOVEMENT_RELS = {"connects_to", "exposes", "uses"}
_CREDENTIAL_THEFT_RELS = {"mounts", "accesses", "has_secret", "reads"}
_DATA_EXFIL_RELS = {"connects_to", "writes"}

_PRIV_ESCALATION_TARGETS = {"clusterrole", "role", "clusterrolebinding", "rolebinding"}
_CREDENTIAL_TARGETS = {"secret"}
_DATA_EXFIL_TARGETS = {"database", "secret"}


def classify_path(G: nx.DiGraph, path: AttackPath) -> list[str]:
    """Classify an attack path into one or more attack categories.

    A single path may belong to multiple categories if it traverses
    different types of relationships.

    Args:
        G: The attack graph.
        path: AttackPath to classify.

    Returns:
        List of attack category strings.
    """
    categories: set[str] = set()
    rels = set(path.relationships)

    # Collect target node types
    target_types: set[str] = set()
    for node_id in path.path_nodes:
        if node_id in G.nodes:
            target_types.add(G.nodes[node_id].get("type", ""))

    # Check Privilege Escalation
    if rels & _PRIV_ESCALATION_RELS and target_types & _PRIV_ESCALATION_TARGETS:
        categories.add("Privilege Escalation")

    # Check Lateral Movement
    if rels & _LATERAL_MOVEMENT_RELS:
        pod_count = sum(
            1 for n in path.path_nodes
            if n in G.nodes and G.nodes[n].get("type") == "pod"
        )
        if pod_count >= 2:
            categories.add("Lateral Movement")

    # Check Credential Theft
    if rels & _CREDENTIAL_THEFT_RELS and target_types & _CREDENTIAL_TARGETS:
        categories.add("Credential Theft")

    # Check Data Exfiltration
    if target_types & _DATA_EXFIL_TARGETS:
        # If the path ends at a database or secret sink
        last_id = path.path_nodes[-1]
        if last_id in G.nodes:
            last_type = G.nodes[last_id].get("type", "")
            if last_type in _DATA_EXFIL_TARGETS and G.nodes[last_id].get("is_sink", False):
                categories.add("Data Exfiltration")

    if not categories:
        categories.add("General Access")

    return sorted(categories)


def compute_advanced_score(path: AttackPath) -> float:
    """Compute the advanced composite score for a path.

    Formula:
        final_score = (risk * 0.6) + (hop_count * 0.2) + (max_cvss * 0.2)

    Args:
        path: AttackPath to score.

    Returns:
        Composite floating-point score.
    """
    risk_component = path.total_risk * 0.6
    hop_component = path.hop_count * 0.2
    max_cvss = max(
        (c for c in path.cvss_scores if c is not None),
        default=0.0,
    )
    cvss_component = max_cvss * 0.2

    return risk_component + hop_component + cvss_component


def format_classified_paths(
    G: nx.DiGraph,
    paths: list[AttackPath],
) -> str:
    """Format paths with classification and advanced scores.

    Args:
        G: The attack graph.
        paths: List of attack paths.

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  ATTACK PATH CLASSIFICATION")
    lines.append("=" * 70)

    if not paths:
        lines.append("  No attack paths to classify.")
        lines.append("=" * 70)
        return "\n".join(lines)

    for idx, path in enumerate(paths, 1):
        categories = classify_path(G, path)
        score = compute_advanced_score(path)
        lines.append(f"\n  Path #{idx}: {' → '.join(path.path_names)}")
        lines.append(f"    Categories: {', '.join(categories)}")
        lines.append(f"    Advanced Score: {score:.2f}")
        lines.append(f"    Risk: {path.total_risk:.2f} | Hops: {path.hop_count} | Severity: {path.severity}")

    lines.append("=" * 70)
    return "\n".join(lines)
