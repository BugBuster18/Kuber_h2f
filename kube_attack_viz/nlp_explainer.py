"""
Natural Language Explanation Engine for KubeAttackViz.

Generates clear, human-readable explanations of attack paths,
designed for security teams and non-technical stakeholders.
"""

from __future__ import annotations

import networkx as nx

from .models import AttackPath, CriticalNodeResult
from .graph_builder import get_node_name
from .classifier import classify_path


# ─── Relationship verb templates ─────────────────────────────────────────────

_REL_VERBS: dict[str, str] = {
    "runs_as": "authenticates as",
    "binds_to": "is bound to",
    "grants": "grants permissions via",
    "accesses": "can access",
    "mounts": "has mounted",
    "exposes": "exposes",
    "connects_to": "establishes a network connection to",
    "uses": "consumes configuration from",
    "escalates_to": "escalates privileges to",
    "has_secret": "holds the secret",
    "reads": "can read data from",
    "writes": "can write data to",
}

_TYPE_ARTICLES: dict[str, str] = {
    "pod": "the pod",
    "service": "the service",
    "serviceaccount": "the ServiceAccount",
    "role": "the Role",
    "clusterrole": "the ClusterRole",
    "rolebinding": "the RoleBinding",
    "clusterrolebinding": "the ClusterRoleBinding",
    "secret": "the secret",
    "configmap": "the ConfigMap",
    "database": "the database",
    "node": "the cluster node",
    "ingress": "the ingress",
}


def explain_path(G: nx.DiGraph, path: AttackPath) -> str:
    """Generate a natural language explanation of an attack path.

    Produces a step-by-step narrative that describes how an attacker
    could traverse the path, in plain English.

    Args:
        G: The attack graph.
        path: AttackPath to explain.

    Returns:
        Multi-line natural language explanation string.
    """
    categories = classify_path(G, path)
    severity = path.severity
    lines: list[str] = []

    # Opening
    first_name = path.path_names[0]
    last_name = path.path_names[-1]
    first_type = G.nodes[path.path_nodes[0]].get("type", "resource") if path.path_nodes[0] in G.nodes else "resource"
    last_type = G.nodes[path.path_nodes[-1]].get("type", "resource") if path.path_nodes[-1] in G.nodes else "resource"

    lines.append(
        f"An attacker who compromises {_article(first_type)} '{first_name}' "
        f"can reach {_article(last_type)} '{last_name}' "
        f"in {path.hop_count} step(s)."
    )
    lines.append(f"This is a {severity}-severity path classified as: {', '.join(categories)}.")
    lines.append("")

    # Step-by-step
    lines.append("Attack chain:")
    for i, rel in enumerate(path.relationships):
        src_name = path.path_names[i]
        tgt_name = path.path_names[i + 1]
        src_type = _get_type(G, path.path_nodes[i])
        tgt_type = _get_type(G, path.path_nodes[i + 1])
        verb = _REL_VERBS.get(rel, f"has a '{rel}' relationship with")

        step = f"  Step {i + 1}: {_article(src_type).capitalize()} '{src_name}' {verb} {_article(tgt_type)} '{tgt_name}'."

        # Add CVE context
        if path.cves[i]:
            cvss_str = f" (CVSS: {path.cvss_scores[i]:.1f})" if path.cvss_scores[i] else ""
            step += f"\n           ⚠ This hop exploits {path.cves[i]}{cvss_str}."

        lines.append(step)

    # Closing
    lines.append("")
    lines.append(
        f"Total risk score: {path.total_risk:.2f}. "
        f"An attacker traversing this path gains access to "
        f"{_article(last_type)} '{last_name}', "
        f"which is flagged as a high-value target."
    )

    return "\n".join(lines)


def explain_critical_node(G: nx.DiGraph, result: CriticalNodeResult) -> str:
    """Generate a natural language explanation of critical node analysis.

    Args:
        G: The attack graph.
        result: CriticalNodeResult from analysis.

    Returns:
        Plain-English explanation string.
    """
    if not result.top_nodes:
        return "No critical chokepoint nodes were identified in this cluster."

    lines: list[str] = []
    top = result.top_nodes[0]
    node_id, name, eliminated = top
    node_type = _get_type(G, node_id)
    pct = (eliminated / max(result.total_paths_baseline, 1)) * 100

    lines.append(
        f"The most critical chokepoint in this cluster is {_article(node_type)} '{name}'. "
        f"If this resource is hardened or removed, it would eliminate "
        f"{eliminated} out of {result.total_paths_baseline} attack paths ({pct:.1f}%)."
    )
    lines.append("")
    lines.append(
        f"This means '{name}' acts as a bottleneck through which "
        f"a majority of attack paths must pass. Hardening this single "
        f"resource provides the highest security return on investment."
    )

    if len(result.top_nodes) > 1:
        lines.append("")
        lines.append("Other significant chokepoints:")
        for _, n_name, n_elim in result.top_nodes[1:]:
            lines.append(f"  • '{n_name}' — eliminates {n_elim} paths")

    return "\n".join(lines)


def _article(node_type: str) -> str:
    """Get the descriptive article for a node type."""
    return _TYPE_ARTICLES.get(node_type, f"the {node_type}")


def _get_type(G: nx.DiGraph, node_id: str) -> str:
    """Get node type from graph."""
    if node_id in G.nodes:
        return G.nodes[node_id].get("type", "resource")
    return "resource"
