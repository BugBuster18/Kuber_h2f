"""
Remediation Engine for KubeAttackViz.

Generates specific, actionable remediation recommendations based on
attack paths, critical nodes, and detected cycles.
"""

from __future__ import annotations

import networkx as nx

from .models import AttackPath, CriticalNodeResult, CycleResult
from .graph_builder import get_node_name


# ─── Remediation templates per relationship type ─────────────────────────────

_RELATIONSHIP_REMEDIATION: dict[str, str] = {
    "runs_as": "Restrict pod ServiceAccount assignment. Use dedicated ServiceAccounts with minimal permissions instead of the default.",
    "binds_to": "Remove or scope down RoleBinding. Apply principle of least privilege to RBAC bindings.",
    "grants": "Audit Role/ClusterRole permissions. Remove wildcard verbs and unnecessary resource access.",
    "accesses": "Enforce network policies to restrict access. Use mTLS for service-to-service communication.",
    "mounts": "Remove unnecessary secret mounts. Use CSI secret store drivers or external secret managers.",
    "exposes": "Remove external service exposure. Use internal ClusterIP services with ingress controllers.",
    "connects_to": "Apply NetworkPolicy to restrict pod-to-pod communication. Segment workloads by namespace.",
    "uses": "Audit resource usage. Implement resource quotas and limit ranges.",
    "escalates_to": "Remove privilege escalation vectors. Enforce PodSecurityPolicies/Standards.",
    "has_secret": "Rotate secret and restrict access. Use Vault or sealed-secrets for secret management.",
    "reads": "Restrict read access via RBAC. Audit who can read sensitive resources.",
    "writes": "Restrict write access via RBAC. Implement admission controllers to validate changes.",
}

_CVE_REMEDIATION_TEMPLATE = "Patch {cve} (CVSS: {cvss:.1f}). Apply the latest security update to the affected component."

_NODE_TYPE_REMEDIATION: dict[str, str] = {
    "serviceaccount": "Review ServiceAccount permissions. Consider using short-lived tokens (TokenRequest API).",
    "role": "Audit Role rules. Remove wildcard permissions and unnecessary API group access.",
    "clusterrole": "Audit ClusterRole rules. Restrict cluster-wide permissions to essential controllers only.",
    "rolebinding": "Review RoleBinding subjects. Ensure bindings follow the principle of least privilege.",
    "clusterrolebinding": "Review ClusterRoleBinding. These grant cluster-wide access — minimize usage.",
    "secret": "Rotate affected secrets. Implement secret encryption at rest and restrict RBAC access.",
    "pod": "Review pod security context. Enforce non-root, read-only filesystem, drop capabilities.",
    "service": "Review service exposure type. Prefer ClusterIP over NodePort/LoadBalancer when possible.",
    "configmap": "Audit ConfigMap contents for sensitive data. Move secrets to Secret resources.",
}


def generate_path_remediation(
    G: nx.DiGraph,
    path: AttackPath,
) -> list[str]:
    """Generate remediation steps for a single attack path.

    Produces specific, actionable recommendations for each hop in the path,
    including CVE patching and relationship-specific fixes.

    Args:
        G: The attack graph.
        path: AttackPath to generate remediation for.

    Returns:
        List of remediation recommendation strings.
    """
    recommendations: list[str] = []

    for i, relationship in enumerate(path.relationships):
        src_name = path.path_names[i]
        tgt_name = path.path_names[i + 1]
        src_id = path.path_nodes[i]
        tgt_id = path.path_nodes[i + 1]

        # Relationship-specific remediation
        base_fix = _RELATIONSHIP_REMEDIATION.get(
            relationship,
            f"Review the '{relationship}' relationship between {src_name} and {tgt_name}.",
        )
        recommendations.append(f"[Hop {i + 1}] {src_name} → {tgt_name}: {base_fix}")

        # CVE-specific remediation
        if path.cves[i]:
            cvss = path.cvss_scores[i] or 0.0
            cve_fix = _CVE_REMEDIATION_TEMPLATE.format(cve=path.cves[i], cvss=cvss)
            recommendations.append(f"  ⚠ {cve_fix}")

        # Target node type remediation
        tgt_type = G.nodes[tgt_id].get("type", "") if tgt_id in G.nodes else ""
        if tgt_type in _NODE_TYPE_REMEDIATION:
            recommendations.append(f"  → {_NODE_TYPE_REMEDIATION[tgt_type]}")

    return recommendations


def generate_critical_node_remediation(
    G: nx.DiGraph,
    result: CriticalNodeResult,
) -> list[str]:
    """Generate remediation for critical nodes identified by graph surgery.

    Args:
        G: The attack graph.
        result: CriticalNodeResult from analysis.

    Returns:
        List of remediation recommendation strings.
    """
    recommendations: list[str] = []

    if not result.top_nodes:
        recommendations.append("No critical chokepoint nodes identified.")
        return recommendations

    for node_id, name, eliminated in result.top_nodes:
        node_type = G.nodes[node_id].get("type", "unknown") if node_id in G.nodes else "unknown"
        recommendations.append(
            f"Remove/harden node '{name}' [{node_type}] → eliminates {eliminated} "
            f"of {result.total_paths_baseline} attack paths."
        )

        if node_type in _NODE_TYPE_REMEDIATION:
            recommendations.append(f"  → {_NODE_TYPE_REMEDIATION[node_type]}")

        # Specific action based on type
        if node_type == "rolebinding" or node_type == "clusterrolebinding":
            recommendations.append(f"  → ACTION: kubectl delete {node_type} {name}")
        elif node_type == "serviceaccount":
            recommendations.append(
                f"  → ACTION: Restrict ServiceAccount '{name}' permissions via RBAC rewrite."
            )
        elif node_type == "role" or node_type == "clusterrole":
            recommendations.append(
                f"  → ACTION: Scope down '{name}' rules — remove wildcard verbs/resources."
            )

    return recommendations


def generate_cycle_remediation(
    G: nx.DiGraph,
    result: CycleResult,
) -> list[str]:
    """Generate remediation for detected privilege escalation cycles.

    Args:
        G: The attack graph.
        result: CycleResult from cycle detection.

    Returns:
        List of remediation recommendation strings.
    """
    recommendations: list[str] = []

    if result.total_cycles == 0:
        recommendations.append("No privilege escalation cycles detected.")
        return recommendations

    recommendations.append(
        f"WARNING: {result.total_cycles} privilege escalation cycle(s) detected!"
    )
    recommendations.append("Cycles allow attackers to loop through permissions indefinitely.")

    for idx, (cycle, names) in enumerate(zip(result.cycles, result.cycle_names), 1):
        cycle_str = " → ".join(names) + " → " + names[0]
        recommendations.append(f"\n  Cycle #{idx}: {cycle_str}")

        # Find the weakest (highest weight) edge to recommend breaking
        max_weight = -1.0
        break_src = ""
        break_tgt = ""
        break_rel = ""

        for i in range(len(cycle)):
            src = cycle[i]
            tgt = cycle[(i + 1) % len(cycle)]
            if G.has_edge(src, tgt):
                w = G.edges[src, tgt].get("weight", 0.0)
                if w > max_weight:
                    max_weight = w
                    break_src = get_node_name(G, src)
                    break_tgt = get_node_name(G, tgt)
                    break_rel = G.edges[src, tgt].get("relationship", "")

        if break_src:
            recommendations.append(
                f"    → BREAK at: {break_src} ──[{break_rel}]──▸ {break_tgt} "
                f"(weight: {max_weight:.1f})"
            )
            if break_rel in _RELATIONSHIP_REMEDIATION:
                recommendations.append(
                    f"    → {_RELATIONSHIP_REMEDIATION[break_rel]}"
                )

    return recommendations
