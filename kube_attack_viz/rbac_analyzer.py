"""
RBAC Risk Analyzer for KubeAttackViz.

Detects dangerous RBAC patterns in the attack graph:
  - cluster-admin bindings
  - Wildcard permissions (inferred from ClusterRole names)
  - Privilege escalation chains (SA → RoleBinding → ClusterRole)
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from .graph_builder import get_node_name


@dataclass
class RBACFinding:
    """A single RBAC risk finding.

    Attributes:
        severity: HIGH, MEDIUM, or LOW.
        category: Finding category (cluster-admin, wildcard, escalation-chain).
        description: Human-readable description.
        affected_nodes: List of node IDs involved.
    """

    severity: str
    category: str
    description: str
    affected_nodes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "affected_nodes": self.affected_nodes,
        }


@dataclass
class RBACAnalysisResult:
    """Full RBAC analysis result.

    Attributes:
        findings: List of RBACFinding instances.
        total_high: Count of HIGH severity findings.
        total_medium: Count of MEDIUM severity findings.
        total_low: Count of LOW severity findings.
    """

    findings: list[RBACFinding] = field(default_factory=list)
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "total_high": self.total_high,
            "total_medium": self.total_medium,
            "total_low": self.total_low,
        }


def analyze_rbac(G: nx.DiGraph) -> RBACAnalysisResult:
    """Analyze RBAC patterns in the attack graph for security risks.

    Checks for:
      1. cluster-admin ClusterRoleBindings
      2. Wildcard/overly-permissive roles (identified by name heuristics + high risk)
      3. Privilege escalation chains (ServiceAccount → binding → ClusterRole)

    Args:
        G: The attack graph.

    Returns:
        RBACAnalysisResult with all findings.
    """
    result = RBACAnalysisResult()

    _check_cluster_admin(G, result)
    _check_wildcard_roles(G, result)
    _check_escalation_chains(G, result)
    _check_default_sa_usage(G, result)

    result.total_high = sum(1 for f in result.findings if f.severity == "HIGH")
    result.total_medium = sum(1 for f in result.findings if f.severity == "MEDIUM")
    result.total_low = sum(1 for f in result.findings if f.severity == "LOW")

    return result


def _check_cluster_admin(G: nx.DiGraph, result: RBACAnalysisResult) -> None:
    """Detect cluster-admin role bindings."""
    for node_id, data in G.nodes(data=True):
        node_type = data.get("type", "")
        name = data.get("name", "")

        if node_type == "clusterrole" and "admin" in name.lower():
            # Find what binds to this role
            predecessors = list(G.predecessors(node_id))
            binding_nodes = [
                p for p in predecessors
                if G.nodes[p].get("type") in ("clusterrolebinding", "rolebinding")
            ]

            for binding_id in binding_nodes:
                binding_name = get_node_name(G, binding_id)
                # Find what subjects bind through this
                subjects = list(G.predecessors(binding_id))

                result.findings.append(
                    RBACFinding(
                        severity="HIGH",
                        category="cluster-admin",
                        description=(
                            f"ClusterRole '{name}' (admin-level) is bound via "
                            f"'{binding_name}' — subjects: "
                            f"{', '.join(get_node_name(G, s) for s in subjects)}. "
                            f"Cluster-admin gives unrestricted access."
                        ),
                        affected_nodes=[node_id, binding_id] + subjects,
                    )
                )


def _check_wildcard_roles(G: nx.DiGraph, result: RBACAnalysisResult) -> None:
    """Detect potentially wildcard / overly-permissive roles."""
    for node_id, data in G.nodes(data=True):
        node_type = data.get("type", "")
        name = data.get("name", "")
        risk = data.get("risk_score", 0.0)

        if node_type in ("role", "clusterrole") and risk >= 5.0:
            # High-risk role — likely has broad permissions
            out_edges = list(G.successors(node_id))
            if len(out_edges) >= 2:
                target_names = [get_node_name(G, t) for t in out_edges]
                result.findings.append(
                    RBACFinding(
                        severity="MEDIUM",
                        category="wildcard-permissions",
                        description=(
                            f"Role '{name}' (risk: {risk:.1f}) accesses {len(out_edges)} "
                            f"resources: {', '.join(target_names)}. "
                            f"Consider scoping down permissions."
                        ),
                        affected_nodes=[node_id] + out_edges,
                    )
                )


def _check_escalation_chains(G: nx.DiGraph, result: RBACAnalysisResult) -> None:
    """Detect privilege escalation chains: SA → Binding → ClusterRole."""
    for node_id, data in G.nodes(data=True):
        if data.get("type") != "serviceaccount":
            continue

        sa_name = data.get("name", "")
        # Walk forward: SA → binding → role
        for successor in G.successors(node_id):
            succ_data = G.nodes.get(successor, {})
            if succ_data.get("type") in ("rolebinding", "clusterrolebinding"):
                for role_node in G.successors(successor):
                    role_data = G.nodes.get(role_node, {})
                    if role_data.get("type") == "clusterrole":
                        role_name = role_data.get("name", "")
                        result.findings.append(
                            RBACFinding(
                                severity="HIGH",
                                category="escalation-chain",
                                description=(
                                    f"ServiceAccount '{sa_name}' escalates to "
                                    f"ClusterRole '{role_name}' via "
                                    f"'{get_node_name(G, successor)}'. "
                                    f"This grants cluster-wide permissions."
                                ),
                                affected_nodes=[node_id, successor, role_node],
                            )
                        )


def _check_default_sa_usage(G: nx.DiGraph, result: RBACAnalysisResult) -> None:
    """Detect pods using the 'default' ServiceAccount."""
    for node_id, data in G.nodes(data=True):
        if data.get("type") != "pod":
            continue

        for successor in G.successors(node_id):
            succ_data = G.nodes.get(successor, {})
            if succ_data.get("type") == "serviceaccount" and succ_data.get("name") == "default":
                pod_name = data.get("name", "")
                result.findings.append(
                    RBACFinding(
                        severity="LOW",
                        category="default-sa",
                        description=(
                            f"Pod '{pod_name}' uses the 'default' ServiceAccount. "
                            f"Assign a dedicated SA with minimal permissions."
                        ),
                        affected_nodes=[node_id, successor],
                    )
                )


def format_rbac_analysis(result: RBACAnalysisResult) -> str:
    """Format RBAC analysis for console output.

    Args:
        result: RBACAnalysisResult.

    Returns:
        Formatted string.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  RBAC RISK ANALYSIS")
    lines.append("=" * 70)
    lines.append(f"  Total Findings: {len(result.findings)}")
    lines.append(f"    HIGH: {result.total_high} | MEDIUM: {result.total_medium} | LOW: {result.total_low}")
    lines.append("-" * 70)

    if not result.findings:
        lines.append("  No RBAC risks detected.")
    else:
        for idx, finding in enumerate(result.findings, 1):
            icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding.severity, "⚪")
            lines.append(f"\n  {icon} [{finding.severity}] {finding.category}")
            lines.append(f"    {finding.description}")

    lines.append("=" * 70)
    return "\n".join(lines)
