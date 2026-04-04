"""
Kill Chain Report Generator for KubeAttackViz.

Generates comprehensive, human-readable + machine-readable reports
combining all analysis results into a unified kill chain assessment.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx

from .models import AttackPath, BlastRadiusResult, CycleResult, CriticalNodeResult
from .graph_builder import (
    get_node_name,
    get_source_nodes,
    get_sink_nodes,
    graph_summary,
)
from .algorithms.bfs import blast_radius, format_blast_radius
from .algorithms.dijkstra import (
    shortest_attack_path,
    all_shortest_paths,
    format_all_paths,
    format_attack_path,
)
from .algorithms.dfs import detect_cycles, format_cycles
from .algorithms.critical_node import critical_node_analysis, format_critical_nodes
from .remediation import (
    generate_path_remediation,
    generate_critical_node_remediation,
    generate_cycle_remediation,
)


def _header() -> str:
    """Generate report header."""
    lines = [
        "",
        "╔" + "═" * 68 + "╗",
        "║" + "  KUBERNETES ATTACK PATH — KILL CHAIN REPORT".center(68) + "║",
        "║" + f"  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}".center(68) + "║",
        "║" + "  Tool: KubeAttackViz v2.0.0".center(68) + "║",
        "╚" + "═" * 68 + "╝",
        "",
    ]
    return "\n".join(lines)


def _graph_overview(G: nx.DiGraph) -> str:
    """Generate graph overview section."""
    summary = graph_summary(G)
    lines = [
        "=" * 70,
        "  GRAPH OVERVIEW",
        "=" * 70,
        f"  Total Nodes: {summary['total_nodes']}",
        f"  Total Edges: {summary['total_edges']}",
        f"  Source Nodes (Entry Points): {summary['source_nodes']}",
        f"  Sink Nodes (Targets): {summary['sink_nodes']}",
        f"  Is DAG: {'Yes' if summary['is_dag'] else 'No (contains cycles)'}",
        f"  Weakly Connected Components: {summary['weakly_connected_components']}",
        "",
        "  Node Types:",
    ]
    for ntype, count in sorted(summary["node_types"].items()):
        lines.append(f"    {ntype}: {count}")
    lines.append("")
    lines.append("  Relationship Types:")
    for rtype, count in sorted(summary["relationship_types"].items()):
        lines.append(f"    {rtype}: {count}")
    lines.append("=" * 70)
    return "\n".join(lines)


def generate_full_report(
    G: nx.DiGraph,
    blast_source: str | None = None,
    blast_depth: int = 3,
) -> str:
    """Generate the complete Kill Chain Report.

    Includes all five sections:
      1. Attack Paths (sorted by risk ascending)
      2. Blast Radius
      3. Cycle Detection
      4. Critical Node Analysis
      5. Summary + Remediation

    Args:
        G: The attack graph.
        blast_source: Optional specific source for blast radius.
                      If None, uses first available source node.
        blast_depth: Maximum BFS depth for blast radius (default: 3).

    Returns:
        Complete formatted report as a string.
    """
    sections: list[str] = []

    # Header
    sections.append(_header())

    # Graph Overview
    sections.append(_graph_overview(G))

    # ── Section 1: Attack Paths ──────────────────────────────────────────────
    paths = all_shortest_paths(G)
    sections.append(format_all_paths(G, paths))

    # Remediation for paths
    if paths:
        sections.append("")
        sections.append("=" * 70)
        sections.append("  ATTACK PATH REMEDIATION")
        sections.append("=" * 70)
        for idx, path in enumerate(paths, 1):
            sections.append(f"\n  ─── Path #{idx} Remediation ───")
            fixes = generate_path_remediation(G, path)
            for fix in fixes:
                sections.append(f"    {fix}")
        sections.append("=" * 70)

    # ── Section 2: Blast Radius ──────────────────────────────────────────────
    sources = get_source_nodes(G)
    if blast_source:
        br_result = blast_radius(G, blast_source, max_depth=blast_depth)
        sections.append(format_blast_radius(G, br_result))
    elif sources:
        # Run blast radius for each source
        for src in sources:
            br_result = blast_radius(G, src, max_depth=blast_depth)
            sections.append(format_blast_radius(G, br_result))
    else:
        sections.append("\n  [Blast Radius] No source nodes available for analysis.\n")

    # ── Section 3: Cycle Detection ───────────────────────────────────────────
    cycle_result = detect_cycles(G)
    sections.append(format_cycles(G, cycle_result))

    # Cycle remediation
    cycle_fixes = generate_cycle_remediation(G, cycle_result)
    if cycle_fixes:
        sections.append("")
        sections.append("=" * 70)
        sections.append("  CYCLE REMEDIATION")
        sections.append("=" * 70)
        for fix in cycle_fixes:
            sections.append(f"    {fix}")
        sections.append("=" * 70)

    # ── Section 4: Critical Node Analysis ────────────────────────────────────
    critical_result = critical_node_analysis(G)
    sections.append(format_critical_nodes(G, critical_result))

    # Critical node remediation
    critical_fixes = generate_critical_node_remediation(G, critical_result)
    if critical_fixes:
        sections.append("")
        sections.append("=" * 70)
        sections.append("  CRITICAL NODE REMEDIATION")
        sections.append("=" * 70)
        for fix in critical_fixes:
            sections.append(f"    {fix}")
        sections.append("=" * 70)

    # ── Section 5: Attack Classification ──────────────────────────────────────
    try:
        from .classifier import format_classified_paths
        sections.append(format_classified_paths(G, paths))
    except Exception:
        pass

    # ── Section 6: RBAC Risk Analysis ─────────────────────────────────────────
    try:
        from .rbac_analyzer import analyze_rbac, format_rbac_analysis
        rbac_result = analyze_rbac(G)
        sections.append(format_rbac_analysis(rbac_result))
    except Exception:
        pass

    # ── Section 7: NLP Explanation (top path) ─────────────────────────────────
    if paths:
        try:
            from .nlp_explainer import explain_path, explain_critical_node
            sections.append("")
            sections.append("=" * 70)
            sections.append("  NATURAL LANGUAGE PATH EXPLANATION (Highest-Risk Path)")
            sections.append("=" * 70)
            # Explain the highest risk path (last in ascending sort)
            sections.append(explain_path(G, paths[-1]))
            sections.append("")
            sections.append(explain_critical_node(G, critical_result))
            sections.append("=" * 70)
        except Exception:
            pass

    # ── Summary ──────────────────────────────────────────────────────────────
    sections.append(_generate_summary(G, paths, cycle_result, critical_result))

    return "\n".join(sections)


def _generate_summary(
    G: nx.DiGraph,
    paths: list[AttackPath],
    cycles: CycleResult,
    critical: CriticalNodeResult,
) -> str:
    """Generate executive summary section."""
    lines = [
        "",
        "╔" + "═" * 68 + "╗",
        "║" + "  EXECUTIVE SUMMARY".center(68) + "║",
        "╚" + "═" * 68 + "╝",
    ]

    total_paths = len(paths)
    critical_paths = sum(1 for p in paths if p.severity == "CRITICAL")
    high_paths = sum(1 for p in paths if p.severity == "HIGH")
    medium_paths = sum(1 for p in paths if p.severity == "MEDIUM")
    low_paths = sum(1 for p in paths if p.severity == "LOW")

    lines.append(f"\n  Attack Paths Found: {total_paths}")
    lines.append(f"    CRITICAL: {critical_paths}")
    lines.append(f"    HIGH:     {high_paths}")
    lines.append(f"    MEDIUM:   {medium_paths}")
    lines.append(f"    LOW:      {low_paths}")
    lines.append(f"\n  Privilege Escalation Cycles: {cycles.total_cycles}")
    lines.append(f"  Baseline Source→Sink Paths: {critical.total_paths_baseline}")

    if critical.top_nodes:
        top = critical.top_nodes[0]
        lines.append(
            f"\n  🔴 Most Critical Node: {top[1]}"
        )
        lines.append(
            f"     Removing it eliminates {top[2]} of {critical.total_paths_baseline} paths "
            f"({top[2] / max(critical.total_paths_baseline, 1) * 100:.1f}%)."
        )

    if critical_paths > 0:
        lines.append("\n  ⚠  IMMEDIATE ACTION REQUIRED: Critical attack paths detected!")
    elif high_paths > 0:
        lines.append("\n  ⚠  ACTION RECOMMENDED: High-severity paths should be reviewed.")
    else:
        lines.append("\n  ✓  Cluster posture is acceptable. Continue monitoring.")

    lines.append("")
    lines.append("=" * 70)
    lines.append(f"  Report generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("  Tool: KubeAttackViz v2.0.0 — Kubernetes Attack Path Visualizer")
    lines.append("=" * 70)

    return "\n".join(lines)


def export_report_json(
    G: nx.DiGraph,
    output_path: str | Path,
    blast_source: str | None = None,
    blast_depth: int = 3,
) -> None:
    """Export all analysis results as a machine-readable JSON report.

    Args:
        G: The attack graph.
        output_path: Path for the output JSON file.
        blast_source: Source node for blast radius analysis.
        blast_depth: Maximum BFS depth.
    """
    paths = all_shortest_paths(G)
    cycle_result = detect_cycles(G)
    critical_result = critical_node_analysis(G)

    sources = get_source_nodes(G)
    blast_results = []

    if blast_source:
        br = blast_radius(G, blast_source, max_depth=blast_depth)
        blast_results.append(br.to_dict())
    elif sources:
        for src in sources:
            br = blast_radius(G, src, max_depth=blast_depth)
            blast_results.append(br.to_dict())

    report = {
        "metadata": {
            "tool": "KubeAttackViz",
            "version": "2.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "graph_summary": graph_summary(G),
        "attack_paths": [p.to_dict() for p in paths],
        "blast_radius": blast_results,
        "cycles": cycle_result.to_dict(),
        "critical_nodes": critical_result.to_dict(),
        "remediation": {
            "path_fixes": [
                {
                    "path_index": i,
                    "fixes": generate_path_remediation(G, p),
                }
                for i, p in enumerate(paths)
            ],
            "critical_node_fixes": generate_critical_node_remediation(G, critical_result),
            "cycle_fixes": generate_cycle_remediation(G, cycle_result),
        },
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
