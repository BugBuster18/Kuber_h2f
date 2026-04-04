"""
CLI Interface for KubeAttackViz v2.0.

Production-grade command-line interface using Typer with all analysis
operations including temporal diff, RBAC analysis, classification,
NLP explanations, built-in tests, and frontend export.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .ingestion import ingest_from_json, ingest_from_kubectl, export_graph_to_json, dump_raw_kubernetes_state
from .graph_builder import build_attack_graph, resolve_node_id, get_node_name, graph_summary
from .algorithms.bfs import blast_radius, format_blast_radius
from .algorithms.dijkstra import (
    shortest_attack_path,
    all_shortest_paths,
    format_attack_path,
    format_all_paths,
)
from .algorithms.dfs import detect_cycles, format_cycles
from .algorithms.critical_node import critical_node_analysis, format_critical_nodes
from .report_generator import generate_full_report, export_report_json
from .remediation import (
    generate_path_remediation,
    generate_critical_node_remediation,
    generate_cycle_remediation,
)

app = typer.Typer(
    name="kube-attack-viz",
    help="🛡️  Kubernetes Attack Path Visualizer v2.0 — Analyze cluster attack surfaces using graph algorithms.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


def _load_graph(input_file: str | None, use_kubectl: bool, use_cvss: bool = True):
    """Load and build the attack graph from the specified source.

    Args:
        input_file: Path to input JSON file.
        use_kubectl: Whether to use live kubectl ingestion.
        use_cvss: Whether to apply CVSS weight adjustments.

    Returns:
        Tuple of (NetworkX DiGraph, ClusterGraph data model).
    """
    cluster = ingest_from_json(input_file) if input_file else ingest_from_kubectl()
    G = build_attack_graph(cluster, use_cvss_weights=use_cvss)
    
    summary = graph_summary(G)
    msg = f"Graph loaded: {summary['total_nodes']} nodes, {summary['total_edges']} edges"
    if not use_cvss:
        msg += " [bold yellow](CVSS WEIGHTS DISABLED)[/]"
    console.print(f"[bold green]✓[/] {msg}")
    
    return G, cluster


def _resolve_or_exit(G, identifier: str, label: str = "Node") -> str:
    """Resolve a node identifier or exit with error."""
    node_id = resolve_node_id(G, identifier)
    if node_id is None:
        console.print(f"[bold red]❌ {label} not found:[/] '{identifier}'")
        console.print("[dim]Available nodes:[/]")
        for nid, data in G.nodes(data=True):
            console.print(f"  • {data.get('name', nid)} ({nid})")
        raise typer.Exit(code=1)
    return node_id


# ─── Original Commands (Preserved) ───────────────────────────────────────────


@app.command("blast-radius")
def cmd_blast_radius(
    source: str = typer.Option(..., "--source", "-s", help="Source node ID or name."),
    depth: int = typer.Option(3, "--depth", "-d", help="Maximum BFS depth."),
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export results as JSON."),
):
    """🔥 Compute blast radius from a source node using BFS."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)
    source_id = _resolve_or_exit(G, source, "Source node")

    result = blast_radius(G, source_id, max_depth=depth)
    console.print(format_blast_radius(G, result))

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("shortest-path")
def cmd_shortest_path(
    source: str = typer.Option(..., "--source", "-s", help="Source node ID or name."),
    target: str = typer.Option(..., "--target", "-t", help="Target node ID or name."),
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export results as JSON."),
):
    """🎯 Find the shortest (minimum-weight) attack path using Dijkstra."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)
    source_id = _resolve_or_exit(G, source, "Source node")
    target_id = _resolve_or_exit(G, target, "Target node")

    path = shortest_attack_path(G, source_id, target_id)

    if path is None:
        console.print(
            f"[bold yellow]⚠ No path exists[/] from "
            f"'{get_node_name(G, source_id)}' to '{get_node_name(G, target_id)}'."
        )
        raise typer.Exit(code=0)

    console.print("\n" + "=" * 70)
    console.print("  SHORTEST ATTACK PATH (Dijkstra)")
    console.print("=" * 70)
    console.print(format_attack_path(G, path))

    # NLP Explanation
    from .nlp_explainer import explain_path
    console.print("\n  📝 Natural Language Explanation:")
    console.print("  " + explain_path(G, path).replace("\n", "\n  "))

    # Remediation
    fixes = generate_path_remediation(G, path)
    console.print("\n  Remediation:")
    for fix in fixes:
        console.print(f"    {fix}")
    console.print("=" * 70)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(path.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("cycles")
def cmd_cycles(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export results as JSON."),
):
    """🔄 Detect all privilege escalation cycles using DFS."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)

    result = detect_cycles(G)
    console.print(format_cycles(G, result))

    # Remediation
    fixes = generate_cycle_remediation(G, result)
    if fixes:
        console.print("\n  Cycle Remediation:")
        for fix in fixes:
            console.print(f"    {fix}")
        console.print("=" * 70)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("critical-node")
def cmd_critical_node(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    top_n: int = typer.Option(5, "--top", "-n", help="Number of top critical nodes."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export results as JSON."),
):
    """🧪 Identify critical chokepoint nodes via graph surgery."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)

    result = critical_node_analysis(G, top_n=top_n)
    console.print(format_critical_nodes(G, result))

    # NLP explanation
    from .nlp_explainer import explain_critical_node
    console.print("\n  📝 Explanation:")
    console.print("  " + explain_critical_node(G, result).replace("\n", "\n  "))

    # Remediation
    fixes = generate_critical_node_remediation(G, result)
    if fixes:
        console.print("\n  Critical Node Remediation:")
        for fix in fixes:
            console.print(f"    {fix}")
        console.print("=" * 70)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("full-report")
def cmd_full_report(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    blast_source: Optional[str] = typer.Option(None, "--blast-source", help="Specific source for blast radius."),
    blast_depth: int = typer.Option(3, "--blast-depth", help="Max BFS depth for blast radius."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export full JSON report."),
    export_format: Optional[str] = typer.Option(None, "--export", "-e", help="Export format: 'json' or 'report'."),
):
    """📋 Generate comprehensive Kill Chain Report with all analyses."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)

    # Resolve blast source if provided
    blast_id = None
    if blast_source:
        blast_id = _resolve_or_exit(G, blast_source, "Blast radius source")

    report = generate_full_report(G, blast_source=blast_id, blast_depth=blast_depth)
    console.print(report)

    # Handle export flag
    out_path = output_json
    if export_format == "json" and not out_path:
        out_path = "report.json"
    elif export_format == "report" and not out_path:
        out_path = "report.txt"

    if out_path and out_path.endswith(".json"):
        export_report_json(G, out_path, blast_source=blast_id, blast_depth=blast_depth)
        console.print(f"\n[bold green]✓ JSON report exported:[/] {out_path}")
    elif out_path and out_path.endswith(".txt"):
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"\n[bold green]✓ Text report exported:[/] {out_path}")
    elif out_path:
        export_report_json(G, out_path, blast_source=blast_id, blast_depth=blast_depth)
        console.print(f"\n[bold green]✓ JSON report exported:[/] {out_path}")


@app.command("graph-info")
def cmd_graph_info(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
):
    """ℹ️  Display graph structure summary and node listing."""
    G, _ = _load_graph(input_file, kubectl)
    summary = graph_summary(G)

    console.print("\n" + "=" * 70)
    console.print("  GRAPH INFORMATION")
    console.print("=" * 70)
    console.print(f"  Nodes: {summary['total_nodes']}")
    console.print(f"  Edges: {summary['total_edges']}")
    console.print(f"  Sources: {summary['source_nodes']}")
    console.print(f"  Sinks: {summary['sink_nodes']}")
    console.print(f"  DAG: {'Yes' if summary['is_dag'] else 'No'}")
    console.print(f"  Components: {summary['weakly_connected_components']}")

    console.print("\n  Node Types:")
    for ntype, count in sorted(summary["node_types"].items()):
        console.print(f"    {ntype}: {count}")

    console.print("\n  All Nodes:")
    for nid, data in sorted(G.nodes(data=True), key=lambda x: x[1].get("type", "")):
        flags = []
        if data.get("is_source"):
            flags.append("SOURCE")
        if data.get("is_sink"):
            flags.append("SINK")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        console.print(
            f"    {data.get('name', nid)} [{data.get('type', '?')}] "
            f"ns={data.get('namespace', '?')} risk={data.get('risk_score', 0):.1f}{flag_str}"
        )

    console.print("=" * 70)


@app.command("export-graph")
def cmd_export_graph(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    output: str = typer.Option("cluster-graph.json", "--output", "-o", help="Output JSON file path."),
):
    """💾 Export cluster graph to JSON file (useful after kubectl ingestion)."""
    if input_file:
        cluster = ingest_from_json(input_file)
    elif kubectl:
        cluster = ingest_from_kubectl()
    else:
        console.print("[bold red]❌ Error:[/] Provide --input <file> or --kubectl flag.")
        raise typer.Exit(code=1)

    export_graph_to_json(cluster, output)
    console.print(f"[bold green]✓ Graph exported to:[/] {output}")


# ─── NEW Commands (v2.0) ─────────────────────────────────────────────────────


@app.command("diff")
def cmd_diff(
    old: str = typer.Argument(..., help="Path to old/baseline graph JSON."),
    new: str = typer.Argument(..., help="Path to new/current graph JSON."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export diff as JSON."),
):
    """🔀 Temporal analysis — diff two cluster graph snapshots."""
    from .temporal import temporal_diff, format_temporal_diff

    console.print(f"[bold blue]📊 Comparing:[/] {old} → {new}")
    diff = temporal_diff(old, new)
    console.print(format_temporal_diff(diff))

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(diff.to_dict(), f, indent=2, default=str)
        console.print(f"[bold green]✓ Diff exported:[/] {output_json}")


@app.command("classify")
def cmd_classify(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
):
    """🏷️  Classify attack paths into categories with advanced scoring."""
    from .classifier import format_classified_paths

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)
    paths = all_shortest_paths(G)
    console.print(format_classified_paths(G, paths))


@app.command("rbac-audit")
def cmd_rbac_audit(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export RBAC findings as JSON."),
):
    """🔐 Analyze RBAC patterns for security risks."""
    from .rbac_analyzer import analyze_rbac, format_rbac_analysis

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)
    result = analyze_rbac(G)
    console.print(format_rbac_analysis(result))

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ RBAC audit exported:[/] {output_json}")


@app.command("explain")
def cmd_explain(
    source: str = typer.Option(..., "--source", "-s", help="Source node ID or name."),
    target: str = typer.Option(..., "--target", "-t", help="Target node ID or name."),
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
):
    """📝 Generate natural language explanation of an attack path."""
    from .nlp_explainer import explain_path

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)
    source_id = _resolve_or_exit(G, source, "Source node")
    target_id = _resolve_or_exit(G, target, "Target node")

    path = shortest_attack_path(G, source_id, target_id)
    if path is None:
        console.print(
            f"[bold yellow]⚠ No path exists[/] from "
            f"'{get_node_name(G, source_id)}' to '{get_node_name(G, target_id)}'."
        )
        raise typer.Exit(code=0)

    console.print("\n" + "=" * 70)
    console.print("  NATURAL LANGUAGE ATTACK PATH EXPLANATION")
    console.print("=" * 70)
    console.print(explain_path(G, path))
    console.print("=" * 70)


@app.command("node-risk")
def cmd_node_risk(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    top_n: int = typer.Option(10, "--top", "-n", help="Number of top nodes to display."),
):
    """📈 Compute amplified node risk scores based on path centrality."""
    from .node_risk import compute_node_risk_amplification, format_node_risk

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)
    entries = compute_node_risk_amplification(G, cutoff=15)
    console.print(format_node_risk(entries, top_n=top_n))


@app.command("export-frontend")
def cmd_export_frontend(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    output: str = typer.Option("visualizer/graph-data.json", "--output", "-o", help="Output JSON for frontend."),
):
    """🌐 Export graph data for the D3.js visualization frontend."""
    from .frontend_export import export_for_frontend

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss)
    export_for_frontend(G, output)
    console.print(f"[bold green]✓ Frontend data exported to:[/] {output}")
    console.print(f"[dim]Open visualizer/index.html in a browser to view.[/]")


@app.command("run-tests")
def cmd_run_tests():
    """🧪 Run built-in validation test suite."""
    from .test_runner import run_all_tests, format_test_results

    console.print("[bold blue]🧪 Running built-in test suite...[/]")
    result = run_all_tests()
    console.print(format_test_results(result))

    if not result.success:
        raise typer.Exit(code=1)


@app.command("dump-raw")
def cmd_dump_raw(
    output: Path = typer.Option(
        "raw-k8s-state.json", "--output", "-o", help="Output file path for raw JSON."
    ),
):
    """📂 Dump raw Kubernetes resource state to a single JSON file (requires kubectl)."""
    try:
        with console.status("[bold green]Querying Kubernetes cluster for raw state..."):
            dump_raw_kubernetes_state(output)
        console.print(f"[bold green]✓ Raw cluster state saved to:[/] {output}")
    except Exception as e:
        console.print(f"[bold red]❌ Raw dump failed:[/] {e}")
        raise typer.Exit(code=1)


def version_callback(value: bool):
    if value:
        console.print(f"KubeAttackViz v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
):
    """🛡️  KubeAttackViz v2.0 — Kubernetes Attack Path Visualizer

    Analyze Kubernetes cluster attack surfaces using graph algorithms.
    Supports BFS blast radius, Dijkstra shortest paths, DFS cycle detection,
    critical node analysis, RBAC auditing, temporal diff, NLP explanations,
    and D3.js visualization export.
    """
    pass
