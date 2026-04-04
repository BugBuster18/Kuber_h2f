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
from .ingestion import ingest_from_json, ingest_from_kubectl, export_graph_to_json
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


def _load_graph(input_file: str | None, use_kubectl: bool):
    """Load and build the attack graph from the specified source.

    Args:
        input_file: Path to input JSON file.
        use_kubectl: Whether to use live kubectl ingestion.

    Returns:
        Tuple of (NetworkX DiGraph, ClusterGraph data model).
    """
    if input_file:
        console.print(f"[bold blue]📂 Loading graph from:[/] {input_file}")
        cluster = ingest_from_json(input_file)
    elif use_kubectl:
        console.print("[bold blue]🔗 Ingesting from live Kubernetes cluster via kubectl...[/]")
        cluster = ingest_from_kubectl()
    else:
        console.print("[bold red]❌ Error:[/] Provide --input <file> or --kubectl flag.")
        raise typer.Exit(code=1)

    G = build_attack_graph(cluster)
    summary = graph_summary(G)
    console.print(
        f"[bold green]✓[/] Graph loaded: "
        f"{summary['total_nodes']} nodes, {summary['total_edges']} edges, "
        f"{summary['source_nodes']} sources, {summary['sink_nodes']} sinks"
    )
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
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export results as JSON."),
):
    """🔥 Compute blast radius from a source node using BFS."""
    G, _ = _load_graph(input_file, kubectl)
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
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export results as JSON."),
):
    """🎯 Find the shortest (minimum-weight) attack path using Dijkstra."""
    G, _ = _load_graph(input_file, kubectl)
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
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export results as JSON."),
):
    """🔄 Detect all privilege escalation cycles using DFS."""
    G, _ = _load_graph(input_file, kubectl)

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
    top_n: int = typer.Option(5, "--top", "-n", help="Number of top critical nodes."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export results as JSON."),
):
    """🧪 Identify critical chokepoint nodes via graph surgery."""
    G, _ = _load_graph(input_file, kubectl)

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
    blast_source: Optional[str] = typer.Option(None, "--blast-source", help="Specific source for blast radius."),
    blast_depth: int = typer.Option(3, "--blast-depth", help="Max BFS depth for blast radius."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export full JSON report."),
    export_format: Optional[str] = typer.Option(None, "--export", "-e", help="Export format: 'json' or 'report'."),
):
    """📋 Generate comprehensive Kill Chain Report with all analyses."""
    G, _ = _load_graph(input_file, kubectl)

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
):
    """🏷️  Classify attack paths into categories with advanced scoring."""
    from .classifier import format_classified_paths

    G, _ = _load_graph(input_file, kubectl)
    paths = all_shortest_paths(G)
    console.print(format_classified_paths(G, paths))


@app.command("rbac-audit")
def cmd_rbac_audit(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export RBAC findings as JSON."),
):
    """🔐 Analyze RBAC patterns for security risks."""
    from .rbac_analyzer import analyze_rbac, format_rbac_analysis

    G, _ = _load_graph(input_file, kubectl)
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
):
    """📝 Generate natural language explanation of an attack path."""
    from .nlp_explainer import explain_path

    G, _ = _load_graph(input_file, kubectl)
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
    top_n: int = typer.Option(10, "--top", "-n", help="Number of top nodes to display."),
):
    """📈 Compute amplified node risk scores based on path centrality."""
    from .node_risk import compute_node_risk_amplification, format_node_risk

    G, _ = _load_graph(input_file, kubectl)
    entries = compute_node_risk_amplification(G, cutoff=15)
    console.print(format_node_risk(entries, top_n=top_n))


@app.command("export-frontend")
def cmd_export_frontend(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    output: str = typer.Option("visualizer/graph-data.json", "--output", "-o", help="Output JSON for frontend."),
):
    """🌐 Export graph data for the D3.js visualization frontend."""
    from .frontend_export import export_for_frontend

    G, _ = _load_graph(input_file, kubectl)
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


# ─── Neo4j + Snapshot + Watcher Commands ─────────────────────────────────────


@app.command("neo4j-sync")
def cmd_neo4j_sync(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j URI."),
    neo4j_user: str = typer.Option("neo4j", "--neo4j-user", help="Neo4j username."),
    neo4j_password: str = typer.Option("", "--neo4j-password", "-p", help="Neo4j password (or set NEO4J_PASSWORD env)."),
    snapshot_label: str = typer.Option("", "--label", "-l", help="Optional snapshot label."),
):
    """🗄️  Sync attack graph to Neo4j database."""
    from .neo4j_store import Neo4jStore

    _, cluster = _load_graph(input_file, kubectl)

    store = Neo4jStore(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
    try:
        store.connect()
        console.print("[green]✓ Connected to Neo4j[/]")
    except Exception as e:
        console.print(f"[bold red]❌ Neo4j connection failed:[/] {e}")
        raise typer.Exit(code=1)

    try:
        result = store.store_graph(cluster)
        console.print(
            f"[bold green]✓ Graph synced to Neo4j:[/] "
            f"{result['node_count']} nodes, {result['edge_count']} edges"
        )

        if snapshot_label:
            ts = store.store_snapshot(cluster, label=snapshot_label)
            console.print(f"[bold green]✓ Snapshot saved:[/] {ts} ({snapshot_label})")
    finally:
        store.close()


@app.command("neo4j-load")
def cmd_neo4j_load(
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j URI."),
    neo4j_user: str = typer.Option("neo4j", "--neo4j-user", help="Neo4j username."),
    neo4j_password: str = typer.Option("", "--neo4j-password", "-p", help="Neo4j password (or set NEO4J_PASSWORD env)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Export loaded graph to JSON file."),
    list_snapshots: bool = typer.Option(False, "--list-snapshots", help="List all stored snapshots."),
):
    """📥 Load graph from Neo4j or list stored snapshots."""
    from .neo4j_store import Neo4jStore

    store = Neo4jStore(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
    try:
        store.connect()
        console.print("[green]✓ Connected to Neo4j[/]")
    except Exception as e:
        console.print(f"[bold red]❌ Neo4j connection failed:[/] {e}")
        raise typer.Exit(code=1)

    try:
        if list_snapshots:
            snaps = store.list_snapshots()
            if not snaps:
                console.print("[yellow]No snapshots found in Neo4j.[/]")
            else:
                console.print(f"\n[bold]📸 Neo4j Snapshots ({len(snaps)}):[/]")
                for i, s in enumerate(snaps, 1):
                    console.print(
                        f"  {i}. [{s['timestamp']}] "
                        f"{s['label'] or '(unlabeled)'} — "
                        f"{s['node_count']} nodes, {s['edge_count']} edges"
                    )
            return

        cluster = store.load_graph()
        G = build_attack_graph(cluster)
        summary = graph_summary(G)
        console.print(
            f"[bold green]✓ Graph loaded from Neo4j:[/] "
            f"{summary['total_nodes']} nodes, {summary['total_edges']} edges"
        )

        if output:
            from .ingestion import export_graph_to_json
            export_graph_to_json(cluster, output)
            console.print(f"[bold green]✓ Exported to:[/] {output}")
    finally:
        store.close()


@app.command("watch")
def cmd_watch(
    interval: int = typer.Option(30, "--interval", "-t", help="Polling interval in seconds."),
    snapshots_dir: str = typer.Option("snapshots", "--snapshots-dir", "-d", help="Snapshot directory."),
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j URI."),
    neo4j_user: str = typer.Option("neo4j", "--neo4j-user", help="Neo4j username."),
    neo4j_password: str = typer.Option("", "--neo4j-password", "-p", help="Neo4j password (optional)."),
):
    """👁️  Start live kubectl watcher — auto-detect cluster changes and snapshot."""
    from .live_watcher import run_watcher_blocking

    run_watcher_blocking(
        interval=interval,
        snapshots_dir=snapshots_dir,
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password or None,
    )


@app.command("snapshot")
def cmd_snapshot(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    label: str = typer.Option("", "--label", "-l", help="Snapshot label."),
    snapshots_dir: str = typer.Option("snapshots", "--snapshots-dir", "-d", help="Snapshot directory."),
    list_all: bool = typer.Option(False, "--list", help="List all saved snapshots."),
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j URI."),
    neo4j_user: str = typer.Option("neo4j", "--neo4j-user", help="Neo4j username."),
    neo4j_password: str = typer.Option("", "--neo4j-password", "-p", help="Neo4j password (optional)."),
):
    """📸 Take a one-off snapshot or list existing snapshots."""
    from .snapshot_manager import save_snapshot, list_snapshots as ls_snaps

    if list_all:
        snaps = ls_snaps(snapshots_dir)
        if not snaps:
            console.print("[yellow]No snapshots found.[/]")
        else:
            console.print(f"\n[bold]📸 Snapshots ({len(snaps)}):[/]")
            for i, s in enumerate(snaps, 1):
                console.print(
                    f"  {i}. [{s['timestamp']}] "
                    f"{s['label'] or '(unlabeled)'} — "
                    f"{s['node_count']} nodes, {s['edge_count']} edges "
                    f"({s['source']})"
                )
        return

    _, cluster = _load_graph(input_file, kubectl)
    source = "kubectl" if kubectl else "json"

    filepath = save_snapshot(
        cluster,
        label=label,
        snapshots_dir=snapshots_dir,
        source=source,
    )
    console.print(f"[bold green]✓ Snapshot saved:[/] {filepath}")

    # Optionally also store in Neo4j
    if neo4j_password:
        try:
            from .neo4j_store import Neo4jStore
            store = Neo4jStore(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
            store.connect()
            ts = store.store_snapshot(cluster, label=label)
            console.print(f"[bold green]✓ Neo4j snapshot:[/] {ts}")
            store.close()
        except Exception as e:
            console.print(f"[yellow]⚠ Neo4j snapshot skipped: {e}[/]")


@app.command("timeline")
def cmd_timeline(
    snapshots_dir: str = typer.Option("snapshots", "--snapshots-dir", "-d", help="Snapshot directory."),
    output: str = typer.Option("timeline/timeline-data.json", "--output", "-o", help="Output timeline JSON."),
    serve: bool = typer.Option(False, "--serve", "-s", help="Start HTTP server to view timeline."),
    port: int = typer.Option(8090, "--port", help="HTTP server port."),
):
    """📊 Generate timeline visualizer with snapshot diffs."""
    from .snapshot_manager import export_timeline_data, list_snapshots as ls_snaps

    snaps = ls_snaps(snapshots_dir)
    if not snaps:
        console.print("[yellow]No snapshots found. Take snapshots first with 'snapshot' command.[/]")
        raise typer.Exit(code=1)

    console.print(f"[bold blue]📊 Generating timeline from {len(snaps)} snapshots...[/]")

    output_path = export_timeline_data(
        snapshots_dir=snapshots_dir,
        output_path=output,
    )
    console.print(f"[bold green]✓ Timeline data exported:[/] {output_path}")
    console.print(f"[dim]Open timeline/index.html in a browser to view.[/]")

    if serve:
        import http.server
        import socketserver

        timeline_dir = str(Path(output).parent)
        console.print(f"\n[bold blue]🌐 Serving timeline at http://localhost:{port}[/]")
        console.print("[dim]Press Ctrl+C to stop...[/]")

        handler = http.server.SimpleHTTPRequestHandler
        with socketserver.TCPServer(("", port), handler) as httpd:
            import os
            os.chdir(timeline_dir)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                console.print("\n[red]Server stopped.[/]")


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
