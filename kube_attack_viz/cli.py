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
from rich.markup import escape
from rich.text import Text

from . import __version__
from .ingestion import (
    ingest_from_json,
    ingest_from_kubectl,
    export_graph_to_json,
    dump_raw_kubernetes_state,
    enrich_cluster_graph,
)
from .graph_builder import (
    build_attack_graph, resolve_node_id, get_node_name, graph_summary, set_default_weight_mode,
)
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


def _out(text: str) -> None:
    """Print plain-text report output with Rich markup disabled.

    Reports contain literal square brackets ("──[routes_to]──▸", "[pod]",
    "[HIGH]") which Rich would otherwise swallow as markup tags.
    """
    console.print(text, markup=False)


def _load_graph(
    input_file: str | None,
    use_kubectl: bool,
    use_cvss: bool = True,
    enrich: Optional[bool] = None,
) -> tuple[nx.DiGraph, ClusterGraph]:
    """Load and build the attack graph from specified source.
    
    Smart Default:
    - If kubectl is used: Default enrich to TRUE.
    - If JSON file is used: Default enrich to FALSE (assume already enriched).
    """
    if enrich is None:
        enrich = True if use_kubectl else False

    if use_kubectl:
        with console.status("[bold cyan]Querying cluster via kubectl..."):
            cluster = ingest_from_kubectl()
    elif input_file:
        with console.status(f"[bold cyan]Ingesting graph from {input_file}..."):
            cluster = ingest_from_json(input_file)
    else:
        console.print("[bold red]❌ Error:[/] You must provide --input or --kubectl.")
        raise typer.Exit(code=1)

    if enrich:
        count = enrich_cluster_graph(cluster)
        if count > 0:
            console.print(f"[bold cyan]ℹ Live Enrichment:[/] Updated {count} CVE(s) from NVD.")

    G = build_attack_graph(cluster, use_cvss_weights=use_cvss)

    summary = graph_summary(G)
    msg = f"Graph loaded: {summary['total_nodes']} nodes, {summary['total_edges']} edges"
    if G.graph.get("weight_mode") == "learned":
        msg += " [bold magenta](LEARNED weights: -ln P(success))[/]"
    elif not use_cvss:
        msg += " [bold yellow](CVSS WEIGHTS DISABLED)[/]"
    console.print(f"[bold green]✓[/] {msg}")
    
    return G, cluster


def _save_report(report_text: str, output_path: str | None):
    """Save a text report to a file if requested."""
    if not output_path:
        return
    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Strip rich color codes if present (though generate_full_report uses plain strings)
        with open(path, "w", encoding="utf-8") as f:
            f.write(report_text)
        console.print(f"[bold green]✓ Report saved to:[/] {output_path}")
    except Exception as e:
        console.print(f"[bold red]❌ Failed to save report:[/] {e}")


def _resolve_or_exit(G, identifier: str, label: str = "Node") -> str:
    """Resolve a node identifier or exit with error."""
    node_id = resolve_node_id(G, identifier)
    if node_id is None:
        console.print(f"[bold red]❌ {label} not found:[/] '{identifier}'")
        console.print("[dim]Available nodes:[/]")
        for nid, data in G.nodes(data=True):
            _out(f"  • {data.get('name', nid)} ({nid})")
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
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export results as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the report as a text file."),
):
    """🔥 Compute blast radius from a source node using BFS."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)
    source_id = _resolve_or_exit(G, source, "Source node")

    result = blast_radius(G, source_id, max_depth=depth)
    report = format_blast_radius(G, result)
    _out(report)

    _save_report(report, output)

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
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export path as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the path report as a text file."),
):
    """🎯 Find the shortest (minimum-weight) attack path using Dijkstra."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)
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
    path_report = format_attack_path(G, path)
    _out(path_report)

    # NLP Explanation
    from .nlp_explainer import explain_path
    nlp_text = "\n  📝 Natural Language Explanation:\n" + "  " + explain_path(G, path).replace("\n", "\n  ")
    _out(nlp_text)

    # Remediation
    fixes = generate_path_remediation(G, path)
    rem_text = "\n  Remediation:\n"
    for fix in fixes:
        rem_text += f"    {fix}\n"
    _out(rem_text)
    console.print("=" * 70)

    full_text = f"SHORTEST ATTACK PATH\n{path_report}\n{nlp_text}\n{rem_text}"
    _save_report(full_text, output)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(path.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("cycles")
def cmd_cycles(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export results as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the cycle report as a text file."),
):
    """🔄 Detect all privilege escalation cycles using DFS."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)

    result = detect_cycles(G)
    report = format_cycles(G, result)
    _out(report)

    # Remediation
    rem_msg = ""
    fixes = generate_cycle_remediation(G, result)
    if fixes:
        rem_msg = "\n  Cycle Remediation:\n"
        for fix in fixes:
            rem_msg += f"    {fix}\n"
        rem_msg += "=" * 70 + "\n"
        _out(rem_msg)

    _save_report(report + rem_msg, output)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("critical-node")
def cmd_critical_node(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    top_n: int = typer.Option(5, "--top", "-n", help="Number of top critical nodes."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export results as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the critical node report as a text file."),
):
    """🧪 Identify critical chokepoint nodes via graph surgery."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)

    result = critical_node_analysis(G, top_n=top_n)
    report = format_critical_nodes(G, result)
    _out(report)

    # Explanation
    from .nlp_explainer import explain_critical_node
    nlp_text = "\n  📝 Explanation:\n" + "  " + explain_critical_node(G, result).replace("\n", "\n  ") + "\n"
    _out(nlp_text)

    # Remediation
    rem_text = ""
    fixes = generate_critical_node_remediation(G, result)
    if fixes:
        rem_text = "\n  Critical Node Remediation:\n"
        for fix in fixes:
            rem_text += f"    {fix}\n"
        rem_text += "=" * 70 + "\n"
        _out(rem_text)

    _save_report(report + nlp_text + rem_text, output)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("full-report")
def cmd_full_report(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    blast_source: Optional[str] = typer.Option(None, "--blast-source", help="Specific source for blast radius."),
    blast_depth: int = typer.Option(3, "--blast-depth", help="Max BFS depth for blast radius."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export full JSON report."),
    output: str = typer.Option("report.txt", "--output", "-o", help="Save the human-readable report as a text file."),
):
    """📋 Generate comprehensive Kill Chain Report with all analyses."""
    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)

    # Resolve blast source if provided
    blast_id = None
    if blast_source:
        blast_id = _resolve_or_exit(G, blast_source, "Blast radius source")

    report = generate_full_report(G, blast_source=blast_id, blast_depth=blast_depth)
    _out(report)

    _save_report(report, output)

    if output_json:
        export_report_json(G, output_json, blast_source=blast_id, blast_depth=blast_depth)
        console.print(f"[bold green]✓ JSON report exported:[/] {output_json}")


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
        _out(
            f"    {data.get('name', nid)} [{data.get('type', '?')}] "
            f"ns={data.get('namespace', '?')} risk={data.get('risk_score', 0):.1f}{flag_str}"
        )

    console.print("=" * 70)


@app.command("export-graph")
def cmd_export_graph(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    enrich: bool = typer.Option(True, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD before exporting (Enabled by default)."),
    output: str = typer.Option("cluster-graph.json", "--output", "-o", help="Output JSON file path."),
):
    """💾 Export cluster graph to JSON file (useful after kubectl ingestion)."""
    _, cluster = _load_graph(input_file, kubectl, enrich=enrich)
    export_graph_to_json(cluster, output)
    console.print(f"[bold green]✓ Graph exported to:[/] {output}")


# ─── NEW Commands (v2.0) ─────────────────────────────────────────────────────


@app.command("diff")
def cmd_diff(
    old: str = typer.Argument(..., help="Path to old/baseline graph JSON."),
    new: str = typer.Argument(..., help="Path to new/current graph JSON."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export diff as JSON."),
    neo4j_uri: Optional[str] = typer.Option(None, "--neo4j-uri", help="Neo4j bolt URI (e.g. bolt://localhost:7687)."),
    neo4j_user: str = typer.Option("neo4j", "--neo4j-user", help="Neo4j username."),
    neo4j_password: str = typer.Option("password", "--neo4j-pass", help="Neo4j password."),
):
    """🔀 Temporal analysis — diff two cluster graph snapshots."""
    from .temporal import temporal_diff, format_temporal_diff, format_alert_summary, Neo4jExporter

    console.print(f"[bold blue]📊 Comparing:[/] {old} → {new}")
    diff = temporal_diff(old, new)
    _out(format_temporal_diff(diff))

    # Show alert summary
    if diff.alerts:
        _out(format_alert_summary(diff.alerts))

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(diff.to_dict(), f, indent=2, default=str)
        console.print(f"[bold green]✓ Diff exported:[/] {output_json}")

    # Neo4j export
    if neo4j_uri and diff.has_changes:
        try:
            exporter = Neo4jExporter(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
            exporter.ensure_constraints()
            stats = exporter.export_diff(diff)
            exporter.close()
            console.print(f"[bold green]✓ Neo4j export:[/] {stats}")
        except Exception as e:
            console.print(f"[bold red]❌ Neo4j export failed:[/] {e}")


@app.command("watch")
def cmd_watch(
    interval: int = typer.Option(300, "--interval", "-n", help="Scan interval in seconds."),
    source: str = typer.Option("kubectl", "--source", "-s", help="Scan source: 'kubectl' or 'json:<path>'."),
    persist_dir: str = typer.Option(".temporal_snapshots", "--persist-dir", "-d", help="Directory for snapshot persistence."),
    max_snapshots: int = typer.Option(100, "--max-snapshots", help="Maximum snapshots to retain."),
    neo4j_uri: Optional[str] = typer.Option(None, "--neo4j-uri", help="Neo4j bolt URI for auto-export on changes."),
    neo4j_user: str = typer.Option("neo4j", "--neo4j-user", help="Neo4j username."),
    neo4j_password: str = typer.Option("password", "--neo4j-pass", help="Neo4j password."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Save diff history to JSON on exit."),
    single: bool = typer.Option(False, "--single", help="Run a single scan cycle then exit."),
):
    """👁️  Continuous temporal monitoring — periodic scan, diff, and alert.

    Continuously scans the cluster at the specified interval, compares
    consecutive snapshots, and generates alerts when new attack paths
    appear. Optionally exports changed graphs to Neo4j automatically.

    Examples:
        # Watch live cluster every 5 minutes
        kube-attack-viz watch --interval 300 --source kubectl

        # Watch a JSON file (re-read periodically) with Neo4j export
        kube-attack-viz watch -n 60 -s json:cluster-graph.json --neo4j-uri bolt://localhost:7687

        # Single scan (for CI/CD pipelines)
        kube-attack-viz watch --single -s json:cluster-graph.json
    """
    from .temporal import (
        TemporalWatcher, format_temporal_diff, format_alert_summary,
        format_snapshot_history, TemporalDiff, TemporalAlert,
    )

    scan_count = 0
    alert_count = 0

    def on_diff(diff: TemporalDiff):
        nonlocal scan_count
        scan_count += 1
        if diff.has_changes:
            console.print(f"\n[bold yellow]⚡ Change detected (scan #{scan_count}):[/]")
            _out(format_temporal_diff(diff))
        else:
            console.print(f"[dim]  Scan #{scan_count}: No changes.[/]")

    def on_alert(alert: TemporalAlert):
        nonlocal alert_count
        alert_count += 1
        sev_colors = {
            "CRITICAL": "bold red", "HIGH": "bold yellow",
            "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim",
        }
        color = sev_colors.get(alert.severity, "white")
        console.print(f"  [{color}]🚨 {escape(f'[{alert.severity}] {alert.title}')}[/]")

    watcher = TemporalWatcher(
        interval_seconds=interval,
        source=source,
        persist_dir=persist_dir,
        max_snapshots=max_snapshots,
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
        on_diff=on_diff,
        on_alert=on_alert,
    )

    if single:
        # Single scan mode (good for CI/CD)
        console.print(f"[bold cyan]📸 Single scan mode ({source})...[/]")
        diff = watcher.scan_once()
        if diff is None:
            console.print("[bold green]✓ First snapshot captured.[/]")
            console.print("[dim]  Run again to diff against this baseline.[/]")
        elif not diff.has_changes:
            console.print("[bold green]✓ No changes detected.[/]")

        _out(format_snapshot_history(watcher.store))

        if output_json and watcher.diff_history:
            history = [d.to_dict() for d in watcher.diff_history]
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2, default=str)
            console.print(f"[bold green]✓ Diff history saved:[/] {output_json}")
        return

    # Continuous mode
    console.print(Panel.fit(
        f"[bold cyan]👁️  Temporal Watcher Active[/]\n"
        f"  Source:   {source}\n"
        f"  Interval: {interval}s\n"
        f"  Storage:  {persist_dir}\n"
        f"  Neo4j:    {neo4j_uri or 'disabled'}\n\n"
        f"  Press Ctrl+C to stop.",
        title="[bold]KubeAttackViz Temporal Monitor[/]",
        border_style="cyan",
    ))

    watcher.start()

    try:
        while watcher.is_running:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⏹  Stopping watcher...[/]")
        watcher.stop()

    # Final summary
    console.print(f"\n[bold green]✓ Monitoring complete.[/]")
    console.print(f"  Scans performed:  {scan_count}")
    console.print(f"  Alerts generated: {alert_count}")
    console.print(f"  Snapshots stored: {watcher.snapshot_count}")
    _out(format_snapshot_history(watcher.store))

    if output_json and watcher.diff_history:
        history = [d.to_dict() for d in watcher.diff_history]
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, default=str)
        console.print(f"[bold green]✓ Diff history saved:[/] {output_json}")


@app.command("temporal-history")
def cmd_temporal_history(
    persist_dir: str = typer.Option(".temporal_snapshots", "--persist-dir", "-d", help="Snapshot persistence directory."),
    diff_all: bool = typer.Option(False, "--diff-all", help="Diff all consecutive snapshot pairs."),
    output_json: Optional[str] = typer.Option(None, "--output-json", "-o", help="Export full history as JSON."),
):
    """📜 View temporal snapshot history and replay diffs.

    Shows all stored snapshots and optionally re-computes diffs for
    each consecutive pair to reconstruct the full temporal timeline.
    """
    from .temporal import (
        SnapshotStore, diff_snapshots, format_temporal_diff,
        format_snapshot_history, format_alert_summary,
    )

    store = SnapshotStore(persist_dir=persist_dir)

    if store.count == 0:
        console.print("[bold yellow]⚠ No snapshots found.[/]")
        console.print(f"[dim]  Directory checked: {persist_dir}[/]")
        console.print("[dim]  Run 'watch --single' or 'temporal-snapshot' to capture one.[/]")
        return

    _out(format_snapshot_history(store))

    if diff_all:
        pairs = store.get_consecutive_pairs()
        if not pairs:
            console.print("[dim]  Need at least 2 snapshots for diff.[/]")
            return

        all_diffs = []
        for i, (old, new) in enumerate(pairs, 1):
            console.print(f"\n[bold blue]─── Diff #{i}: {old.timestamp} → {new.timestamp} ───[/]")
            diff = diff_snapshots(old, new)
            _out(format_temporal_diff(diff))
            if diff.alerts:
                _out(format_alert_summary(diff.alerts))
            all_diffs.append(diff)

        if output_json:
            history = [d.to_dict() for d in all_diffs]
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2, default=str)
            console.print(f"[bold green]✓ Full diff history exported:[/] {output_json}")


@app.command("temporal-snapshot")
def cmd_temporal_snapshot(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Capture from live cluster."),
    persist_dir: str = typer.Option(".temporal_snapshots", "--persist-dir", "-d", help="Snapshot storage directory."),
    diff_previous: bool = typer.Option(True, "--diff/--no-diff", help="Diff against previous snapshot."),
    neo4j_uri: Optional[str] = typer.Option(None, "--neo4j-uri", help="Neo4j bolt URI for export."),
    neo4j_user: str = typer.Option("neo4j", "--neo4j-user", help="Neo4j username."),
    neo4j_password: str = typer.Option("password", "--neo4j-pass", help="Neo4j password."),
):
    """📸 Capture a single temporal snapshot and optionally diff.

    Stores the current cluster state as a snapshot. If a previous
    snapshot exists, automatically diffs and alerts on new attack paths.

    Examples:
        # Capture from JSON
        kube-attack-viz temporal-snapshot -i cluster-graph.json

        # Capture from live cluster with Neo4j export
        kube-attack-viz temporal-snapshot -k --neo4j-uri bolt://localhost:7687
    """
    from .temporal import (
        Snapshot, SnapshotStore, diff_snapshots,
        format_temporal_diff, format_alert_summary,
        format_snapshot_history, Neo4jExporter,
    )

    store = SnapshotStore(persist_dir=persist_dir)

    # Capture snapshot
    if kubectl:
        with console.status("[bold cyan]Querying cluster via kubectl..."):
            cluster = ingest_from_kubectl()
        source = "kubectl"
    elif input_file:
        cluster = ingest_from_json(input_file)
        source = f"json:{input_file}"
    else:
        console.print("[bold red]❌ Error:[/] Provide --input or --kubectl.")
        raise typer.Exit(code=1)

    new_snap = Snapshot.from_cluster(cluster, source=source)
    old_snap = store.latest

    # Quick hash check
    if old_snap and old_snap.graph_hash == new_snap.graph_hash:
        console.print("[bold green]✓ Snapshot captured (identical to previous).[/]")
        store.add(new_snap)
        _out(format_snapshot_history(store))
        return

    store.add(new_snap)
    console.print(f"[bold green]✓ Snapshot captured:[/] {new_snap.snapshot_id}")
    console.print(f"  Hash: {new_snap.graph_hash}  Source: {source}")

    # Diff against previous
    if diff_previous and old_snap:
        diff = diff_snapshots(old_snap, new_snap)
        _out(format_temporal_diff(diff))

        if diff.alerts:
            _out(format_alert_summary(diff.alerts))

        # Neo4j export if changes detected
        if neo4j_uri and diff.has_changes:
            try:
                exporter = Neo4jExporter(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
                exporter.ensure_constraints()
                stats = exporter.export_diff(diff, old_snap, new_snap)
                exporter.close()
                console.print(f"[bold green]✓ Neo4j export:[/] {stats}")
            except Exception as e:
                console.print(f"[bold red]❌ Neo4j export failed:[/] {e}")
    elif not old_snap:
        console.print("[dim]  First snapshot — diff will be available after next capture.[/]")

    _out(format_snapshot_history(store))


@app.command("classify")
def cmd_classify(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the classification report as a text file."),
):
    """🏷️  Classify attack paths into categories with advanced scoring."""
    from .classifier import format_classified_paths

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)
    paths = all_shortest_paths(G)
    report = format_classified_paths(G, paths)
    _out(report)
    _save_report(report, output)


@app.command("rbac-audit")
def cmd_rbac_audit(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export RBAC findings as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the RBAC audit report as a text file."),
):
    """🔐 Analyze RBAC patterns for security risks."""
    from .rbac_analyzer import analyze_rbac, format_rbac_analysis

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)
    result = analyze_rbac(G)
    report = format_rbac_analysis(result)
    _out(report)
    _save_report(report, output)

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
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
):
    """📝 Generate natural language explanation of an attack path."""
    from .nlp_explainer import explain_path

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)
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
    _out(explain_path(G, path))
    console.print("=" * 70)


@app.command("node-risk")
def cmd_node_risk(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    top_n: int = typer.Option(10, "--top", "-n", help="Number of top nodes to display."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the node risk report as a text file."),
):
    """📈 Compute amplified node risk scores based on path centrality."""
    from .node_risk import compute_node_risk_amplification, format_node_risk

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)
    entries = compute_node_risk_amplification(G, cutoff=15)
    report = format_node_risk(entries, top_n=top_n)
    _out(report)
    _save_report(report, output)


@app.command("export-frontend")
def cmd_export_frontend(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD (Enabled for kubectl, Disabled for JSON)."),
    output: str = typer.Option("visualizer/graph-data.json", "--output", "-o", help="Output JSON for frontend."),
):
    """🌐 Export graph data for the D3.js visualization frontend."""
    from .frontend_export import export_for_frontend

    G, _ = _load_graph(input_file, kubectl, use_cvss=use_cvss, enrich=enrich)
    export_for_frontend(G, output)
    console.print(f"[bold green]✓ Frontend data exported to:[/] {output}")
    console.print(f"[dim]Open visualizer/index.html in a browser to view.[/]")


@app.command("run-tests")
def cmd_run_tests():
    """🧪 Run built-in validation test suite."""
    from .test_runner import run_all_tests, format_test_results

    console.print("[bold blue]🧪 Running built-in test suite...[/]")
    result = run_all_tests()
    _out(format_test_results(result))

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


# ─── ML Commands ─────────────────────────────────────────────────────────────


@app.command("ml-fetch-data")
def cmd_ml_fetch_data(
    start_year: int = typer.Option(2010, "--start-year", help="First NVD year to download."),
    epss: bool = typer.Option(True, "--epss/--no-epss", help="Also download EPSS (benchmark only)."),
    force: bool = typer.Option(False, "--force", help="Re-download files that already exist."),
):
    """⬇️  Download training data: CISA KEV, NVD CVE feeds, FIRST EPSS."""
    from datetime import datetime, timezone
    from .ml.datasets import fetch_all
    from .ml.paths import RAW_DIR

    years = range(start_year, datetime.now(timezone.utc).year + 1)
    console.print(f"[bold cyan]Downloading datasets to {RAW_DIR}[/]")
    fetch_all(years=years, with_epss=epss, force=force, log=_out)
    console.print("[bold green]✓ Done.[/] Next: python main.py ml-train")


@app.command("ml-train")
def cmd_ml_train(
    rebuild: bool = typer.Option(False, "--rebuild", help="Rebuild the CVE feature table from raw data."),
):
    """🧠 Train the CVE exploitation model and write the model card."""
    from .ml import datasets
    from .ml.cve_model import build_cve_table, train_cve_model
    from .ml.model_card import write_model_card
    from .ml.paths import CVE_FEATURES_PATH, MODEL_CARD_MD

    if not datasets.kev_path().exists() or not datasets.available_nvd_years():
        console.print("[bold red]❌ No training data.[/] Run: python main.py ml-fetch-data")
        raise typer.Exit(code=1)

    df = None
    if rebuild or not CVE_FEATURES_PATH.exists():
        console.print("[bold cyan]Building CVE feature table...[/]")
        df = build_cve_table(log=_out)
    console.print("[bold cyan]Training CVE exploitation model...[/]")
    train_cve_model(df, log=_out)
    write_model_card()
    console.print(f"[bold green]✓ Models trained.[/] Model card: {MODEL_CARD_MD}")
    console.print("[dim]Use them with: python main.py --weights learned full-report -i <graph.json>[/]")


@app.command("ml-edges")
def cmd_ml_edges(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    kubectl: bool = typer.Option(False, "--kubectl", "-k", help="Ingest from live cluster."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export edge scores as JSON."),
):
    """📊 Show learned P(success) and weight for every edge next to its static weight."""
    from .ml.weights import get_learned_weights, models_available

    if not models_available():
        console.print("[bold red]❌ No trained models.[/] Run: python main.py ml-train")
        raise typer.Exit(code=1)
    if kubectl:
        cluster = ingest_from_kubectl()
    elif input_file:
        cluster = ingest_from_json(input_file)
    else:
        console.print("[bold red]❌ Error:[/] You must provide --input or --kubectl.")
        raise typer.Exit(code=1)

    scorer = get_learned_weights()
    nodes = {n.id: n for n in cluster.nodes}
    rows = []
    for e in cluster.edges:
        if e.source not in nodes or e.target not in nodes:
            continue
        s, t = nodes[e.source], nodes[e.target]
        sc = scorer.score_edge(s.type, e.relationship, t.type, e.cve, e.cvss, t.cves)
        rows.append({"source": s.name, "target": t.name, "relationship": e.relationship,
                     "static_weight": e.weight, **sc})
    rows.sort(key=lambda r: r["weight"])

    _out("=" * 108)
    _out("  LEARNED EDGE WEIGHTS  (weight = -ln P(success); lower = easier for an attacker)")
    _out("=" * 108)
    _out(f"  {'Edge':<46}{'Category':<23}{'P(succ)':>8}{'Learned':>9}{'Static':>8}  Exploit evidence")
    _out("  " + "-" * 106)
    for r in rows:
        edge = f"{r['source']} ─[{r['relationship']}]→ {r['target']}"
        ev = f"{r['exploit_cve']} p={r['p_exploit']:.3f} ({r['exploit_evidence']})" if r["exploit_cve"] or r["p_exploit"] else ""
        _out(f"  {edge[:45]:<46}{r['category']:<23}{r['p_success']:>8.3f}{r['weight']:>9.2f}{r['static_weight']:>8.1f}  {ev}")
    _out("=" * 108)

    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        console.print(f"[bold green]✓ Edge scores exported:[/] {output_json}")


@app.command("ml-info")
def cmd_ml_info():
    """ℹ️  Show the trained models' provenance and evaluation metrics."""
    from .ml.paths import MODEL_CARD_JSON, MODEL_CARD_MD

    if not MODEL_CARD_JSON.exists():
        console.print("[bold yellow]⚠ No model card yet.[/] Run: python main.py ml-train")
        raise typer.Exit(code=1)
    _out(MODEL_CARD_MD.read_text(encoding="utf-8"))


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
    weights: str = typer.Option(
        "static", "--weights", "-w", envvar="KAV_WEIGHTS",
        help="Edge weights: 'static' (from the input file) or 'learned' (ML: -ln P(success)).",
    ),
    online_cve: bool = typer.Option(
        False, "--online-cve", envvar="KAV_ONLINE_CVE",
        help="Learned weights: fetch unknown CVEs' NVD records online (cached).",
    ),
):
    """🛡️  KubeAttackViz v2.0 — Kubernetes Attack Path Visualizer

    Analyze Kubernetes cluster attack surfaces using graph algorithms.
    Supports BFS blast radius, Dijkstra shortest paths, DFS cycle detection,
    critical node analysis, RBAC auditing, temporal diff, NLP explanations,
    and D3.js visualization export.
    """
    weights = weights.lower()
    if weights not in ("static", "learned"):
        console.print(f"[bold red]❌ --weights must be 'static' or 'learned', got '{weights}'.[/]")
        raise typer.Exit(code=1)
    if weights == "learned":
        from .ml.weights import get_learned_weights, models_available
        if not models_available():
            console.print("[bold red]❌ Learned weights need trained models.[/] "
                          "Run: python main.py ml-fetch-data && python main.py ml-train")
            raise typer.Exit(code=1)
        get_learned_weights(allow_network=online_cve)
    set_default_weight_mode(weights)
