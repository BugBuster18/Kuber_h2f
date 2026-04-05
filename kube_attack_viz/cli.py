"""
CLI Interface for KubeAttackViz v2.0.

Production-grade command-line interface using Typer with all analysis
operations including temporal diff, RBAC analysis, classification,
NLP explanations, built-in tests, and frontend export.

All data ingestion is JSON-based — provide a cluster graph JSON file
via --input / -i.
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
from .ingestion import (
    ingest_from_json,
    export_graph_to_json,
    enrich_cluster_graph,
)
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


def _load_graph(
    input_file: str | None,
    use_cvss: bool = True,
    enrich: Optional[bool] = None,
) -> tuple:
    """Load and build the attack graph from a JSON file.

    Args:
        input_file: Path to a cluster graph JSON file (required).
        use_cvss: Whether to apply CVSS weight adjustments.
        enrich: Whether to enrich CVEs from NVD (default: False).
    """
    if enrich is None:
        enrich = False

    if not input_file:
        console.print("[bold red]❌ Error:[/] You must provide --input / -i with a JSON file.")
        raise typer.Exit(code=1)

    with console.status(f"[bold cyan]Ingesting graph from {input_file}..."):
        cluster = ingest_from_json(input_file)

    if enrich:
        count = enrich_cluster_graph(cluster)
        if count > 0:
            console.print(f"[bold cyan]ℹ Live Enrichment:[/] Updated {count} CVE(s) from NVD.")

    G = build_attack_graph(cluster, use_cvss_weights=use_cvss)

    summary = graph_summary(G)
    msg = f"Graph loaded: {summary['total_nodes']} nodes, {summary['total_edges']} edges"
    if not use_cvss:
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
            console.print(f"  • {data.get('name', nid)} ({nid})")
        raise typer.Exit(code=1)
    return node_id


# ─── Core Commands ────────────────────────────────────────────────────────────


@app.command("blast-radius")
def cmd_blast_radius(
    source: str = typer.Option(..., "--source", "-s", help="Source node ID or name."),
    depth: int = typer.Option(3, "--depth", "-d", help="Maximum BFS depth."),
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export results as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the report as a text file."),
):
    """🔥 Compute blast radius from a source node using BFS."""
    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)
    source_id = _resolve_or_exit(G, source, "Source node")

    result = blast_radius(G, source_id, max_depth=depth)
    report = format_blast_radius(G, result)
    console.print(report)

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
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export path as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the path report as a text file."),
):
    """🎯 Find the shortest (minimum-weight) attack path using Dijkstra."""
    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)
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
    console.print(path_report)

    # NLP Explanation
    from .nlp_explainer import explain_path
    nlp_text = "\n  📝 Natural Language Explanation:\n" + "  " + explain_path(G, path).replace("\n", "\n  ")
    console.print(nlp_text)

    # Remediation
    fixes = generate_path_remediation(G, path)
    rem_text = "\n  Remediation:\n"
    for fix in fixes:
        rem_text += f"    {fix}\n"
    console.print(rem_text)
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
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export results as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the cycle report as a text file."),
):
    """🔄 Detect all privilege escalation cycles using DFS."""
    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)

    result = detect_cycles(G)
    report = format_cycles(G, result)
    console.print(report)

    # Remediation
    rem_msg = ""
    fixes = generate_cycle_remediation(G, result)
    if fixes:
        rem_msg = "\n  Cycle Remediation:\n"
        for fix in fixes:
            rem_msg += f"    {fix}\n"
        rem_msg += "=" * 70 + "\n"
        console.print(rem_msg)

    _save_report(report + rem_msg, output)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("critical-node")
def cmd_critical_node(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    top_n: int = typer.Option(5, "--top", "-n", help="Number of top critical nodes."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export results as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the critical node report as a text file."),
):
    """🧪 Identify critical chokepoint nodes via graph surgery."""
    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)

    result = critical_node_analysis(G, top_n=top_n)
    report = format_critical_nodes(G, result)
    console.print(report)

    # Explanation
    from .nlp_explainer import explain_critical_node
    nlp_text = "\n  📝 Explanation:\n" + "  " + explain_critical_node(G, result).replace("\n", "\n  ") + "\n"
    console.print(nlp_text)

    # Remediation
    rem_text = ""
    fixes = generate_critical_node_remediation(G, result)
    if fixes:
        rem_text = "\n  Critical Node Remediation:\n"
        for fix in fixes:
            rem_text += f"    {fix}\n"
        rem_text += "=" * 70 + "\n"
        console.print(rem_text)

    _save_report(report + nlp_text + rem_text, output)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[bold green]✓ JSON exported:[/] {output_json}")


@app.command("full-report")
def cmd_full_report(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    blast_source: Optional[str] = typer.Option(None, "--blast-source", help="Specific source for blast radius."),
    blast_depth: int = typer.Option(3, "--blast-depth", help="Max BFS depth for blast radius."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export full JSON report."),
    output: str = typer.Option("report.txt", "--output", "-o", help="Save the human-readable report as a text file."),
):
    """📋 Generate comprehensive Kill Chain Report with all analyses."""
    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)

    # Resolve blast source if provided
    blast_id = None
    if blast_source:
        blast_id = _resolve_or_exit(G, blast_source, "Blast radius source")

    report = generate_full_report(G, blast_source=blast_id, blast_depth=blast_depth)
    console.print(report)

    _save_report(report, output)

    if output_json:
        export_report_json(G, output_json, blast_source=blast_id, blast_depth=blast_depth)
        console.print(f"[bold green]✓ JSON report exported:[/] {output_json}")


@app.command("graph-info")
def cmd_graph_info(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
):
    """ℹ️  Display graph structure summary and node listing."""
    G, _ = _load_graph(input_file)
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
    enrich: bool = typer.Option(True, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD before exporting."),
    output: str = typer.Option("cluster-graph.json", "--output", "-o", help="Output JSON file path."),
):
    """💾 Export cluster graph to JSON file."""
    _, cluster = _load_graph(input_file, enrich=enrich)
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
    console.print(format_temporal_diff(diff))

    # Show alert summary
    if diff.alerts:
        console.print(format_alert_summary(diff.alerts))

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
    source: str = typer.Option(..., "--source", "-s", help="Scan source: 'json:<path>' (e.g. json:cluster-graph.json)."),
    persist_dir: str = typer.Option(".temporal_snapshots", "--persist-dir", "-d", help="Directory for snapshot persistence."),
    max_snapshots: int = typer.Option(100, "--max-snapshots", help="Maximum snapshots to retain."),
    neo4j_uri: Optional[str] = typer.Option(None, "--neo4j-uri", help="Neo4j bolt URI for auto-export on changes."),
    neo4j_user: str = typer.Option("neo4j", "--neo4j-user", help="Neo4j username."),
    neo4j_password: str = typer.Option("password", "--neo4j-pass", help="Neo4j password."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Save diff history to JSON on exit."),
    single: bool = typer.Option(False, "--single", help="Run a single scan cycle then exit."),
):
    """👁️  Continuous temporal monitoring — periodic scan, diff, and alert.

    Continuously reads a JSON cluster graph file at the specified interval,
    compares consecutive snapshots, and generates alerts when new attack
    paths appear. Optionally exports changed graphs to Neo4j automatically.

    Examples:
        # Watch a JSON file (re-read periodically) with Neo4j export
        kube-attack-viz watch -n 60 -s json:cluster-graph.json --neo4j-uri bolt://localhost:7687

        # Single scan (for CI/CD pipelines)
        kube-attack-viz watch --single -s json:cluster-graph.json
    """
    from .temporal import (
        TemporalWatcher, format_temporal_diff, format_alert_summary,
        format_snapshot_history, TemporalDiff, TemporalAlert,
    )

    # Validate source format
    if not source.startswith("json:"):
        console.print("[bold red]❌ Error:[/] Source must be in format 'json:<path>' (e.g. json:cluster-graph.json).")
        raise typer.Exit(code=1)

    scan_count = 0
    alert_count = 0

    def on_diff(diff: TemporalDiff):
        nonlocal scan_count
        scan_count += 1
        if diff.has_changes:
            console.print(f"\n[bold yellow]⚡ Change detected (scan #{scan_count}):[/]")
            console.print(format_temporal_diff(diff))
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
        console.print(f"  [{color}]🚨 [{alert.severity}] {alert.title}[/]")

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

        console.print(format_snapshot_history(watcher.store))

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
    console.print(format_snapshot_history(watcher.store))

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

    console.print(format_snapshot_history(store))

    if diff_all:
        pairs = store.get_consecutive_pairs()
        if not pairs:
            console.print("[dim]  Need at least 2 snapshots for diff.[/]")
            return

        all_diffs = []
        for i, (old, new) in enumerate(pairs, 1):
            console.print(f"\n[bold blue]─── Diff #{i}: {old.timestamp} → {new.timestamp} ───[/]")
            diff = diff_snapshots(old, new)
            console.print(format_temporal_diff(diff))
            if diff.alerts:
                console.print(format_alert_summary(diff.alerts))
            all_diffs.append(diff)

        if output_json:
            history = [d.to_dict() for d in all_diffs]
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2, default=str)
            console.print(f"[bold green]✓ Full diff history exported:[/] {output_json}")


@app.command("temporal-snapshot")
def cmd_temporal_snapshot(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
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
    """
    from .temporal import (
        Snapshot, SnapshotStore, diff_snapshots,
        format_temporal_diff, format_alert_summary,
        format_snapshot_history, Neo4jExporter,
    )

    store = SnapshotStore(persist_dir=persist_dir)

    if not input_file:
        console.print("[bold red]❌ Error:[/] You must provide --input / -i with a JSON file.")
        raise typer.Exit(code=1)

    cluster = ingest_from_json(input_file)
    source = f"json:{input_file}"

    new_snap = Snapshot.from_cluster(cluster, source=source)
    old_snap = store.latest

    # Quick hash check
    if old_snap and old_snap.graph_hash == new_snap.graph_hash:
        console.print("[bold green]✓ Snapshot captured (identical to previous).[/]")
        store.add(new_snap)
        console.print(format_snapshot_history(store))
        return

    store.add(new_snap)
    console.print(f"[bold green]✓ Snapshot captured:[/] {new_snap.snapshot_id}")
    console.print(f"  Hash: {new_snap.graph_hash}  Source: {source}")

    # Diff against previous
    if diff_previous and old_snap:
        diff = diff_snapshots(old_snap, new_snap)
        console.print(format_temporal_diff(diff))

        if diff.alerts:
            console.print(format_alert_summary(diff.alerts))

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

    console.print(format_snapshot_history(store))


@app.command("classify")
def cmd_classify(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the classification report as a text file."),
):
    """🏷️  Classify attack paths into categories with advanced scoring."""
    from .classifier import format_classified_paths

    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)
    paths = all_shortest_paths(G)
    report = format_classified_paths(G, paths)
    console.print(report)
    _save_report(report, output)


@app.command("rbac-audit")
def cmd_rbac_audit(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Export RBAC findings as JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the RBAC audit report as a text file."),
):
    """🔐 Analyze RBAC patterns for security risks."""
    from .rbac_analyzer import analyze_rbac, format_rbac_analysis

    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)
    result = analyze_rbac(G)
    report = format_rbac_analysis(result)
    console.print(report)
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
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
):
    """📝 Generate natural language explanation of an attack path."""
    from .nlp_explainer import explain_path

    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)
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
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    top_n: int = typer.Option(10, "--top", "-n", help="Number of top nodes to display."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save the node risk report as a text file."),
):
    """📈 Compute amplified node risk scores based on path centrality."""
    from .node_risk import compute_node_risk_amplification, format_node_risk

    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)
    entries = compute_node_risk_amplification(G, cutoff=15)
    report = format_node_risk(entries, top_n=top_n)
    console.print(report)
    _save_report(report, output)


@app.command("export-frontend")
def cmd_export_frontend(
    input_file: Optional[str] = typer.Option(None, "--input", "-i", help="Input JSON file."),
    use_cvss: bool = typer.Option(True, "--cvss-weights/--no-cvss-weights", help="Toggle CVSS weight adjustment."),
    enrich: Optional[bool] = typer.Option(None, "--enrich/--no-enrich", help="Fetch live CVSS scores from NVD."),
    output: str = typer.Option("visualizer/graph-data.json", "--output", "-o", help="Output JSON for frontend."),
):
    """🌐 Export graph data for the D3.js visualization frontend."""
    from .frontend_export import export_for_frontend

    G, _ = _load_graph(input_file, use_cvss=use_cvss, enrich=enrich)
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

    All ingestion is JSON-based — provide a cluster graph file via --input / -i.
    """
    pass
