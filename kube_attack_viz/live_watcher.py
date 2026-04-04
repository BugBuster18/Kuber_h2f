"""
Live kubectl Watcher for KubeAttackViz.

Polls a live Kubernetes cluster via kubectl at a configurable interval,
detects changes by diffing against the last-known graph, and automatically
saves snapshots when changes are detected.
"""

from __future__ import annotations

import threading
import time
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .ingestion import ingest_from_kubectl
from .graph_builder import build_attack_graph, graph_summary
from .models import ClusterGraph


console = Console()


class LiveWatcher:
    """Polls a Kubernetes cluster and detects graph changes.

    Usage:
        watcher = LiveWatcher(interval=30)
        watcher.start()
        # ... runs in background ...
        watcher.stop()
    """

    def __init__(
        self,
        interval: int = 30,
        snapshots_dir: str | Path = "snapshots",
        neo4j_store=None,
        on_change: Optional[Callable] = None,
    ):
        """Initialize the live watcher.

        Args:
            interval: Polling interval in seconds.
            snapshots_dir: Directory to save snapshots.
            neo4j_store: Optional Neo4jStore instance for Neo4j persistence.
            on_change: Optional callback invoked when changes are detected.
                       Receives (old_graph, new_graph, diff_summary) args.
        """
        self.interval = interval
        self.snapshots_dir = Path(snapshots_dir)
        self.neo4j_store = neo4j_store
        self._on_change = on_change
        self._timer: Optional[threading.Timer] = None
        self._running = False
        self._last_graph: Optional[ClusterGraph] = None
        self._poll_count = 0
        self._change_count = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the polling loop."""
        if self._running:
            console.print("[yellow]⚠ Watcher is already running.[/]")
            return

        self._running = True
        console.print(
            Panel(
                f"[bold green]🔍 Live Watcher Started[/]\n"
                f"Polling interval: {self.interval}s\n"
                f"Snapshots dir: {self.snapshots_dir}\n"
                f"Neo4j: {'Connected' if self.neo4j_store else 'Disabled'}",
                title="KubeAttackViz Live Watcher",
                border_style="green",
            )
        )
        self._schedule_poll()

    def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
        console.print(
            f"\n[bold red]⏹ Watcher stopped.[/] "
            f"Polls: {self._poll_count}, Changes detected: {self._change_count}"
        )

    def _schedule_poll(self) -> None:
        """Schedule the next poll."""
        if not self._running:
            return
        self._timer = threading.Timer(self.interval, self._poll_loop)
        self._timer.daemon = True
        self._timer.start()

    def _poll_loop(self) -> None:
        """Execute a poll and schedule the next one."""
        try:
            self.poll_once()
        except Exception as e:
            console.print(f"[bold red]❌ Poll error:[/] {e}")
        finally:
            self._schedule_poll()

    def poll_once(self) -> dict:
        """Execute a single poll cycle.

        Returns:
            Dict with poll results including whether changes were detected.
        """
        with self._lock:
            self._poll_count += 1
            ts = datetime.now(timezone.utc)
            ts_str = ts.strftime("%H:%M:%S")

            console.print(
                f"[dim]🔄 [{ts_str}] Poll #{self._poll_count}... [/]", end=""
            )

            try:
                new_graph = ingest_from_kubectl()
            except RuntimeError as e:
                console.print(f"[red]FAILED: {e}[/]")
                return {"success": False, "error": str(e)}

            new_G = build_attack_graph(new_graph)
            new_summary = graph_summary(new_G)

            result = {
                "success": True,
                "poll_number": self._poll_count,
                "timestamp": ts.isoformat(),
                "node_count": new_summary["total_nodes"],
                "edge_count": new_summary["total_edges"],
                "changes_detected": False,
            }

            if self._last_graph is None:
                # First poll — save as baseline
                console.print(
                    f"[green]BASELINE — "
                    f"{new_summary['total_nodes']} nodes, "
                    f"{new_summary['total_edges']} edges[/]"
                )
                self._save_snapshot(new_graph, "baseline", ts.isoformat())
                self._last_graph = new_graph
                result["changes_detected"] = True
                result["change_type"] = "baseline"
                return result

            # ── Diff against last graph ──────────────────────────────────────
            diff = self._compute_diff(self._last_graph, new_graph)

            if diff["total_changes"] == 0:
                console.print("[dim]no changes[/]")
                return result

            # Changes detected!
            self._change_count += 1
            result["changes_detected"] = True
            result["diff"] = diff

            console.print(
                f"[bold yellow]⚡ CHANGES DETECTED[/] — "
                f"+{diff['nodes_added']} nodes, "
                f"-{diff['nodes_removed']} nodes, "
                f"+{diff['edges_added']} edges, "
                f"-{diff['edges_removed']} edges"
            )

            # Show details
            for node in diff.get("new_node_details", [])[:5]:
                console.print(f"  [green]+ {node['name']}[/] [{node['type']}]")
            for node in diff.get("removed_node_details", [])[:5]:
                console.print(f"  [red]- {node['name']}[/] [{node['type']}]")

            # Save snapshot
            label = f"change-{self._change_count}"
            self._save_snapshot(new_graph, label, ts.isoformat())

            # Invoke callback
            if self._on_change:
                try:
                    self._on_change(self._last_graph, new_graph, diff)
                except Exception as e:
                    console.print(f"[red]Callback error: {e}[/]")

            self._last_graph = new_graph
            return result

    def _compute_diff(
        self, old_graph: ClusterGraph, new_graph: ClusterGraph
    ) -> dict:
        """Compute a lightweight diff between two graphs."""
        old_G = build_attack_graph(old_graph)
        new_G = build_attack_graph(new_graph)

        old_nodes = set(old_G.nodes)
        new_nodes = set(new_G.nodes)

        old_edges = {
            (u, v, d.get("relationship", ""))
            for u, v, d in old_G.edges(data=True)
        }
        new_edges = {
            (u, v, d.get("relationship", ""))
            for u, v, d in new_G.edges(data=True)
        }

        added_nodes = new_nodes - old_nodes
        removed_nodes = old_nodes - new_nodes
        added_edges = new_edges - old_edges
        removed_edges = old_edges - new_edges

        new_node_details = []
        for nid in added_nodes:
            data = new_G.nodes[nid]
            new_node_details.append({
                "id": nid,
                "name": data.get("name", nid),
                "type": data.get("type", "unknown"),
            })

        removed_node_details = []
        for nid in removed_nodes:
            data = old_G.nodes[nid]
            removed_node_details.append({
                "id": nid,
                "name": data.get("name", nid),
                "type": data.get("type", "unknown"),
            })

        return {
            "nodes_added": len(added_nodes),
            "nodes_removed": len(removed_nodes),
            "edges_added": len(added_edges),
            "edges_removed": len(removed_edges),
            "total_changes": (
                len(added_nodes) + len(removed_nodes)
                + len(added_edges) + len(removed_edges)
            ),
            "new_node_details": new_node_details,
            "removed_node_details": removed_node_details,
        }

    def _save_snapshot(
        self, graph: ClusterGraph, label: str, timestamp: str
    ) -> None:
        """Save a snapshot to both disk and Neo4j (if available)."""
        from .snapshot_manager import save_snapshot

        filepath = save_snapshot(
            graph,
            label=label,
            snapshots_dir=self.snapshots_dir,
            source="kubectl-watcher",
            timestamp=timestamp,
        )
        console.print(f"  [dim]📸 Snapshot saved: {filepath}[/]")

        if self.neo4j_store:
            try:
                self.neo4j_store.store_snapshot(graph, label=label, timestamp=timestamp)
                console.print(f"  [dim]🗄️  Snapshot synced to Neo4j[/]")
            except Exception as e:
                console.print(f"  [red]Neo4j snapshot error: {e}[/]")


def run_watcher_blocking(
    interval: int = 30,
    snapshots_dir: str = "snapshots",
    neo4j_uri: Optional[str] = None,
    neo4j_user: Optional[str] = None,
    neo4j_password: Optional[str] = None,
) -> None:
    """Run the watcher in blocking mode (for CLI use).

    Args:
        interval: Polling interval in seconds.
        snapshots_dir: Snapshot directory.
        neo4j_uri: Optional Neo4j URI.
        neo4j_user: Optional Neo4j user.
        neo4j_password: Optional Neo4j password.
    """
    neo4j_store = None
    if neo4j_password:
        try:
            from .neo4j_store import Neo4jStore
            neo4j_store = Neo4jStore(
                uri=neo4j_uri, user=neo4j_user, password=neo4j_password
            )
            neo4j_store.connect()
            console.print("[green]✓ Connected to Neo4j[/]")
        except Exception as e:
            console.print(f"[yellow]⚠ Neo4j unavailable: {e}. Continuing without Neo4j.[/]")
            neo4j_store = None

    watcher = LiveWatcher(
        interval=interval,
        snapshots_dir=snapshots_dir,
        neo4j_store=neo4j_store,
    )

    # Do first poll immediately
    watcher._last_graph = None
    try:
        watcher.poll_once()
    except Exception as e:
        console.print(f"[red]Initial poll failed: {e}[/]")

    watcher.start()

    try:
        console.print("\n[dim]Press Ctrl+C to stop watching...[/]\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        watcher.stop()
        if neo4j_store:
            neo4j_store.close()
