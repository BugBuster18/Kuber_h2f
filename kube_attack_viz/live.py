"""
Live multi-cluster monitoring.

One ClusterMonitor thread per kubectl context repeatedly:
  scan (kubectl, context-pinned) → Trivy CVEs (cached per image) → snapshot
  → diff against the previous snapshot when the cluster changed (temporal
  engine, alerts) → attack graph with the active weights → publish.

LiveServer serves the visualizer and a small JSON API:
  GET /api/clusters                 status + headline numbers per cluster
  GET /api/graph?cluster=<ctx>      latest frontend payload (same schema as export-frontend)
  GET /api/history?cluster=<ctx>    temporal diffs, oldest first (Timeline view)
  GET /api/alerts?since=<seq>       alerts across clusters after a sequence number

Read-only towards the clusters: only get/list calls are made.
"""

from __future__ import annotations

import json
import threading
import time
import traceback
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from . import ingestion
from .frontend_export import build_frontend_payload
from .graph_builder import build_attack_graph
from .temporal import Snapshot, diff_snapshots

VISUALIZER_DIR = Path(__file__).resolve().parent.parent / "visualizer"
MAX_HISTORY = 200
EXPLAIN_TOP = 3

_BASIS_LABEL = {
    "exact-config": "config fact",
    "cve-model": "ML: CVE model",
    "scenario-param": "assumption",
    "legacy-prior": "legacy prior",
}


def scan_summary(raw: dict[str, Any], seconds: float) -> str:
    """One line describing what kubectl returned."""
    def n(key):
        return len((raw.get(key) or {}).get("items", []))
    parts = [f"{n('pods')} pods", f"{n('services')} svc", f"{n('serviceaccounts')} SAs",
             f"{n('roles') + n('clusterroles')} roles", f"{n('rolebindings') + n('clusterrolebindings')} bindings",
             f"{n('networkpolicies')} netpols", f"{n('secrets')} secrets (names only)"]
    errs = raw.get("_errors") or {}
    return (f"kubectl get ×{len(ingestion.KUBECTL_RESOURCES) + 1} → " + ", ".join(parts)
            + f" in {seconds:.1f}s" + (f"  ⚠ cannot list: {', '.join(errs)}" if errs else ""))


def explain_paths(G, paths: list[dict[str, Any]], top: int = EXPLAIN_TOP) -> list[str]:
    """Hop-by-hop explanation of why the top paths rank where they do."""
    lines = []
    learned = G.graph.get("weight_mode") == "learned"
    for rank, p in enumerate(paths[:top], 1):
        prob = p.get("success_probability")
        head = f"  ▶ #{rank} {p['severity']:<8} risk {p['total_risk']:.2f}/10"
        head += f"  P(path)={prob * 100:.1f}%" if prob is not None else f"  cost={p['total_cost']:.2f}"
        lines.append(head + "   " + " → ".join(p["path_names"]))
        weakest = None
        nodes = p["path_nodes"]
        for i in range(len(nodes) - 1):
            e = G.edges[nodes[i], nodes[i + 1]]
            src, dst = G.nodes[nodes[i]].get("name"), G.nodes[nodes[i + 1]].get("name")
            hop = f"{src} ─[{e.get('relationship')}]→ {dst}"
            if learned:
                ps = e.get("p_success", 1.0)
                basis = _BASIS_LABEL.get(e.get("weight_basis"), e.get("weight_basis") or "?")
                ev = ""
                if e.get("exploit_cve") and e.get("weight_basis") == "cve-model":
                    ev = f"  {e['exploit_cve']} p_exploit={e['p_exploit']:.3f} ({e.get('exploit_evidence')})"
                elif e.get("evidence"):
                    ev = f"  ({e['evidence'][:60]})"
                lines.append(f"      {i + 1}. {hop[:58]:<58} P={ps:.3f}  w={e['weight']:.2f}  {basis:<13}{ev}")
                if weakest is None or ps < weakest[1]:
                    weakest = (i + 1, ps, basis)
            else:
                lines.append(f"      {i + 1}. {hop[:58]:<58} w={e['weight']:.2f}")
        if learned and weakest:
            lines.append(f"      ↳ weakest link: hop {weakest[0]} (P={weakest[1]:.3f}, {weakest[2]}) — "
                         f"the path's uncertainty lives there")
    return lines


class ClusterMonitor(threading.Thread):
    def __init__(self, context: str, interval: float, scan_images: bool,
                 alert_sink: Callable[[str, dict], None], log: Callable[[str], None]):
        super().__init__(daemon=True, name=f"monitor-{context}")
        self.context = context
        self.interval = interval
        self.scan_images = scan_images
        self.alert_sink = alert_sink
        self.log = log
        self.lock = threading.Lock()
        self.payload: dict[str, Any] | None = None
        self.history: list[dict[str, Any]] = []
        self.last_snapshot: Snapshot | None = None
        self.version = 0
        self.scans = 0
        self.status = "starting"
        self.error: str | None = None
        self.last_scan_at: str | None = None
        self.scan_seconds: float | None = None
        self._stop = threading.Event()

    # ── one scan ──────────────────────────────────────────────────────────
    def scan_once(self) -> None:
        t0 = time.time()
        raw = ingestion.fetch_raw_state(context=self.context)
        self.log(f"[{self.context}] scan #{self.scans + 1}  " + scan_summary(raw, time.time() - t0))
        cluster = ingestion.cluster_from_raw(raw)
        if self.scan_images:
            from .scanners import attach_image_cves
            attach_image_cves(cluster, log=self.log)

        snap = Snapshot.from_cluster(cluster, source=f"kubectl:{self.context}")
        changed = self.last_snapshot is None or snap.graph_hash != self.last_snapshot.graph_hash
        diff_dict = None
        if self.last_snapshot is not None and changed:
            diff = diff_snapshots(self.last_snapshot, snap)
            diff_dict = diff.to_dict()
            diff_dict["cluster"] = self.context
            for alert in diff_dict.get("alerts", []):
                self.alert_sink(self.context, alert)

        if changed:
            G = build_attack_graph(cluster)
            payload = build_frontend_payload(G)
            payload["metadata"].update({"cluster": self.context, "graph_hash": snap.graph_hash,
                                        "scan_errors": raw.get("_errors", {})})
        with self.lock:
            self.scans += 1
            self.last_scan_at = datetime.now(timezone.utc).isoformat()
            self.scan_seconds = round(time.time() - t0, 2)
            if changed:
                self.version += 1
                payload["metadata"]["version"] = self.version
                payload["metadata"]["scanned_at"] = self.last_scan_at
                self.payload = payload
                self.last_snapshot = snap
                if diff_dict:
                    self.history.append(diff_dict)
                    del self.history[:-MAX_HISTORY]
            elif self.payload is not None:
                self.payload["metadata"]["scanned_at"] = self.last_scan_at
            self.status, self.error = "ok", None
        if changed:
            self.log(f"[{self.context}] ● graph v{self.version}: {len(payload['nodes'])} nodes, "
                     f"{len(payload['edges'])} edges, {len(payload['attack_paths'])} attack paths, "
                     f"weights={G.graph.get('weight_mode')}"
                     + (f", {len(diff_dict['alerts'])} alert(s)" if diff_dict else "")
                     + f"  ({self.scan_seconds}s)")
            for line in explain_paths(G, payload["attack_paths"]):
                self.log(f"[{self.context}] {line}")
        else:
            self.log(f"[{self.context}] no change (graph v{self.version})")

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception as e:
                with self.lock:
                    self.status, self.error = "error", f"{type(e).__name__}: {e}"
                self.log(f"[{self.context}] scan failed: {e}")
                traceback.print_exc()
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()

    def summary(self) -> dict[str, Any]:
        with self.lock:
            p = self.payload or {}
            paths = p.get("attack_paths", [])
            sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            worst = next((s for s in sev_order if any(x["severity"] == s for x in paths)), None)
            return {
                "context": self.context, "name": self.context.removeprefix("kind-"),
                "status": self.status, "error": self.error, "version": self.version,
                "scans": self.scans, "last_scan_at": self.last_scan_at, "scan_seconds": self.scan_seconds,
                "nodes": len(p.get("nodes", [])), "edges": len(p.get("edges", [])),
                "attack_paths": len(paths), "worst_severity": worst,
                "diffs": len(self.history),
                "alerts": sum(len(d.get("alerts", [])) for d in self.history),
                "weight_mode": (p.get("metadata") or {}).get("weight_mode"),
            }


class LiveServer:
    def __init__(self, contexts: list[str], interval: float = 15.0, scan_images: bool = True,
                 log: Callable[[str], None] = print):
        self.log = log
        self.alerts: list[dict[str, Any]] = []
        self.alerts_lock = threading.Lock()
        self.monitors = {c: ClusterMonitor(c, interval, scan_images, self._on_alert, log) for c in contexts}

    def _on_alert(self, context: str, alert: dict) -> None:
        with self.alerts_lock:
            self.alerts.append({"seq": len(self.alerts) + 1, "cluster": context, **alert})
        self.log(f"🚨 [{context}] [{alert.get('severity')}] {alert.get('title')}")

    def handler(self):
        server = self

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=str(VISUALIZER_DIR), **kw)

            def log_message(self, *args):        # keep the terminal for scan output
                pass

            def _json(self, obj, status=200):
                body = json.dumps(obj, default=str).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                url = urlparse(self.path)
                q = parse_qs(url.query)
                if not url.path.startswith("/api/"):
                    return super().do_GET()
                mon = server.monitors.get((q.get("cluster") or [""])[0])
                if url.path == "/api/clusters":
                    return self._json({"live": True, "clusters": [m.summary() for m in server.monitors.values()]})
                if url.path == "/api/graph":
                    if not mon:
                        return self._json({"error": "unknown cluster"}, 404)
                    with mon.lock:
                        if mon.payload is None:
                            return self._json({"error": "first scan not finished", "status": mon.status}, 503)
                        return self._json(mon.payload)
                if url.path == "/api/history":
                    if not mon:
                        return self._json({"error": "unknown cluster"}, 404)
                    with mon.lock:
                        return self._json(list(mon.history))
                if url.path == "/api/alerts":
                    since = int((q.get("since") or ["0"])[0])
                    with server.alerts_lock:
                        return self._json([a for a in server.alerts if a["seq"] > since])
                return self._json({"error": "not found"}, 404)

        return Handler

    def serve(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        for m in self.monitors.values():
            m.start()
        httpd = ThreadingHTTPServer((host, port), self.handler())
        self.log(f"● Live dashboard: http://{host}:{port}/   (Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            for m in self.monitors.values():
                m.stop()
            httpd.server_close()
