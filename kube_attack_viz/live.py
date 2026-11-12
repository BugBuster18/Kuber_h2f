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

With --demo-sample (presentation views, see DemoViews):
  GET  /api/demo                    current view (1-4) + readiness of each view
  GET  /api/demo/graph?view=<n>     payload of a view (default: the current one)
  POST /api/demo/view?view=<n>      switch the view shown in every open dashboard
  GET  /api/benchmark               last benchmark result (Goat + Bad Pods answer key)

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
BENCHMARK_LATEST = Path(__file__).resolve().parent.parent / "data" / "benchmark" / "latest.json"
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
                 alert_sink: Callable[[str, dict], None], log: Callable[[str], None],
                 extra_modes: tuple[str, ...] = ()):
        super().__init__(daemon=True, name=f"monitor-{context}")
        self.context = context
        self.interval = interval
        self.scan_images = scan_images
        self.alert_sink = alert_sink
        self.log = log
        self.extra_modes = extra_modes     # also publish the graph under these weight modes (demo views)
        self.lock = threading.Lock()
        self.payload: dict[str, Any] | None = None
        self.payloads: dict[str, dict[str, Any]] = {}   # weight mode -> payload, same scan
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
            payloads = {G.graph.get("weight_mode"): payload}
            for mode in self.extra_modes:          # same scan, other weighting
                if mode not in payloads:
                    p = build_frontend_payload(build_attack_graph(cluster, weight_mode=mode))
                    p["metadata"].update({"cluster": self.context, "graph_hash": snap.graph_hash})
                    payloads[mode] = p
        with self.lock:
            self.scans += 1
            self.last_scan_at = datetime.now(timezone.utc).isoformat()
            self.scan_seconds = round(time.time() - t0, 2)
            if changed:
                self.version += 1
                for p in payloads.values():
                    p["metadata"]["version"] = self.version
                    p["metadata"]["scanned_at"] = self.last_scan_at
                self.payload = payload
                self.payloads = payloads
                self.last_snapshot = snap
                if diff_dict:
                    self.history.append(diff_dict)
                    del self.history[:-MAX_HISTORY]
            elif self.payload is not None:
                for p in self.payloads.values():
                    p["metadata"]["scanned_at"] = self.last_scan_at
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


class DemoViews:
    """The four presentation views: {sample, live} cluster x {static, learned} weights.

    The sample cluster's graphs are built once; the live views read the
    monitor of `live_context`, which publishes both weightings from each scan.
    The presenter switches views from the terminal (demo/views.sh → POST
    /api/demo/view) or from the buttons in the dashboard; the browser polls
    /api/demo and redraws.
    """

    VIEWS = (
        (1, "sample", "static", "Sample cluster", "Old weights (paper-style, hand-set)"),
        (2, "sample", "learned", "Sample cluster", "ML weights (−ln P)"),
        (3, "live", "static", "Live cluster", "Old weights (paper-style, hand-set)"),
        (4, "live", "learned", "Live cluster", "ML weights (−ln P)"),
    )

    def __init__(self, sample_file: str, live_context: str, monitors: dict[str, "ClusterMonitor"]):
        self.sample_file = sample_file
        self.live_context = live_context
        self.monitors = monitors
        self.sample: dict[str, dict[str, Any]] = {}
        cluster = ingestion.ingest_from_json(sample_file)
        for mode in ("static", "learned"):
            p = build_frontend_payload(build_attack_graph(cluster, weight_mode=mode))
            p["metadata"].update({"cluster": f"sample:{Path(sample_file).name}", "version": 1})
            self.sample[mode] = p
        self.view = 1
        self.seq = 1                 # bumps on every switch so the browser notices a re-select too
        self.lock = threading.Lock()

    def _row(self, vid: int) -> tuple:
        return next(v for v in self.VIEWS if v[0] == vid)

    def payload(self, vid: int) -> dict[str, Any] | None:
        _, src, mode, _, _ = self._row(vid)
        if src == "sample":
            return self.sample[mode]
        mon = self.monitors[self.live_context]
        with mon.lock:
            return mon.payloads.get(mode)

    def select(self, vid: int) -> None:
        self._row(vid)               # raises StopIteration on an unknown view
        with self.lock:
            self.view, self.seq = vid, self.seq + 1

    def state(self) -> dict[str, Any]:
        mon = self.monitors[self.live_context]
        live_name = self.live_context.removeprefix("kind-")
        views = []
        for vid, src, mode, cluster, weights in self.VIEWS:
            p = self.payload(vid)
            views.append({"id": vid, "source": src, "weights": mode, "cluster_label": cluster,
                          "weights_label": weights,
                          "cluster_name": live_name if src == "live" else Path(self.sample_file).name,
                          "ready": p is not None,
                          "version": (p or {}).get("metadata", {}).get("version"),
                          "paths": len((p or {}).get("attack_paths", []))})
        with self.lock:
            view, seq = self.view, self.seq
        return {"enabled": True, "view": view, "seq": seq, "views": views,
                "live": {"context": self.live_context, "status": mon.status, "scans": mon.scans,
                         "last_scan_at": mon.last_scan_at, "scan_seconds": mon.scan_seconds}}


class LiveServer:
    def __init__(self, contexts: list[str], interval: float = 15.0, scan_images: bool = True,
                 log: Callable[[str], None] = print, demo_sample: str | None = None,
                 demo_context: str | None = None):
        self.log = log
        self.alerts: list[dict[str, Any]] = []
        self.alerts_lock = threading.Lock()
        demo_context = demo_context or (contexts[0] if demo_sample else None)
        if demo_context and demo_context not in contexts:
            contexts = [*contexts, demo_context]
        self.monitors = {c: ClusterMonitor(c, interval, scan_images, self._on_alert, log,
                                           extra_modes=("static", "learned") if c == demo_context else ())
                         for c in contexts}
        self.demo = DemoViews(demo_sample, demo_context, self.monitors) if demo_sample else None

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
                if url.path == "/api/demo":
                    if not server.demo:
                        return self._json({"enabled": False})
                    return self._json(server.demo.state())
                if url.path == "/api/benchmark":
                    f = BENCHMARK_LATEST
                    if not f.is_file():
                        return self._json({"error": "no benchmark yet: python main.py benchmark"}, 404)
                    return self._json(json.loads(f.read_text()))
                if url.path == "/api/demo/graph":
                    if not server.demo:
                        return self._json({"error": "demo views off (serve --demo-sample)"}, 404)
                    try:
                        vid = int((q.get("view") or [server.demo.view])[0])
                        p = server.demo.payload(vid)
                    except (ValueError, StopIteration):
                        return self._json({"error": "unknown view"}, 404)
                    if p is None:
                        return self._json({"error": "first scan not finished"}, 503)
                    return self._json(p)
                return self._json({"error": "not found"}, 404)

            def do_POST(self):
                url = urlparse(self.path)
                q = parse_qs(url.query)
                if url.path == "/api/demo/view" and server.demo:
                    try:
                        server.demo.select(int((q.get("view") or [""])[0]))
                    except (ValueError, StopIteration):
                        return self._json({"error": "view must be 1-4"}, 400)
                    return self._json(server.demo.state())
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
