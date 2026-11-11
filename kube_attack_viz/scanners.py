"""
Container image vulnerability scanning with Trivy.

Each distinct image is scanned once (`trivy image --scanners vuln`) and the
result cached in data/trivy/ for CACHE_TTL. The CVEs found on a pod's images
are ranked by the learned exploitation probability (CISA KEV entries first,
then the CVE model) and the top TOP_N are attached to the pod — these feed
the `cve-model` edge weights in learned mode.

Limitation (Trivy's, documented): it matches OS / language packages. A
binary compiled from source inside an image (e.g. httpd in the official
httpd image) is not identified, so its CVEs are not reported.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .ml.paths import DATA_DIR
from .models import ClusterGraph

TRIVY_DIR = DATA_DIR / "trivy"
CACHE_TTL = 24 * 3600
TOP_N = 10

_lock = threading.Lock()   # trivy serializes on its DB; one scan at a time


def trivy_available() -> bool:
    return shutil.which("trivy") is not None


def _cache_path(image: str) -> Path:
    safe = image.replace("/", "_").replace(":", "_").replace("@", "_")
    return TRIVY_DIR / f"{safe}.json"


def scan_image(image: str, log: Callable[[str], None] | None = None) -> list[dict[str, Any]]:
    """Vulnerabilities for one image: [{id, severity, cvss, pkg, installed, fixed}]."""
    path = _cache_path(image)
    if path.exists() and time.time() - path.stat().st_mtime < CACHE_TTL:
        return json.loads(path.read_text(encoding="utf-8"))["vulns"]

    with _lock:
        if path.exists() and time.time() - path.stat().st_mtime < CACHE_TTL:
            return json.loads(path.read_text(encoding="utf-8"))["vulns"]
        if log:
            log(f"  trivy: scanning {image} …")
        r = subprocess.run(
            ["trivy", "image", "--quiet", "--format", "json", "--scanners", "vuln", image],
            capture_output=True, text=True, timeout=900,
        )
        if r.returncode != 0:
            if log:
                log(f"  trivy: {image} failed: {r.stderr.strip()[:200]}")
            return []
        report = json.loads(r.stdout or "{}")
        vulns, seen = [], set()
        for res in report.get("Results") or []:
            for v in res.get("Vulnerabilities") or []:
                vid = v.get("VulnerabilityID", "")
                if not vid.startswith("CVE-") or vid in seen:
                    continue
                seen.add(vid)
                cvss = None
                for source in ("nvd", "redhat", "ghsa"):
                    s = (v.get("CVSS") or {}).get(source) or {}
                    if s.get("V3Score") is not None:
                        cvss = float(s["V3Score"])
                        break
                vulns.append({"id": vid, "severity": v.get("Severity"), "cvss": cvss,
                              "pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                              "fixed": v.get("FixedVersion")})
        TRIVY_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"image": image, "scanned_at": time.time(),
                                    "trivy": report.get("Trivy", {}), "vulns": vulns}), encoding="utf-8")
        return vulns


def attach_image_cves(cluster: ClusterGraph, top_n: int = TOP_N,
                      log: Callable[[str], None] | None = None) -> int:
    """Scan every pod's images and attach the highest-risk CVEs to the pod.

    Returns the number of pods that received CVEs.
    """
    if not trivy_available():
        if log:
            log("[WARN] trivy not found on PATH — image CVEs not scanned")
        return 0

    predictor = None
    try:
        from .ml.weights import models_available
        if models_available():
            from .ml.cve_model import CVEExploitPredictor
            predictor = CVEExploitPredictor(allow_network=False)
    except Exception:
        predictor = None

    enriched = 0
    for node in cluster.nodes:
        if node.type != "pod":
            continue
        images = node.properties.get("images") or ([node.image] if node.image else [])
        vulns: dict[str, dict] = {}
        for image in images:
            for v in scan_image(image, log=log):
                vulns.setdefault(v["id"], v)
        if not vulns:
            continue

        def rank(v):
            if predictor:
                p, _ = predictor.predict(v["id"], v["cvss"])
                return (p, v["cvss"] or 0.0)
            return (0.0, v["cvss"] or 0.0)

        ranked = sorted(vulns.values(), key=rank, reverse=True)
        node.cves = [v["id"] for v in ranked[:top_n]]
        severities: dict[str, int] = {}
        for v in vulns.values():
            severities[v["severity"] or "UNKNOWN"] = severities.get(v["severity"] or "UNKNOWN", 0) + 1
        node.properties["image_vulnerabilities"] = {
            "total": len(vulns), "by_severity": severities,
            "kev": sorted(v["id"] for v in vulns.values() if predictor and v["id"] in predictor.kev),
            "top": [{k: v[k] for k in ("id", "severity", "cvss", "pkg", "fixed")} for v in ranked[:top_n]],
        }
        enriched += 1
    return enriched
