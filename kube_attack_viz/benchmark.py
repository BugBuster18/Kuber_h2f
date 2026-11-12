"""
Benchmark: compare our attack paths with paths documented by public projects.

Input   a live cluster running unmodified public manifests (Kubernetes Goat
        and Bad Pods, deployed by ./demo/setup.sh bench) and an answer key
        (demo/benchmark/expected.yaml) listing each documented attack with a
        link to where it is documented.
Output  for each documented attack, under the old (static) weights and the ML
        (learned) weights:
          * found     - does our graph contain the path?
          * rank      - where does it rank among ALL attack paths in the cluster?
                        (risk compared at 2 decimals; equal risks share a rank)
                        (entry points: the internet, users and every pod, since
                        Kubernetes Goat assumes any application can be compromised)
          * verdict   - for Bad Pods: does the weighting claim the pod can reach
                        its node, and is that what Bad Pods documents?

Nothing here is tuned to the answer key: the graph and both weightings are the
same code the rest of the tool uses.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import networkx as nx

from . import ingestion
from .algorithms.dijkstra import compute_path_risk, shortest_attack_path
from .graph_builder import build_attack_graph

MODES = ("static", "learned")
ESCAPE_P = 0.5          # ML weights claim an escape when P(pod -> node) is at least this
RANK_DECIMALS = 2       # risks are compared as displayed (2 decimals): equal risks share a rank


@dataclass
class ModeResult:
    found: bool = False
    path: list[str] = field(default_factory=list)
    risk: float | None = None
    probability: float | None = None      # learned only
    rank: int | None = None               # among all entry -> target paths (targets only)
    claims_escape: bool | None = None     # Bad Pods: direct pod -> node step
    escape_score: float | None = None     # Bad Pods: static risk of that step, or its learned P


@dataclass
class ItemResult:
    id: str
    group: str
    title: str
    doc: str
    documented: str
    expect: str
    source: str
    target: str
    modes: dict[str, ModeResult] = field(default_factory=dict)


def _load_expected(path: str | Path) -> list[dict[str, Any]]:
    import yaml
    data = yaml.safe_load(Path(path).read_text())
    items = []
    for group, block in data.items():
        for p in block.get("paths", []):
            items.append({**p, "group": group})
    return items


def _resolve(G: nx.DiGraph, ref: str, pod_nodes: dict[tuple[str, str], str]) -> str | None:
    """Map an answer-key endpoint to a graph node id (None if not in the graph)."""
    ref = ref.strip()
    if ref == "internet":
        nid = "externalactor:cluster/internet"
        return nid if nid in G else None
    kind, _, rest = ref.partition(" ")
    ns, _, name = rest.strip().partition("/")
    if kind == "pod":
        for n, d in G.nodes(data=True):
            if d.get("type") == "pod" and d.get("namespace") == ns and str(d.get("name", "")).startswith(name):
                return n
        return None
    if kind == "secret":
        nid = f"secret:{ns}/{name}"
        return nid if nid in G else None
    if kind == "node-of":
        node_name = next((v for (pns, pname), v in pod_nodes.items() if pns == ns and pname.startswith(name)), None)
        nid = f"node:cluster/{node_name}" if node_name else None
        return nid if nid and nid in G else None
    raise ValueError(f"unknown endpoint in answer key: {ref!r}")


def _all_paths(G: nx.DiGraph, mode: str) -> list[tuple[str, str, float]]:
    """Best path from every entry point to every target: (source, sink, risk)."""
    entries = [n for n, d in G.nodes(data=True)
               if d.get("is_source") or d.get("type") in ("pod", "user", "externalactor")]
    sinks = {n for n, d in G.nodes(data=True) if d.get("is_sink")}
    out = []
    for src in entries:
        dist = nx.single_source_dijkstra_path_length(G, src, weight="weight")
        for sink, cost in dist.items():
            if sink in sinks and sink != src:
                d = G.nodes[sink]
                impact = d.get("impact") if d.get("impact") is not None else d.get("risk_score")
                out.append((src, sink, compute_path_risk(impact, cost, mode)))
    return out


def run_benchmark(context: str, expected: str | Path, scan_images: bool = True,
                  log: Callable[[str], None] = print) -> dict[str, Any]:
    t0 = time.time()
    raw = ingestion.fetch_raw_state(context=context)
    cluster = ingestion.cluster_from_raw(raw)
    if scan_images:
        from .scanners import attach_image_cves
        attach_image_cves(cluster, log=log)
    pod_nodes = {(p["metadata"]["namespace"], p["metadata"]["name"]): p["spec"].get("nodeName")
                 for p in raw["pods"]["items"]}
    items = _load_expected(expected)

    # The answer key covers the full benchmark; a cluster may run a subset
    # (the live-demo set). Entries whose workloads are not deployed are
    # skipped, not counted as misses.
    def deployed(ref: str) -> bool:
        kind, _, rest = ref.strip().partition(" ")
        if kind not in ("pod", "node-of"):
            return True
        ns, _, prefix = rest.strip().partition("/")
        return any(pns == ns and pname.startswith(prefix) for pns, pname in pod_nodes)
    skipped = [i["id"] for i in items if not (deployed(i["from"]) and deployed(i["to"]))]
    items = [i for i in items if i["id"] not in skipped]
    results = [ItemResult(id=i["id"], group=i["group"], title=i["title"], doc=i["doc"],
                          documented=i["documented"], expect=i["expect"], source=i["from"], target=i["to"])
               for i in items]
    totals: dict[str, int] = {}

    for mode in MODES:
        G = build_attack_graph(cluster, weight_mode=mode)
        ranked = sorted((round(r, RANK_DECIMALS) for _, _, r in _all_paths(G, mode)), reverse=True)
        totals[mode] = len(ranked)
        for res in results:
            m = ModeResult()
            res.modes[mode] = m
            src = _resolve(G, res.source, pod_nodes)
            tgt = _resolve(G, res.target, pod_nodes)
            if src is None or tgt is None:
                if res.group == "bad_pods":
                    m.claims_escape, m.escape_score = False, 0.0
                continue
            p = shortest_attack_path(G, src, tgt)
            if p is not None:
                m.found = True
                m.path = p.path_names
                m.risk = round(p.total_risk, 3)
                m.probability = None if p.success_probability is None else round(p.success_probability, 4)
                if G.nodes[tgt].get("is_sink"):
                    mine = round(p.total_risk, RANK_DECIMALS)
                    m.rank = 1 + sum(1 for r in ranked if r > mine)     # competition ranking: ties share a rank
            if res.group == "bad_pods":
                # The documented question is about the pod's OWN spec: the direct pod -> node step.
                if G.has_edge(src, tgt):
                    e = G.edges[src, tgt]
                    if mode == "learned":
                        m.escape_score = round(float(e.get("p_success", 0.0)), 4)
                        m.claims_escape = m.escape_score >= ESCAPE_P
                    else:
                        d = G.nodes[tgt]
                        impact = d.get("impact") if d.get("impact") is not None else d.get("risk_score")
                        m.escape_score = round(compute_path_risk(impact, e["weight"], "static"), 3)
                        m.claims_escape = True      # static weights have no probability: an edge is a claim
                else:
                    m.claims_escape, m.escape_score = False, 0.0

    summary = _summarise(results, totals)
    return {
        "context": context,
        "expected": str(expected),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seconds": round(time.time() - t0, 1),
        "entry_points": "internet, users and every pod (Kubernetes Goat assumes any app can be compromised)",
        "escape_threshold_learned": ESCAPE_P,
        "paths_ranked": totals,
        "skipped_not_deployed": skipped,
        "summary": summary,
        "items": [{**{k: v for k, v in asdict(r).items() if k != "modes"},
                   "modes": {k: asdict(v) for k, v in r.modes.items()}} for r in results],
    }


def _pairwise(results: list[ItemResult], mode: str) -> float | None:
    """Share of (documented-escape, documented-no-escape) Bad Pod pairs the weighting orders correctly.
    Ties count half. 1.0 = always ranks a real escape above a non-escape; 0.5 = cannot tell them apart."""
    bp = [r for r in results if r.group == "bad_pods"]
    yes = [r.modes[mode].escape_score or 0.0 for r in bp if r.expect == "reachable"]
    no = [r.modes[mode].escape_score or 0.0 for r in bp if r.expect == "not-reachable"]
    if not yes or not no:
        return None
    s = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in yes for b in no)
    return round(s / (len(yes) * len(no)), 3)


def _summarise(results: list[ItemResult], totals: dict[str, int]) -> dict[str, Any]:
    goat = [r for r in results if r.group == "kubernetes_goat"]
    bp = [r for r in results if r.group == "bad_pods"]
    out: dict[str, Any] = {}
    for mode in MODES:
        ranks = [r.modes[mode].rank for r in goat if r.modes[mode].rank is not None]
        out[mode] = {
            "goat_found": sum(r.modes[mode].found for r in goat),
            "goat_total": len(goat),
            "goat_ranks": {r.id: r.modes[mode].rank for r in goat if r.modes[mode].rank is not None},
            "goat_mean_rank": round(sum(ranks) / len(ranks), 1) if ranks else None,
            "badpods_correct": sum(r.modes[mode].claims_escape == (r.expect == "reachable") for r in bp),
            "badpods_total": len(bp),
            "badpods_pairwise": _pairwise(results, mode),
            "paths_ranked": totals.get(mode),
        }
    return out


def save(result: dict[str, Any], out_dir: str | Path = "data/benchmark") -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"benchmark-{datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
    path.write_text(json.dumps(result, indent=2))
    (out / "latest.json").write_text(json.dumps(result, indent=2))
    return path
