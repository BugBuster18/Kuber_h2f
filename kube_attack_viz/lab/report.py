"""Precision / recall / F1 of the feasibility engine against lab ground truth."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .runner import LAB_DIR


def latest_run() -> Path | None:
    runs = sorted(p for p in LAB_DIR.glob("*") if (p / "results.jsonl").exists())
    return runs[-1] if runs else None


def load_rows(run: Path) -> list[dict[str, Any]]:
    with open(run / "results.jsonl", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def confusion(rows) -> dict[str, Any]:
    tp = sum(1 for r in rows if r["engine"] and r["truth"])
    fp = sum(1 for r in rows if r["engine"] and not r["truth"])
    fn = sum(1 for r in rows if not r["engine"] and r["truth"])
    tn = sum(1 for r in rows if not r["engine"] and not r["truth"])
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else (
        None if precision is None or recall is None else 0.0)
    return {"n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1,
            "accuracy": (tp + tn) / len(rows) if rows else None}


def summarize(run: Path) -> dict[str, Any]:
    rows = load_rows(run)
    meta = json.loads((run / "run.json").read_text(encoding="utf-8"))
    by_kind = defaultdict(list)
    for r in rows:
        by_kind[r["kind"]].append(r)
    summary = {
        "run": meta,
        "scenarios": len({r["scenario"] for r in rows}),
        "overall": confusion(rows),
        "by_kind": {k: confusion(v) for k, v in by_kind.items()},
        "rbac_by_permission": {p: confusion([r for r in by_kind["rbac"] if r["permission"] == p])
                               for p in sorted({r["permission"] for r in by_kind["rbac"]})},
        "network_by_host_network": {
            str(h): confusion([r for r in by_kind["network"]
                               if (r["features"]["src_host_network"] or r["features"]["dst_host_network"]) == h])
            for h in (False, True)
        },
        "disagreements": [r for r in rows if r["engine"] != r["truth"]][:200],
        "disagreement_patterns": Counter(
            (r["kind"], r.get("permission") or ("hostNetwork" if r.get("features", {}).get("src_host_network")
                                                or r.get("features", {}).get("dst_host_network") else "-"),
             "FP" if r["engine"] else "FN")
            for r in rows if r["engine"] != r["truth"]).most_common(),
    }
    (run / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return summary


def _fmt(x):
    return "  —  " if x is None else f"{x:.3f}"


def format_summary(s: dict[str, Any]) -> str:
    lines = ["=" * 78, "  FEASIBILITY ENGINE vs. LIVE CLUSTER (lab ground truth)", "=" * 78,
             f"  Run {s['run']['run_id']} · {s['scenarios']} scenarios · Kubernetes {s['run']['server_version']} · "
             f"{s['run']['cni']}", "",
             f"  {'Check':<28}{'N':>7}{'TP':>6}{'FP':>5}{'FN':>5}{'TN':>7}{'Prec':>8}{'Recall':>8}{'F1':>8}",
             "  " + "-" * 76]

    def row(label, c):
        lines.append(f"  {label:<28}{c['n']:>7}{c['tp']:>6}{c['fp']:>5}{c['fn']:>5}{c['tn']:>7}"
                     f"{_fmt(c['precision']):>8}{_fmt(c['recall']):>8}{_fmt(c['f1']):>8}")

    for k, c in s["by_kind"].items():
        row(k, c)
    row("ALL", s["overall"])
    lines += ["", "  RBAC by permission:"]
    for p, c in s["rbac_by_permission"].items():
        row(f"  {p}", c)
    lines += ["", "  Network, involving a hostNetwork pod:"]
    for h, c in s["network_by_host_network"].items():
        if c["n"]:
            row(f"  hostNetwork={h}", c)
    if s["disagreement_patterns"]:
        lines += ["", "  Disagreement patterns (kind, permission/context, type → count):"]
        for (kind, ctx, typ), n in s["disagreement_patterns"]:
            lines.append(f"    {kind:<8} {ctx:<20} {typ}  × {n}")
    lines.append("=" * 78)
    return "\n".join(lines)
