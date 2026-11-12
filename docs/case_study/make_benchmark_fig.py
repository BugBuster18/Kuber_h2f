"""Benchmark figure for the case study, drawn from demo/benchmark/results-full.json.

    python docs/case_study/make_benchmark_fig.py
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
res = json.loads((ROOT / "demo/benchmark/results-full.json").read_text())
OLD, ML, INK, MUTED, GRID = "#8e99ab", "#2255cc", "#1c2333", "#5b6577", "#e6e9ef"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9.5, "axes.edgecolor": "#9aa3b2",
                     "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED})

items = {i["id"]: i for i in res["items"]}
S = res["summary"]
ranked = [k for k in ("goat-2", "goat-4", "goat-12", "goat-16") if k in S["learned"]["goat_ranks"]]
SHORT = {"goat-2": "Docker-in-Docker escape", "goat-4": "container escape to host",
         "goat-12": "secret in environment", "goat-16": "RBAC: SA reads secrets"}
fig, (a, b) = plt.subplots(1, 2, figsize=(9.2, 3.5), gridspec_kw={"width_ratios": [1.4, 1]})

# left: rank of each documented Goat attack, old -> ML
for y, k in enumerate(reversed(ranked)):
    o, m = S["static"]["goat_ranks"][k], S["learned"]["goat_ranks"][k]
    a.plot([o, m], [y, y], color="#c9d1de", lw=3, zorder=1, solid_capstyle="round")
    a.scatter([o], [y], s=70, color=OLD, zorder=3)
    a.scatter([m], [y], s=70, color=ML, zorder=4)
    a.text(o + 0.9, y + 0.17, f"#{o}", color=MUTED, fontsize=8.5, va="bottom")
    a.text(m - 0.9 if m > 1 else m - 0.6, y + 0.17, f"#{m}", color=ML, fontsize=8.5, va="bottom",
           ha="right" if m > 1 else "right", weight="bold")
a.set_yticks(range(len(ranked)))
a.set_yticklabels([f"Goat #{k.split('-')[1]}  {SHORT.get(k, items[k]['title'])}" for k in reversed(ranked)], fontsize=8.6)
a.set_xlim(-1.5, max(S["static"]["goat_ranks"].values()) + 4)
a.set_ylim(-0.6, len(ranked) - 0.4)
a.set_xlabel(f"rank among all {S['learned']['paths_ranked']} attack paths (1 = most dangerous)")
a.set_title("Where each documented attack ranks", color=INK, fontsize=10.5, pad=8)
a.grid(axis="x", color=GRID); a.set_axisbelow(True)
for s in ("top", "right"):
    a.spines[s].set_visible(False)
a.scatter([], [], color=OLD, s=50, label=f"old weights (mean #{S['static']['goat_mean_rank']})")
a.scatter([], [], color=ML, s=50, label=f"ML weights (mean #{S['learned']['goat_mean_rank']})")
a.legend(loc="lower center", bbox_to_anchor=(0.5, -0.42), ncol=2, frameon=False, fontsize=8.4)

# right: agreement with the documented answers
total = S["static"]["goat_total"] + S["static"]["badpods_total"]
match = {m: S[m]["goat_found"] + S[m]["badpods_correct"] for m in ("static", "learned")}
groups = [("matches the\ndocumented answer\n(15 cases)", {m: match[m] / total * 100 for m in match},
           {m: f"{match[m]}/{total}" for m in match}),
          ("real escapes ranked\nabove non-escapes\n(Bad Pods)", {m: S[m]["badpods_pairwise"] * 100 for m in match},
           {m: f"{S[m]['badpods_pairwise'] * 100:.0f}%" for m in match})]
w, GAP = 0.36, 1.25
for gi, (label, vals, txt) in enumerate(groups):
    for j, (m, c) in enumerate((("static", OLD), ("learned", ML))):
        x = gi * GAP + (j - 0.5) * w
        b.bar(x, vals[m], width=w * 0.92, color=c, zorder=2)
        b.text(x, vals[m] + 2, txt[m], ha="center", va="bottom", fontsize=8.6,
               color=ML if m == "learned" else MUTED, weight="bold" if m == "learned" else "normal")
b.axhline(50, color="#c2c8d3", lw=1, ls="--", zorder=1)
b.set_xticks([i * GAP for i in range(len(groups))])
b.set_xlim(-0.45, (len(groups) - 1) * GAP + 0.45)
b.set_xticklabels([g[0] for g in groups], fontsize=8.0)
b.set_ylim(0, 110); b.set_yticks([0, 25, 50, 75, 100]); b.set_ylabel("%")
b.set_title("Agreement with the answer key", color=INK, fontsize=10.5, pad=8)
b.grid(axis="y", color=GRID); b.set_axisbelow(True)
for s in ("top", "right"):
    b.spines[s].set_visible(False)

fig.tight_layout(w_pad=2.5)
out = Path(__file__).with_name("assets") / "fig_benchmark.png"
fig.savefig(out, dpi=220)
print("saved", out)
