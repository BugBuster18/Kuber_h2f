"""Generate the model card (JSON + Markdown) from the trained artifacts."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from . import ML_VERSION
from .paths import CVE_MODEL_PATH, KEV_IDS_PATH, MODEL_CARD_JSON, MODEL_CARD_MD
from .weights import DEFAULT_P_UNKNOWN, EDGE_PRIORS, P_MAX


def write_model_card() -> dict:
    import joblib

    from .datasets import load_manifest

    art = joblib.load(CVE_MODEL_PATH)
    kev = json.loads(KEV_IDS_PATH.read_text(encoding="utf-8"))
    manifest = load_manifest().get("files", {})
    m = art["metrics"]

    card = {
        "ml_version": ML_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cve_model": {
            "task": "P(CVE is exploited in the wild), label = listed in CISA KEV",
            "algorithm": "HistGradientBoostingClassifier (scikit-learn), log-loss objective",
            "sklearn_version": art["sklearn_version"],
            "trained_at": art["trained_at"],
            "training_rows": art["n_train_rows"],
            "positives": art["n_positive"],
            "features": art["features"],
            "evaluation": {
                "split": f"temporal: train <= {art['train_until_year_for_eval']}, "
                         f"test > {art['train_until_year_for_eval']}",
                "metrics": m,
            },
            "kev_catalog_version": kev.get("catalogVersion"),
        },
        "edge_weights": {
            "weight": "-ln P(edge)",
            "bases": {
                "exact-config": f"feasibility decided by configuration (k8s engine): P = {P_MAX}",
                "cve-model": "conditional edge with a known CVE: 1 - (1 - p_unknown) * (1 - p_exploit)",
                "scenario-param": f"conditional edge, no CVE: P = p_unknown (default {DEFAULT_P_UNKNOWN}; "
                                  "an assumption, not a measurement)",
                "legacy-prior": "graph JSON without feasibility info: assumed per-category priors",
            },
            "learned_component": "p_exploit from the CVE model",
            "legacy_priors": EDGE_PRIORS,
        },
        "data_sources": {name: {k: v for k, v in e.items() if k != "bytes"} for name, e in manifest.items()},
    }
    MODEL_CARD_JSON.write_text(json.dumps(card, indent=2), encoding="utf-8")

    def row(name: str, label: str) -> str:
        r = m.get(name)
        if not r:
            return ""
        p100 = r.get("precision_at_100", "—")
        return f"| {label} | {r['roc_auc']:.3f} | {r['pr_auc']:.3f} | {r['brier']:.5f} | {p100} |\n"

    md = f"""# KubeAttackViz — Learned Edge Weights: Model Card

Generated {card['generated_at'][:19]} UTC · ml v{ML_VERSION} · scikit-learn {art['sklearn_version']}

## What it does
Each attack-graph edge gets a traversal probability `P(edge)` and weight `-ln P(edge)`.
Dijkstra's cheapest path is then the **most probable** path, `P(path) = exp(-cost)`,
and path risk = `target impact × P(path)` (expected impact, 0–10).

Each edge's probability has a reported **basis**:

| Basis | When | P(edge) |
|---|---|---|
| `exact-config` | Feasibility decided by configuration (RBAC grant, mounted token, routing, privileged pod) | {P_MAX} |
| `cve-model` | Conditional edge with a known CVE | `1 − (1 − p_unknown)(1 − p_exploit)` — `p_exploit` **learned** (below) |
| `scenario-param` | Conditional edge, no CVE evidence | `p_unknown` = {DEFAULT_P_UNKNOWN} by default (`--p-unknown`) — an **assumption**, not a measurement |
| `legacy-prior` | Hand-made graph JSON without feasibility info | assumed per-category priors (table at the end) |

## CVE exploitation model
* **Task:** P(CVE is exploited in the wild). Label = listed in CISA KEV (catalog {kev.get('catalogVersion')}).
* **Data:** {art['n_train_rows']:,} NVD CVE records, {art['n_positive']:,} known exploited ({art['n_positive'] / art['n_train_rows'] * 100:.2f}%).
* **Features:** CVSS base metrics, CWE, reference tags (public exploit / patch / advisory),
  description keywords, vendor popularity, publication year.
* **Leakage guards:** CISA-derived NVD fields, cisa.gov references, vulnStatus and lastModified are excluded.
* **Algorithm:** gradient-boosted trees (log-loss). Post-hoc isotonic/sigmoid calibration was tested and
  rejected: it inflated predictions ~5× and scored a worse Brier than simply predicting the base rate.

### Evaluation — temporal split (train ≤ {art['train_until_year_for_eval']}, test > {art['train_until_year_for_eval']})

| Model | ROC-AUC | PR-AUC | Brier | Precision@100 |
|---|---|---|---|---|
{row('cvss_score_only_logreg', 'CVSS base score only (baseline)')}{row('logistic_regression', 'Logistic regression')}{row('gradient_boosting', '**Gradient boosting (deployed)**')}{row('gradient_boosting_score_only_inputs', 'Deployed model, CVSS-score-only inputs (offline fallback)')}{row('epss_benchmark_on_same_test_cves', 'FIRST EPSS (reference only — scored with hindsight)')}
Out-of-fold (all years, 5-fold): ROC-AUC {m['out_of_fold_all_years']['roc_auc']:.3f}, PR-AUC {m['out_of_fold_all_years']['pr_auc']:.3f}.

### Inference — evidence used, best first
1. On CISA KEV → 0.99
2. Out-of-fold score table for {art['n_train_rows']:,} known CVEs (shipped in `artifacts/`; never in-sample)
3. NVD record (cached; fetched online only with `--online-cve`)
4. CVSS score on the edge only → score-only prediction
5. Nothing known → base-rate prediction

## Limitations
* KEV is a *lower bound* on exploitation; probabilities are conservative.
* Recent CVEs have had less time to be added to KEV (label lag), so test-set base rate is lower than training.
* `p_unknown` (chance of a foothold with no known CVE) has no public measurement. Absolute path
  probabilities scale with it; rankings are what the evaluation checks for stability.
* Legacy priors apply only to graphs without feasibility information.

## Legacy category priors (graphs without feasibility information only)
| Category | Prior P(success) |
|---|---|
""" + "".join(f"| {k} | {v:.2f} |\n" for k, v in EDGE_PRIORS.items()) + """
## Data sources
""" + "".join(f"* `{n}` — {e.get('url')} (sha256 `{e.get('sha256', '')[:16]}…`, fetched {e.get('fetched_at', '')[:10]})\n"
               for n, e in manifest.items()) + """
## Reproduce
```bash
python main.py ml-fetch-data
python main.py ml-train
```
"""
    MODEL_CARD_MD.write_text(md, encoding="utf-8")
    return card
