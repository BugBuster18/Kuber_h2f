# KubeAttackViz — Learned Edge Weights: Model Card

Generated 2026-11-10T09:23:28 UTC · ml v1.0.0 · scikit-learn 1.7.2

## What it does
Each attack-graph edge gets a traversal probability `P(edge)` and weight `-ln P(edge)`.
Dijkstra's cheapest path is then the **most probable** path, `P(path) = exp(-cost)`,
and path risk = `target impact × P(path)` (expected impact, 0–10).

```
P(edge) = 1 - (1 - prior[category]) * (1 - p_exploit)
```

| Part | Source |
|---|---|
| `p_exploit` | **Learned** — CVE exploitation model below |
| `prior[category]` | **Assumed** — documented priors (no public hop-level outcome dataset exists) |

## CVE exploitation model
* **Task:** P(CVE is exploited in the wild). Label = listed in CISA KEV (catalog 2026.11.09).
* **Data:** 361,825 NVD CVE records, 1,743 known exploited (0.48%).
* **Features:** CVSS base metrics, CWE, reference tags (public exploit / patch / advisory),
  description keywords, vendor popularity, publication year.
* **Leakage guards:** CISA-derived NVD fields, cisa.gov references, vulnStatus and lastModified are excluded.
* **Algorithm:** gradient-boosted trees (log-loss). Post-hoc isotonic/sigmoid calibration was tested and
  rejected: it inflated predictions ~5× and scored a worse Brier than simply predicting the base rate.

### Evaluation — temporal split (train ≤ 2023, test > 2023)

| Model | ROC-AUC | PR-AUC | Brier | Precision@100 |
|---|---|---|---|---|
| CVSS base score only (baseline) | 0.770 | 0.012 | 0.00312 | 0.05 |
| Logistic regression | 0.877 | 0.112 | 0.00297 | 0.48 |
| **Gradient boosting (deployed)** | 0.887 | 0.108 | 0.00296 | 0.54 |
| Deployed model, CVSS-score-only inputs (offline fallback) | 0.777 | 0.010 | 0.00312 | — |
| FIRST EPSS (reference only — scored with hindsight) | 0.975 | 0.428 | 0.00303 | 0.89 |

Out-of-fold (all years, 5-fold): ROC-AUC 0.936, PR-AUC 0.309.

### Inference — evidence used, best first
1. On CISA KEV → 0.99
2. Out-of-fold score table for 361,825 known CVEs (shipped in `artifacts/`; never in-sample)
3. NVD record (cached; fetched online only with `--online-cve`)
4. CVSS score on the edge only → score-only prediction
5. Nothing known → base-rate prediction

## Limitations
* KEV is a *lower bound* on exploitation; probabilities are conservative.
* Recent CVEs have had less time to be added to KEV (label lag), so test-set base rate is lower than training.
* Category priors are assumptions, not measurements. Replace them with rates from your own
  assessment data in `kube_attack_viz/ml/weights.py` (`EDGE_PRIORS`).

## Edge category priors
| Category | Prior P(success) |
|---|---|
| endpoint_reachability | 0.95 |
| workload_entry | 0.06 |
| workload_to_workload | 0.08 |
| identity_use | 0.85 |
| rbac_binding | 0.97 |
| permission_use | 0.90 |
| config_access | 0.88 |
| data_store_access | 0.70 |
| infrastructure_access | 0.12 |
| scope_control | 0.80 |
| workload_control | 0.90 |
| other | 0.50 |

## Data sources
* `kev.json` — https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (sha256 `4372c54ba169d113…`, fetched 2026-11-10)
* `CVE-2010.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2010.json.xz (sha256 `ad3758a9acb49f76…`, fetched 2026-11-10)
* `CVE-2011.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2011.json.xz (sha256 `dee7aac93bd547ba…`, fetched 2026-11-10)
* `CVE-2012.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2012.json.xz (sha256 `809439df35faaf88…`, fetched 2026-11-10)
* `CVE-2013.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2013.json.xz (sha256 `5c55f3f4ebc46b81…`, fetched 2026-11-10)
* `CVE-2014.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2014.json.xz (sha256 `23356ec5537d9754…`, fetched 2026-11-10)
* `CVE-2015.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2015.json.xz (sha256 `04f01a46de88a500…`, fetched 2026-11-10)
* `CVE-2016.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2016.json.xz (sha256 `65e63e75adca9860…`, fetched 2026-11-10)
* `CVE-2017.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2017.json.xz (sha256 `1e4c38d7ef290436…`, fetched 2026-11-10)
* `CVE-2018.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2018.json.xz (sha256 `040cb04f9efb19fd…`, fetched 2026-11-10)
* `CVE-2019.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2019.json.xz (sha256 `3778d414921f4f09…`, fetched 2026-11-10)
* `CVE-2020.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2020.json.xz (sha256 `08c629bfc4154e7b…`, fetched 2026-11-10)
* `CVE-2021.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2021.json.xz (sha256 `bea9afdf365bbb53…`, fetched 2026-11-10)
* `CVE-2022.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2022.json.xz (sha256 `1c8855614bd00f74…`, fetched 2026-11-10)
* `CVE-2023.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2023.json.xz (sha256 `e4c5d2ca289b4cab…`, fetched 2026-11-10)
* `CVE-2024.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2024.json.xz (sha256 `fe398e1d0aca6412…`, fetched 2026-11-10)
* `CVE-2025.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2025.json.xz (sha256 `b7f93bae0e5e6f9e…`, fetched 2026-11-10)
* `CVE-2026.json.xz` — https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2026.json.xz (sha256 `0f0d288630b235cc…`, fetched 2026-11-10)
* `epss_scores-current.csv.gz` — https://epss.empiricalsecurity.com/epss_scores-current.csv.gz (sha256 `23bda31009c5c72f…`, fetched 2026-11-10)

## Reproduce
```bash
python main.py ml-fetch-data
python main.py ml-train
```
