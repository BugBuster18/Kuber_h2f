"""
Model 1 — CVE exploitation probability.

Label:    1 if the CVE is in CISA's Known Exploited Vulnerabilities catalog.
Features: CVSS v3 (or v2) base metrics, CWE, reference tags (public exploit /
          patch / advisory), description keywords, vendor popularity, year.
Split:    temporal — train on CVEs published <= TRAIN_UNTIL_YEAR, test on
          later ones (what a deployed model actually faces).
Models:   CVSS-score-only logistic baseline, full logistic regression, and a
          regularized gradient-boosted tree model (the one we deploy).
"""

from __future__ import annotations

import gzip
import json
import lzma
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

from .cve_features import (
    CATEGORICAL_FEATURES, FEATURES, NUMERIC_FEATURES,
    encode_row, extract_raw, score_only_raw,
)
from .paths import CVE_FEATURES_PATH, CVE_MODEL_PATH, CVE_SCORES_PATH, KEV_IDS_PATH, PROCESSED_DIR
from . import datasets

TRAIN_UNTIL_YEAR = 2023
CWE_VOCAB_SIZE = 60
VENDOR_VOCAB_SIZE = 5000
SCORE_ONLY_AUGMENT_FRACTION = 0.15
# A CVE on CISA's KEV list is *known* to be exploited; we don't predict it.
KEV_PROBABILITY = 0.99


# ─── Dataset construction ────────────────────────────────────────────────────


def load_kev_ids() -> set[str]:
    data = json.loads(datasets.kev_path().read_text(encoding="utf-8"))
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def build_cve_table(log: Callable[[str], None] = print):
    """Parse NVD yearly feeds + KEV into one feature table (pandas DataFrame)."""
    import pandas as pd

    kev = load_kev_ids()
    rows: list[dict[str, Any]] = []
    for year in datasets.available_nvd_years():
        with lzma.open(datasets.nvd_year_path(year), "rt", encoding="utf-8") as f:
            items = json.load(f).get("cve_items", [])
        kept = 0
        for rec in items:
            if rec.get("vulnStatus") == "Rejected":
                continue
            raw = extract_raw(rec)
            raw["cve_id"] = rec["id"]
            raw["label"] = 1 if rec["id"] in kev else 0
            rows.append(raw)
            kept += 1
        del items
        log(f"  parsed CVE-{year}: {kept:,} records")

    df = pd.DataFrame(rows)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(CVE_FEATURES_PATH, index=False, compression="gzip")
    log(f"  → {len(df):,} CVEs, {int(df.label.sum()):,} known-exploited "
        f"({df.label.mean() * 100:.2f}%) saved to {CVE_FEATURES_PATH.name}")
    return df


# ─── Encoding helpers ────────────────────────────────────────────────────────


def _vocabs(df) -> tuple[dict[str, int], list[str]]:
    vendor_counts = dict(Counter(v for v in df["vendor"].dropna()).most_common(VENDOR_VOCAB_SIZE))
    cwe_vocab = [c for c, _ in Counter(df["cwe"].fillna("NONE")).most_common(CWE_VOCAB_SIZE)]
    return vendor_counts, cwe_vocab


def _matrix(df, vendor_counts, cwe_vocab):
    import numpy as np

    records = df.to_dict("records")
    for r in records:  # pandas turns missing vendor into NaN
        if not isinstance(r.get("vendor"), str):
            r["vendor"] = None
    return np.array([encode_row(r, vendor_counts, cwe_vocab) for r in records], dtype=float)


def _augment_score_only(df, rng):
    """Add rows where only the CVSS score is known, so the model behaves
    sensibly for CVEs we cannot look up (offline / unknown IDs)."""
    import pandas as pd

    sample = df.sample(frac=SCORE_ONLY_AUGMENT_FRACTION, random_state=rng)
    aug = pd.DataFrame([
        {**score_only_raw(s if not math.isnan(s) else None), "label": l, "cve_id": c}
        for s, l, c in zip(sample["base_score"], sample["label"], sample["cve_id"])
    ])
    return pd.concat([df, aug], ignore_index=True)


def _make_gbm():
    """Regularized gradient boosting with log-loss objective.

    No post-hoc calibration wrapper: in evaluation, isotonic/sigmoid
    calibration (CalibratedClassifierCV) inflated mean predictions ~5x and
    made Brier score worse than predicting the base rate, while the
    regularized model's own probabilities beat the base rate.
    """
    from sklearn.ensemble import HistGradientBoostingClassifier

    cat_mask = [f in CATEGORICAL_FEATURES for f in FEATURES]
    return HistGradientBoostingClassifier(
        learning_rate=0.05, max_iter=300, max_leaf_nodes=15, min_samples_leaf=100,
        l2_regularization=3.0, categorical_features=cat_mask,
        early_stopping=True, validation_fraction=0.1, random_state=0,
    )


def _make_logreg():
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    return make_pipeline(
        SimpleImputer(strategy="median", add_indicator=True),
        StandardScaler(),
        LogisticRegression(max_iter=2000, C=0.5),
    )


def _metrics(y, p) -> dict[str, float]:
    from sklearn.metrics import average_precision_score, brier_score_loss, log_loss, roc_auc_score

    return {
        "roc_auc": round(float(roc_auc_score(y, p)), 4),
        "pr_auc": round(float(average_precision_score(y, p)), 4),
        "brier": round(float(brier_score_loss(y, p)), 5),
        "log_loss": round(float(log_loss(y, p, labels=[0, 1])), 5),
        "base_rate": round(float(sum(y) / len(y)), 5),
    }


def _top_k_precision(y, p, k=100) -> float:
    import numpy as np

    idx = np.argsort(-np.asarray(p))[:k]
    return round(float(np.asarray(y)[idx].mean()), 3)


# ─── Training ────────────────────────────────────────────────────────────────


def train_cve_model(df=None, log: Callable[[str], None] = print) -> dict:
    """Train, evaluate and save the CVE exploitation model. Returns metrics."""
    import joblib
    import numpy as np
    import pandas as pd
    import sklearn
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold

    if df is None:
        df = pd.read_csv(CVE_FEATURES_PATH, compression="gzip", low_memory=False)
    df = df[df["published_year"].notna()].reset_index(drop=True)

    train = df[df.published_year <= TRAIN_UNTIL_YEAR].reset_index(drop=True)
    test = df[df.published_year > TRAIN_UNTIL_YEAR].reset_index(drop=True)
    log(f"  split: train ≤{TRAIN_UNTIL_YEAR}: {len(train):,} ({int(train.label.sum())} exploited) | "
        f"test >{TRAIN_UNTIL_YEAR}: {len(test):,} ({int(test.label.sum())} exploited)")

    vendor_counts, cwe_vocab = _vocabs(train)
    train_aug = _augment_score_only(train, rng=1)
    X_tr, y_tr = _matrix(train_aug, vendor_counts, cwe_vocab), train_aug.label.to_numpy()
    X_te, y_te = _matrix(test, vendor_counts, cwe_vocab), test.label.to_numpy()

    results: dict[str, Any] = {}

    # Baseline: CVSS base score only
    bs_idx = NUMERIC_FEATURES.index("base_score")
    fill = np.nanmedian(X_tr[:, bs_idx])
    base = LogisticRegression().fit(np.nan_to_num(X_tr[:, [bs_idx]], nan=fill), y_tr)
    p_base = base.predict_proba(np.nan_to_num(X_te[:, [bs_idx]], nan=fill))[:, 1]
    results["cvss_score_only_logreg"] = _metrics(y_te, p_base)

    lr = _make_logreg().fit(X_tr, y_tr)
    p_lr = lr.predict_proba(X_te)[:, 1]
    results["logistic_regression"] = _metrics(y_te, p_lr)

    gbm = _make_gbm().fit(X_tr, y_tr)
    p_gbm = gbm.predict_proba(X_te)[:, 1]
    results["gradient_boosting"] = _metrics(y_te, p_gbm)
    results["gradient_boosting"]["precision_at_100"] = _top_k_precision(y_te, p_gbm)
    results["cvss_score_only_logreg"]["precision_at_100"] = _top_k_precision(y_te, p_base)
    results["logistic_regression"]["precision_at_100"] = _top_k_precision(y_te, p_lr)

    # External benchmark: FIRST EPSS (note: today's EPSS has hindsight)
    if datasets.epss_path().exists():
        epss = pd.read_csv(datasets.epss_path(), comment="#", compression="gzip")
        epss_map = dict(zip(epss["cve"], epss["epss"]))
        mask = test.cve_id.map(lambda c: c in epss_map).to_numpy()
        if mask.sum() > 0 and y_te[mask].sum() > 0:
            p_epss = test.cve_id[mask].map(epss_map).to_numpy()
            results["epss_benchmark_on_same_test_cves"] = {
                **_metrics(y_te[mask], p_epss),
                "note": "EPSS is a production model scored with today's data (hindsight); "
                        "shown as an upper reference, not a fair baseline.",
                "precision_at_100": _top_k_precision(y_te[mask], p_epss),
            }
            results["gradient_boosting_on_epss_subset"] = _metrics(y_te[mask], p_gbm[mask])

    for name, m in results.items():
        log(f"  {name:<36} ROC-AUC {m['roc_auc']:.3f}  PR-AUC {m['pr_auc']:.3f}  Brier {m['brier']:.5f}")

    # Score-only regime check (how the model behaves offline)
    X_so = np.full_like(X_te, np.nan)
    X_so[:, bs_idx] = X_te[:, bs_idx]
    X_so[:, -1] = float(len(cwe_vocab))
    results["gradient_boosting_score_only_inputs"] = _metrics(y_te, gbm.predict_proba(X_so)[:, 1])

    # ── Final model: refit on ALL years, out-of-fold scores for every CVE ──
    vendor_counts_all, cwe_vocab_all = _vocabs(df)
    X_all = _matrix(df, vendor_counts_all, cwe_vocab_all)
    y_all = df.label.to_numpy()

    oof = np.zeros(len(df))
    for fold, (tr, va) in enumerate(StratifiedKFold(5, shuffle=True, random_state=7).split(X_all, y_all)):
        sub = _augment_score_only(df.iloc[tr], rng=fold)
        m = _make_gbm().fit(_matrix(sub, vendor_counts_all, cwe_vocab_all), sub.label.to_numpy())
        oof[va] = m.predict_proba(X_all[va])[:, 1]
    results["out_of_fold_all_years"] = _metrics(y_all, oof)
    log(f"  out-of-fold (all years, 5-fold)       ROC-AUC {results['out_of_fold_all_years']['roc_auc']:.3f}")

    df_aug = _augment_score_only(df, rng=99)
    final = _make_gbm().fit(_matrix(df_aug, vendor_counts_all, cwe_vocab_all), df_aug.label.to_numpy())

    # Out-of-fold scores are the lookup table: honest (never in-sample)
    with gzip.open(CVE_SCORES_PATH, "wt", encoding="utf-8") as f:
        json.dump({c: round(float(p), 5) for c, p in zip(df.cve_id, oof)}, f)

    kev_ids = sorted(load_kev_ids())
    kev_meta = json.loads(datasets.kev_path().read_text(encoding="utf-8"))
    KEV_IDS_PATH.write_text(json.dumps({
        "catalogVersion": kev_meta.get("catalogVersion"),
        "dateReleased": kev_meta.get("dateReleased"),
        "cve_ids": kev_ids,
    }), encoding="utf-8")

    artifact = {
        "model": final,
        "features": FEATURES,
        "vendor_counts": vendor_counts_all,
        "cwe_vocab": cwe_vocab_all,
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_train_rows": int(len(df)),
        "n_positive": int(y_all.sum()),
        "train_until_year_for_eval": TRAIN_UNTIL_YEAR,
        "metrics": results,
    }
    joblib.dump(artifact, CVE_MODEL_PATH, compress=3)
    log(f"  ✓ saved {CVE_MODEL_PATH.name}, {CVE_SCORES_PATH.name}, {KEV_IDS_PATH.name}")
    return results


# ─── Inference ───────────────────────────────────────────────────────────────


class CVEExploitPredictor:
    """P(exploited in the wild) for a CVE, using the best evidence available:

      1. On CISA KEV                       → KEV_PROBABILITY (known exploited)
      2. In the out-of-fold score table    → that score (needs ml-train data)
      3. NVD record (cached / online)      → model prediction
      4. Only the CVSS score on the edge   → model prediction (score-only)
      5. Nothing                           → model prediction with no inputs
    """

    def __init__(self, allow_network: bool = True):
        import joblib

        art = joblib.load(CVE_MODEL_PATH)
        self.model = art["model"]
        self.vendor_counts = art["vendor_counts"]
        self.cwe_vocab = art["cwe_vocab"]
        self.allow_network = allow_network
        self.kev = set(json.loads(KEV_IDS_PATH.read_text(encoding="utf-8"))["cve_ids"]) \
            if KEV_IDS_PATH.exists() else set()
        self._scores: dict[str, float] | None = None
        self._cache: dict[tuple, tuple[float, str]] = {}

    def _score_table(self) -> dict[str, float]:
        if self._scores is None:
            self._scores = {}
            if CVE_SCORES_PATH.exists():
                with gzip.open(CVE_SCORES_PATH, "rt", encoding="utf-8") as f:
                    self._scores = json.load(f)
        return self._scores

    def predict_raw(self, raw: dict[str, Any]) -> float:
        import numpy as np

        x = np.array([encode_row(raw, self.vendor_counts, self.cwe_vocab)], dtype=float)
        return float(self.model.predict_proba(x)[0, 1])

    def predict(self, cve_id: str | None, cvss: float | None = None) -> tuple[float, str]:
        """Return (probability, evidence_source)."""
        key = (cve_id, cvss)
        if key in self._cache:
            return self._cache[key]

        if cve_id and cve_id in self.kev:
            out = (KEV_PROBABILITY, "cisa-kev")
        elif cve_id and cve_id in self._score_table():
            out = (self._score_table()[cve_id], "model:nvd-record")
        else:
            record = None
            if cve_id and self.allow_network:
                from ..cve_service import enricher
                record = enricher.get_nvd_record(cve_id)
            if record:
                out = (self.predict_raw(extract_raw(record)), "model:nvd-record")
            else:
                out = (self.predict_raw(score_only_raw(cvss)),
                       "model:cvss-only" if cvss is not None else "model:no-data")
        self._cache[key] = out
        return out
