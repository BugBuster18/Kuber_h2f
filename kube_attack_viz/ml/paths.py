"""Filesystem locations for ML datasets and model artifacts."""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent

# Trained models ship inside the package so `--weights learned` works
# without retraining.
ARTIFACTS_DIR = PACKAGE_DIR / "artifacts"

# Downloaded + derived datasets (gitignored, reproducible via ml-fetch-data
# and ml-train). Override with KAV_DATA_DIR.
DATA_DIR = Path(os.environ.get("KAV_DATA_DIR", PROJECT_ROOT / "data"))
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

CVE_MODEL_PATH = ARTIFACTS_DIR / "cve_model.joblib"
KEV_IDS_PATH = ARTIFACTS_DIR / "kev_ids.json"
MODEL_CARD_JSON = ARTIFACTS_DIR / "model_card.json"
MODEL_CARD_MD = ARTIFACTS_DIR / "MODEL_CARD.md"

CVE_FEATURES_PATH = PROCESSED_DIR / "cve_features.csv.gz"
# Out-of-fold exploit probability for every training CVE (shipped, ~1.5 MB)
CVE_SCORES_PATH = ARTIFACTS_DIR / "cve_exploit_scores.json.gz"
