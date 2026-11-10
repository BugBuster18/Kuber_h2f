"""
Download the public datasets used to train the CVE exploitation model.

Sources (all public, no account needed):
  * CISA Known Exploited Vulnerabilities (KEV) catalog — labels.
      https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  * NVD CVE records (API 2.0 schema), yearly mirror maintained by
    Fraunhofer FKIE — features (CVSS vector, CWE, references, text).
      https://github.com/fkie-cad/nvd-json-data-feeds
  * FIRST EPSS scores — used ONLY as an external benchmark in evaluation,
    never as a training feature.
      https://www.first.org/epss/

Every download is recorded in data/raw/manifest.json with its URL, size,
SHA-256 and fetch time so a training run can be traced to exact inputs.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

import requests

from .paths import RAW_DIR

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_YEAR_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

DEFAULT_YEARS = tuple(range(2010, datetime.now(timezone.utc).year + 1))

_USER_AGENT = "KubeAttackViz-ML/1.0 (dataset fetch)"


def kev_path() -> Path:
    return RAW_DIR / "kev.json"


def nvd_year_path(year: int) -> Path:
    return RAW_DIR / f"CVE-{year}.json.xz"


def epss_path() -> Path:
    return RAW_DIR / "epss_scores-current.csv.gz"


def _manifest_path() -> Path:
    return RAW_DIR / "manifest.json"


def load_manifest() -> dict:
    p = _manifest_path()
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"files": {}}


def _save_manifest(manifest: dict) -> None:
    _manifest_path().write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _download(url: str, dest: Path, force: bool, log: Callable[[str], None]) -> dict:
    """Stream a URL to dest atomically; return its manifest entry."""
    if dest.exists() and not force:
        log(f"  ✓ cached  {dest.name}")
        return {}
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    sha = hashlib.sha256()
    size = 0
    with requests.get(url, stream=True, timeout=60, headers={"User-Agent": _USER_AGENT}) as r:
        r.raise_for_status()
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 20):
                f.write(chunk)
                sha.update(chunk)
                size += len(chunk)
    tmp.replace(dest)
    log(f"  ↓ fetched {dest.name} ({size / 1e6:.1f} MB)")
    return {
        "url": url,
        "bytes": size,
        "sha256": sha.hexdigest(),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def fetch_all(
    years: Iterable[int] = DEFAULT_YEARS,
    with_epss: bool = True,
    force: bool = False,
    log: Callable[[str], None] = print,
) -> dict:
    """Download KEV, NVD yearly feeds and (optionally) EPSS into data/raw/."""
    manifest = load_manifest()
    jobs = [(KEV_URL, kev_path())]
    jobs += [(NVD_YEAR_URL.format(year=y), nvd_year_path(y)) for y in years]
    if with_epss:
        jobs.append((EPSS_URL, epss_path()))

    for url, dest in jobs:
        try:
            entry = _download(url, dest, force, log)
        except requests.HTTPError as e:
            # Future/empty years may not exist yet — skip, don't abort.
            log(f"  ✗ skipped {dest.name}: {e}")
            continue
        if entry:
            manifest["files"][dest.name] = entry
            _save_manifest(manifest)
    return manifest


def available_nvd_years() -> list[int]:
    years = []
    for p in sorted(RAW_DIR.glob("CVE-*.json.xz")):
        try:
            years.append(int(p.stem.split("-")[1].split(".")[0]))
        except (IndexError, ValueError):
            continue
    return years
