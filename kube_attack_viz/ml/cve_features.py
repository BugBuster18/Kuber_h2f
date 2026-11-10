"""
Feature extraction for the CVE exploitation model.

The same function turns an NVD record into features at training time and at
analysis time, so the model never sees a feature it can't get in production.

Leakage guards — these are dropped because they are *consequences* of a CVE
being added to KEV rather than properties of the vulnerability:
  * cisaExploitAdd / cisaActionDue / cisaRequiredAction / cisaVulnerabilityName
  * references pointing at cisa.gov
  * vulnStatus / lastModified (NVD prioritises analysis of KEV entries)
"""

from __future__ import annotations

import math
import re
from typing import Any

# Ordinal encodings for CVSS v3 base metrics (higher = easier / worse).
_AV = {"NETWORK": 3, "ADJACENT_NETWORK": 2, "ADJACENT": 2, "LOCAL": 1, "PHYSICAL": 0}
_AC = {"LOW": 1, "HIGH": 0}
_PR = {"NONE": 2, "LOW": 1, "HIGH": 0}
_UI = {"NONE": 1, "REQUIRED": 0}
_SCOPE = {"CHANGED": 1, "UNCHANGED": 0}
_CIA = {"HIGH": 2, "LOW": 1, "NONE": 0}
# CVSS v2 equivalents (fallback for old records)
_AV2 = {"NETWORK": 3, "ADJACENT_NETWORK": 2, "LOCAL": 1}
_AC2 = {"LOW": 1, "MEDIUM": 1, "HIGH": 0}
_AU2 = {"NONE": 2, "SINGLE": 1, "MULTIPLE": 0}
_CIA2 = {"COMPLETE": 2, "PARTIAL": 1, "NONE": 0}

# Description keywords that describe *what an attacker gets*.
_KEYWORDS = {
    "kw_rce": r"remote code execution|execute arbitrary (code|commands)|code execution",
    "kw_auth_bypass": r"authentication bypass|bypass authentication|unauthenticated|without authentication",
    "kw_cmd_injection": r"command injection|os command",
    "kw_deserialization": r"deserializ",
    "kw_path_traversal": r"path traversal|directory traversal",
    "kw_priv_esc": r"privilege escalation|escalate privileges|gain (root|elevated) privileges",
    "kw_sqli": r"sql injection",
    "kw_xss": r"cross-site scripting|\bxss\b",
    "kw_dos": r"denial of service|\bdos\b|crash",
    "kw_container": r"container|kubernetes|docker|runc|containerd|kubelet",
    "kw_in_the_wild": r"in the wild|actively exploited",
}
_KEYWORD_RE = {k: re.compile(v, re.I) for k, v in _KEYWORDS.items()}

NUMERIC_FEATURES = [
    "av", "ac", "pr", "ui", "scope", "conf", "integ", "avail",
    "base_score", "exploitability_score", "impact_score", "cvss_major",
    "has_exploit_ref", "has_patch_ref", "has_vendor_advisory", "log_n_refs",
    "log_vendor_cves", "published_year",
    *_KEYWORDS.keys(),
]
CATEGORICAL_FEATURES = ["cwe"]
FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES

NAN = float("nan")


def _pick_metric(metrics: dict, key: str) -> dict | None:
    """Prefer NVD's own (Primary) assessment, else the first one available."""
    entries = metrics.get(key) or []
    if not entries:
        return None
    for m in entries:
        if m.get("type") == "Primary":
            return m
    return entries[0]


def _vendor(record: dict) -> str | None:
    for block in record.get("affected", []) or []:
        for item in block.get("affectedData", []) or []:
            v = (item.get("vendor") or "").strip().lower()
            if v and v not in ("n/a", "unknown"):
                return v
    for cfg in record.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 4 and parts[3] not in ("*", "-"):
                    return parts[3].lower()
    return None


def _cwe(record: dict) -> str:
    for w in record.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = d.get("value", "")
            if v.startswith("CWE-"):
                return v
    return "NONE"


def extract_raw(record: dict) -> dict[str, Any]:
    """Extract model inputs (before vendor-frequency/CWE vocab encoding)."""
    metrics = record.get("metrics", {}) or {}
    row: dict[str, Any] = {k: NAN for k in NUMERIC_FEATURES}

    m = _pick_metric(metrics, "cvssMetricV31") or _pick_metric(metrics, "cvssMetricV30")
    if m:
        c = m.get("cvssData", {})
        row.update(
            av=_AV.get(c.get("attackVector"), NAN),
            ac=_AC.get(c.get("attackComplexity"), NAN),
            pr=_PR.get(c.get("privilegesRequired"), NAN),
            ui=_UI.get(c.get("userInteraction"), NAN),
            scope=_SCOPE.get(c.get("scope"), NAN),
            conf=_CIA.get(c.get("confidentialityImpact"), NAN),
            integ=_CIA.get(c.get("integrityImpact"), NAN),
            avail=_CIA.get(c.get("availabilityImpact"), NAN),
            base_score=float(c.get("baseScore", NAN)),
            exploitability_score=float(m.get("exploitabilityScore", NAN)),
            impact_score=float(m.get("impactScore", NAN)),
            cvss_major=3.0,
        )
    else:
        m2 = _pick_metric(metrics, "cvssMetricV2")
        if m2:
            c = m2.get("cvssData", {})
            row.update(
                av=_AV2.get(c.get("accessVector"), NAN),
                ac=_AC2.get(c.get("accessComplexity"), NAN),
                pr=_AU2.get(c.get("authentication"), NAN),
                conf=_CIA2.get(c.get("confidentialityImpact"), NAN),
                integ=_CIA2.get(c.get("integrityImpact"), NAN),
                avail=_CIA2.get(c.get("availabilityImpact"), NAN),
                base_score=float(c.get("baseScore", NAN)),
                exploitability_score=float(m2.get("exploitabilityScore", NAN)) * 3.9 / 10.0,
                impact_score=float(m2.get("impactScore", NAN)) * 6.0 / 10.0,
                cvss_major=2.0,
            )

    refs = [
        r for r in (record.get("references") or [])
        if "cisa.gov" not in (r.get("url") or "")  # leakage guard
    ]
    tags = {t for r in refs for t in (r.get("tags") or [])}
    row["has_exploit_ref"] = 1.0 if "Exploit" in tags else 0.0
    row["has_patch_ref"] = 1.0 if "Patch" in tags else 0.0
    row["has_vendor_advisory"] = 1.0 if "Vendor Advisory" in tags else 0.0
    row["log_n_refs"] = math.log1p(len(refs))

    published = record.get("published") or ""
    row["published_year"] = float(published[:4]) if published[:4].isdigit() else NAN

    desc = " ".join(
        d.get("value", "") for d in (record.get("descriptions") or []) if d.get("lang") == "en"
    )
    for k, rx in _KEYWORD_RE.items():
        row[k] = 1.0 if rx.search(desc) else 0.0

    row["cwe"] = _cwe(record)
    row["vendor"] = _vendor(record)
    row["log_vendor_cves"] = NAN  # filled by encode_row() from the vendor vocab
    return row


def encode_row(raw: dict[str, Any], vendor_counts: dict[str, int], cwe_vocab: list[str]) -> list[float]:
    """Turn an extracted row into the model's numeric feature vector."""
    vendor = raw.get("vendor")
    count = vendor_counts.get(vendor, 0) if vendor else 0
    vec = []
    for f in NUMERIC_FEATURES:
        if f == "log_vendor_cves":
            vec.append(math.log1p(count) if vendor else NAN)
        else:
            v = raw.get(f, NAN)
            vec.append(NAN if v is None else float(v))
    cwe = raw.get("cwe") or "NONE"
    vec.append(float(cwe_vocab.index(cwe)) if cwe in cwe_vocab else float(len(cwe_vocab)))
    return vec


def score_only_raw(cvss: float | None) -> dict[str, Any]:
    """Features when all we know about a CVE is its CVSS base score."""
    row: dict[str, Any] = {k: NAN for k in NUMERIC_FEATURES}
    if cvss is not None:
        row["base_score"] = float(cvss)
    row["cwe"] = "NONE"
    row["vendor"] = None
    return row
