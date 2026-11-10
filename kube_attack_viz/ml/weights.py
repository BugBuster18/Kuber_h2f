"""
Learned edge weights.

For every edge we estimate P(traversal succeeds) and set

    weight = -ln(P)

so Dijkstra's minimum-cost path is the most probable path and
P(path) = exp(-total_cost) = product of per-hop probabilities.

Where each probability comes from (reported per edge as `weight_basis`):

  "exact-config"    The edge's feasibility is "exact": the cluster's
                    configuration fully decides the transition (an RBAC
                    grant, a mounted token, a Service routing). It is
                    allowed, so P = P_MAX. Nothing is guessed.

  "cve-model"       The edge is "conditional" (configuration permits the
                    attempt; success needs e.g. an exploitable flaw in the
                    target workload) and a CVE is known for it. P combines
                    the LEARNED exploitation probability (CVE model trained
                    on NVD + CISA KEV) with the scenario parameter below.

  "scenario-param"  Conditional edge, no CVE evidence. P is the explicit
                    scenario parameter `p_unknown_foothold` — the assumed
                    chance of getting across without a known vulnerability
                    (zero-days, weak credentials, misconfigured apps). It is
                    NOT a measured rate: no public dataset reports it.
                    Default DEFAULT_P_UNKNOWN; set with --p-unknown /
                    KAV_P_UNKNOWN; the evaluation reports how rankings
                    change across its range.

  "legacy-prior"    The edge comes from a graph JSON without feasibility
                    information (e.g. the hand-made sample files). The
                    per-category priors in EDGE_PRIORS are used, as in the
                    previous version. These are assumptions.

    P(conditional) = 1 - (1 - p_unknown_foothold) * (1 - p_exploit)

A known CVE adds an independent second way across, so it can only raise P.
"""

from __future__ import annotations

import math
import os
from typing import Any

from .techniques import WORKLOADS, categorize_edge

P_MIN, P_MAX = 0.01, 0.995   # keeps weights finite and > 0

DEFAULT_P_UNKNOWN = 0.05
P_UNKNOWN_ENV = "KAV_P_UNKNOWN"

# Legacy: assumed per-category priors, used ONLY for graphs that carry no
# feasibility information. Not learned, not measured.
EDGE_PRIORS: dict[str, float] = {
    "endpoint_reachability": 0.95,
    "workload_entry": 0.06,
    "workload_to_workload": 0.08,
    "identity_use": 0.85,
    "rbac_binding": 0.97,
    "permission_use": 0.90,
    "config_access": 0.88,
    "data_store_access": 0.70,
    "infrastructure_access": 0.12,
    "scope_control": 0.80,
    "workload_control": 0.90,
    "other": 0.50,
}


def probability_to_weight(p: float) -> float:
    return -math.log(min(max(p, P_MIN), P_MAX))


def combine(prior: float, p_exploit: float | None) -> float:
    if p_exploit is None:
        return prior
    return 1.0 - (1.0 - prior) * (1.0 - p_exploit)


def default_p_unknown() -> float:
    raw = os.environ.get(P_UNKNOWN_ENV)
    if raw is None:
        return DEFAULT_P_UNKNOWN
    value = float(raw)
    if not 0.0 < value < 1.0:
        raise ValueError(f"{P_UNKNOWN_ENV} must be in (0, 1), got {raw}")
    return value


class LearnedEdgeWeights:
    """Scores graph edges with traversal probabilities."""

    def __init__(self, allow_network: bool = False, p_unknown: float | None = None):
        from .cve_model import CVEExploitPredictor

        self.cve = CVEExploitPredictor(allow_network=allow_network)
        self.p_unknown = default_p_unknown() if p_unknown is None else p_unknown

    def _best_cve(self, candidates: list[tuple[str | None, float | None]]) -> dict[str, Any] | None:
        best = None
        for cve_id, cvss in candidates:
            if not cve_id and cvss is None:
                continue
            p, evidence = self.cve.predict(cve_id, cvss)
            if best is None or p > best["p_exploit"]:
                best = {"cve": cve_id, "p_exploit": p, "evidence": evidence}
        return best

    def score_edge(
        self,
        src_type: str,
        relationship: str,
        tgt_type: str,
        edge_cve: str | None = None,
        edge_cvss: float | None = None,
        target_cves: list[str] | None = None,
        features: dict | None = None,
    ) -> dict[str, Any]:
        category = categorize_edge(src_type, relationship, tgt_type)
        feasibility = (features or {}).get("feasibility")

        candidates: list[tuple[str | None, float | None]] = [(edge_cve, edge_cvss)]
        # A vulnerable workload is reachable through any edge that enters it.
        if (tgt_type or "").lower() in WORKLOADS:
            candidates += [(c, None) for c in (target_cves or [])]
        best = self._best_cve(candidates)
        p_exploit = best["p_exploit"] if best else None

        if feasibility == "exact":
            basis, prior, p = "exact-config", None, P_MAX
        elif feasibility == "conditional":
            prior = self.p_unknown
            p = combine(prior, p_exploit)
            basis = "cve-model" if best else "scenario-param"
        else:
            prior = EDGE_PRIORS.get(category, EDGE_PRIORS["other"])
            p = combine(prior, p_exploit)
            basis = "legacy-prior"

        return {
            "category": category,
            "feasibility": feasibility,
            "weight_basis": basis,
            "prior": prior,
            "p_exploit": p_exploit,
            "exploit_cve": best["cve"] if best else None,
            "exploit_evidence": best["evidence"] if best else None,
            "p_success": p,
            "weight": probability_to_weight(p),
        }


_instance: LearnedEdgeWeights | None = None


def get_learned_weights(allow_network: bool = False, p_unknown: float | None = None) -> LearnedEdgeWeights:
    """Shared instance (model loading takes ~1s). Passing p_unknown reconfigures it."""
    global _instance
    if _instance is None:
        _instance = LearnedEdgeWeights(allow_network=allow_network, p_unknown=p_unknown)
    elif p_unknown is not None:
        _instance.p_unknown = p_unknown
    return _instance


def models_available() -> bool:
    from .paths import CVE_MODEL_PATH

    return CVE_MODEL_PATH.exists()
