"""
Learned edge weights.

For every edge we estimate P(traversal succeeds) and set

    weight = -ln(P)

so Dijkstra's minimum-cost path is the most probable path and
P(path) = exp(-total_cost) = product of per-hop probabilities.

    P(edge) = 1 - (1 - prior[category]) * (1 - p_exploit)

  * prior[category]: documented baseline probability for the edge's
    category (see techniques.py). These are stated assumptions — the part
    of the model that is NOT learned, because no public hop-level outcome
    dataset exists. Override them in one place: EDGE_PRIORS.
  * p_exploit: LEARNED. Probability that the CVE on the edge (or on the
    workload it enters) is exploited in the wild, from the CVE model
    trained on NVD + CISA KEV. A CVE adds an independent second way across
    the edge, so it can only raise P, never lower it.
"""

from __future__ import annotations

import math
from typing import Any

from .techniques import WORKLOADS, categorize_edge

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

P_MIN, P_MAX = 0.01, 0.995   # keeps weights finite and > 0


def probability_to_weight(p: float) -> float:
    return -math.log(min(max(p, P_MIN), P_MAX))


def combine(prior: float, p_exploit: float | None) -> float:
    if p_exploit is None:
        return prior
    return 1.0 - (1.0 - prior) * (1.0 - p_exploit)


class LearnedEdgeWeights:
    """Scores edges of a ClusterGraph with learned traversal probabilities."""

    def __init__(self, allow_network: bool = False):
        from .cve_model import CVEExploitPredictor

        self.cve = CVEExploitPredictor(allow_network=allow_network)

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
    ) -> dict[str, Any]:
        category = categorize_edge(src_type, relationship, tgt_type)
        prior = EDGE_PRIORS.get(category, EDGE_PRIORS["other"])

        candidates: list[tuple[str | None, float | None]] = [(edge_cve, edge_cvss)]
        # A vulnerable workload is reachable through any edge that enters it.
        if (tgt_type or "").lower() in WORKLOADS:
            candidates += [(c, None) for c in (target_cves or [])]
        best = self._best_cve(candidates)

        p = combine(prior, best["p_exploit"] if best else None)
        return {
            "category": category,
            "prior": prior,
            "p_exploit": best["p_exploit"] if best else None,
            "exploit_cve": best["cve"] if best else None,
            "exploit_evidence": best["evidence"] if best else None,
            "p_success": p,
            "weight": probability_to_weight(p),
        }


_instance: LearnedEdgeWeights | None = None


def get_learned_weights(allow_network: bool = False) -> LearnedEdgeWeights:
    """Shared instance (model loading takes ~1s)."""
    global _instance
    if _instance is None:
        _instance = LearnedEdgeWeights(allow_network=allow_network)
    return _instance


def models_available() -> bool:
    from .paths import CVE_MODEL_PATH

    return CVE_MODEL_PATH.exists()
