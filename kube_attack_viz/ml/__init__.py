"""
Learned edge weights for KubeAttackViz.

Each edge gets a traversal probability and weight = -ln P(success), so
Dijkstra's minimum-cost path is the most probable path and
P(path) = exp(-total_cost).

    P(edge) = 1 - (1 - prior[category]) * (1 - p_exploit)

  * p_exploit — LEARNED by the CVE exploitation model (cve_model.py),
    trained on real data: NVD CVE records (features) + CISA Known
    Exploited Vulnerabilities catalog (labels).
  * prior[category] — documented per-category assumptions (weights.py);
    edges are categorized by techniques.py.

Pipeline: datasets.py (download) → cve_features.py → cve_model.py (train /
predict) → weights.py (edge weights) → model_card.py (provenance + metrics).
"""

ML_VERSION = "1.0.0"
