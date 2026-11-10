"""
Kubernetes resource model and exact feasibility engine.

  inventory.py   raw `kubectl get -o json` output → typed resources
                 (Secrets are read as metadata only — values never fetched)
  selectors.py   label selector matching (matchLabels / matchExpressions)
  rbac.py        RBAC evaluation: what can a subject do, in which scope
  netpol.py      NetworkPolicy pod-to-pod reachability
  podsec.py      pod host-access properties (privileged, hostPath, caps …)
  graph.py       inventory → ClusterGraph with per-edge features + evidence

Everything here is deterministic: it answers "is this transition allowed by
the cluster's configuration?" exactly, the way the API server / network
plugin would. Learned models are only used where configuration cannot
decide the outcome (see kube_attack_viz/ml).
"""
