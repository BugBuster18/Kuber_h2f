"""
Controlled experiments: validate the feasibility engine against a real
Kubernetes API server and network plugin.

  kube.py         kubectl wrapper pinned to a local kind-* context (refuses others)
  scenarios.py    generates valid, randomized cluster configurations
  groundtruth.py  measures outcomes on the cluster:
                    RBAC      — SubjectAccessReview (the API server's authorizer)
                    network   — HTTP probes between pods (the CNI's enforcement)
                    tokens    — whether the API server injected the SA token
  runner.py       apply → wait → scan with the engine → measure → compare → teardown
  report.py       precision / recall / F1 / confusion matrices per edge type

The configurations are generated; every label is MEASURED on the cluster.
Probes only check authorization decisions and TCP/HTTP reachability; nothing
is exploited.
"""
