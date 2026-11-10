"""
Normalize graph edges into a small set of edge categories for risk scoring.

Relationship names in cluster graphs are free-form ("routes_to", "routes-to",
"bound_to", "can-read", ...). The edge model never sees raw relationship
strings; each edge is mapped from (source type, relationship, target type)
to one category below, so unseen spellings still get a sensible score.
"""

from __future__ import annotations

WORKLOADS = {"pod", "deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob"}
ENTRYPOINTS = {"externalactor", "ingress", "service", "loadbalancer"}
IDENTITIES = {"serviceaccount", "user", "group"}
RBAC_OBJECTS = {"role", "clusterrole", "rolebinding", "clusterrolebinding"}
CONFIG_STORES = {"secret", "configmap"}
DATA_STORES = {"database", "persistentvolume", "persistentvolumeclaim"}
INFRA = {"node"}
SCOPES = {"namespace"}

CATEGORIES = [
    "endpoint_reachability",   # reaching an exposed ingress/service
    "workload_entry",          # entering a workload from an exposed endpoint
    "workload_to_workload",    # moving between workloads inside the cluster
    "identity_use",            # workload acting as its ServiceAccount
    "rbac_binding",            # identity/binding linked to a role
    "permission_use",          # role permission applied to a resource
    "config_access",           # reading a Secret / ConfigMap
    "data_store_access",       # reaching a database / volume
    "infrastructure_access",   # reaching a cluster node
    "scope_control",           # control over a namespace
    "workload_control",        # controller creating/owning workloads
    "other",
]

_CONTROL_RELS = {"creates", "owns", "manages", "controls"}


def normalize_relationship(rel: str | None) -> str:
    return (rel or "").strip().lower().replace("-", "_").replace(" ", "_")


def categorize_edge(src_type: str | None, rel: str | None, tgt_type: str | None) -> str:
    s = (src_type or "").lower()
    t = (tgt_type or "").lower()
    r = normalize_relationship(rel)

    if t in WORKLOADS:
        if s in ENTRYPOINTS:
            return "workload_entry"
        if r in _CONTROL_RELS:
            return "workload_control"
        if s in WORKLOADS or s == "serviceaccount":
            return "workload_to_workload"
        if s in IDENTITIES or s in RBAC_OBJECTS:
            return "permission_use"
        return "other"
    if t in ENTRYPOINTS:
        return "endpoint_reachability"
    if t in IDENTITIES:
        return "identity_use"
    if t in RBAC_OBJECTS:
        return "rbac_binding"
    if t in CONFIG_STORES:
        return "config_access"
    if t in DATA_STORES:
        return "data_store_access"
    if t in INFRA:
        return "infrastructure_access"
    if t in SCOPES:
        return "scope_control"
    return "other"
