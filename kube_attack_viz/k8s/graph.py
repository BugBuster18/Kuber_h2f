"""
Inventory → ClusterGraph.

Every edge is created only when the cluster configuration allows the
transition (exact evaluation, see rbac.py / netpol.py / podsec.py). Each
edge records:
  * feasibility —
      "exact":       configuration fully decides the transition (RBAC grant,
                     mounted token or secret, exposure, ingress routing)
      "conditional": configuration permits the attempt, but success depends
                     on things configuration cannot decide — gaining a
                     foothold in a reachable workload, or crossing the host
                     boundary from a pod that violates PSS baseline. These
                     are the edges where learned probabilities apply.
  * evidence — the specific object(s) that make it possible
  * features — the security properties of the transition, used by the
    learned models (kube_attack_viz/ml) and never by the static weights
Static weights/risk scores are still filled in so `--weights static`
behaves exactly as before.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import ClusterGraph, EdgeData, NodeData
from . import rbac
from .inventory import Inventory, Pod
from .netpol import reachable
from .podsec import host_access, namespace_enforce_level, token_mounted

# Static weights (unchanged semantics: lower = easier). Only used by
# --weights static; the learned path never reads them.
STATIC_WEIGHTS = {
    "exposes": 2.5, "routes_to": 2.0, "runs_as": 2.0, "bound_to": 3.0, "grants": 4.0,
    "mounts": 3.5, "can_read": 3.0, "can_exec": 3.5, "can_run_as": 4.0,
    "can_create_token": 3.0, "can_impersonate": 3.0, "can_bind": 5.0,
    "can_proxy": 5.0, "host_access": 6.0, "connects_to": 2.0,
}
_STATIC_IMPACT = {"pod": 4.0, "service": 3.0, "ingress": 4.0, "serviceaccount": 5.0,
                  "role": 4.5, "clusterrole": 6.5, "rolebinding": 3.5, "clusterrolebinding": 6.0,
                  "secret": 9.0, "node": 9.0, "externalactor": 1.0, "configmap": 3.0}
_STATIC_LIKELIHOOD = {"pod": 2.0, "service": 3.0, "ingress": 5.0, "serviceaccount": 2.0,
                      "secret": 1.5, "node": 1.0, "externalactor": 10.0}

INTERNET_ID = "externalactor:cluster/internet"

# Transitions into a workload over the network, and across the host boundary:
# allowed by configuration, success not decidable from configuration.
CONDITIONAL_RELATIONSHIPS = {"connects_to", "host_access"}


def node_id(kind: str, namespace: str | None, name: str) -> str:
    return f"{kind}:{namespace or 'cluster'}/{name}"


def _static_risk(kind: str, bump_likelihood: float = 0.0, bump_impact: float = 0.0) -> tuple[float, float, float]:
    likelihood = min(10.0, _STATIC_LIKELIHOOD.get(kind, 1.0) + bump_likelihood)
    impact = min(10.0, _STATIC_IMPACT.get(kind, 3.0) + bump_impact)
    return (likelihood / 10.0) * impact, likelihood, impact


class _Builder:
    def __init__(self, inv: Inventory):
        self.inv = inv
        self.nodes: dict[str, NodeData] = {}
        self.edges: dict[tuple[str, str, str], EdgeData] = {}

    def node(self, kind, ns, name, *, source=False, sink=False, props=None, image=None,
             bump_l=0.0, bump_i=0.0) -> str:
        nid = node_id(kind, ns, name)
        if nid not in self.nodes:
            risk, l, i = _static_risk(kind, bump_l, bump_i)
            self.nodes[nid] = NodeData(
                id=nid, type=kind, name=name, namespace=ns or "cluster", risk_score=risk,
                likelihood=l, impact=i, is_source=source, is_sink=sink,
                image=image, properties=props or {},
            )
        else:
            n = self.nodes[nid]
            n.is_sink = n.is_sink or sink
            n.is_source = n.is_source or source
        return nid

    def edge(self, src, tgt, rel, evidence, features):
        key = (src, tgt, rel)
        if key in self.edges:                        # merge evidence from several grants
            e = self.edges[key]
            if evidence not in (e.evidence or ""):
                e.evidence = f"{e.evidence}; {evidence}"
            for k, v in features.items():
                if isinstance(v, list):
                    e.features[k] = sorted(set(e.features.get(k, [])) | set(v))
            return
        self.edges[key] = EdgeData(
            source=src, target=tgt, relationship=rel,
            weight=STATIC_WEIGHTS.get(rel, 3.0),
            features={"feasibility": "conditional" if rel in CONDITIONAL_RELATIONSHIPS else "exact",
                      **features},
            evidence=evidence,
        )


def _pod_features(inv: Inventory, pod: Pod, exposure: list[str]) -> dict:
    ha = host_access(pod)
    return {
        "privileged": ha.privileged,
        "run_as_root": ha.run_as_root,
        "allow_privilege_escalation": ha.allow_privilege_escalation,
        "host_pid": ha.host_pid, "host_ipc": ha.host_ipc, "host_network": ha.host_network,
        "host_path_mounts": ha.host_path_mounts,
        "non_baseline_capabilities": ha.non_baseline_capabilities,
        "pss_baseline_violations": ha.baseline_violations,
        "token_mounted": token_mounted(inv, pod),
        "namespace_psa_enforce": namespace_enforce_level(inv, pod.namespace),
        "exposure": sorted(set(exposure)),
        "images": pod.images,
    }


def build_cluster_graph(inv: Inventory) -> ClusterGraph:
    b = _Builder(inv)

    # ── Exposure: internet → LoadBalancer/NodePort services and ingresses ──
    exposed_services = {(s.namespace, s.name) for s in inv.services if s.type in ("LoadBalancer", "NodePort")}
    if exposed_services or inv.ingresses:
        b.node("externalactor", None, "internet", source=True)
    for s in inv.services:
        if (s.namespace, s.name) in exposed_services:
            sid = b.node("service", s.namespace, s.name)
            b.edge(INTERNET_ID, sid, "exposes", f"Service type {s.type}",
                   {"service_type": s.type, "ports": s.ports})
    for ing in inv.ingresses:
        iid = b.node("ingress", ing.namespace, ing.name)
        b.edge(INTERNET_ID, iid, "exposes", f"Ingress {ing.namespace}/{ing.name}", {"service_type": "Ingress"})
        for svc in ing.backend_services:
            if any(s.namespace == ing.namespace and s.name == svc for s in inv.services):
                b.edge(iid, b.node("service", ing.namespace, svc), "routes_to",
                       f"Ingress backend {svc}", {"service_type": "Ingress"})

    # ── Pods and what they expose ──────────────────────────────────────────
    from .selectors import matches_service_selector

    pod_exposure: dict[tuple[str, str], list[str]] = defaultdict(list)
    service_targets: dict[tuple[str, str], list[Pod]] = defaultdict(list)
    for s in inv.services:
        for pod in inv.pods:
            if pod.namespace == s.namespace and matches_service_selector(s.selector, pod.labels):
                service_targets[(s.namespace, s.name)].append(pod)
                ingress_backed = any(s.name in i.backend_services and i.namespace == s.namespace for i in inv.ingresses)
                pod_exposure[(pod.namespace, pod.name)].append(
                    "Ingress" if ingress_backed and s.type == "ClusterIP" else s.type)

    pod_ids: dict[tuple[str, str], str] = {}
    for pod in inv.pods:
        ha = host_access(pod)
        feats = _pod_features(inv, pod, pod_exposure.get((pod.namespace, pod.name), []))
        pid = b.node(
            "pod", pod.namespace, pod.name, image=(pod.images or [None])[0], props=feats,
            bump_l=(3.0 if ha.privileged else 0) + (3.0 if ha.host_network else 0) + (2.0 if ha.run_as_root else 0),
            bump_i=1.0 if ha.privileged else 0,
        )
        pod_ids[(pod.namespace, pod.name)] = pid

    for (ns, name), pods in service_targets.items():
        sid = b.node("service", ns, name)
        svc = next(s for s in inv.services if s.namespace == ns and s.name == name)
        for pod in pods:
            b.edge(sid, pod_ids[(pod.namespace, pod.name)], "routes_to",
                   f"Service selector {svc.selector}",
                   {"feasibility": "conditional", "service_type": svc.type, "ports": svc.ports,
                    **{k: v for k, v in b.nodes[pod_ids[(pod.namespace, pod.name)]].properties.items()
                       if k not in ("images",)}})

    # ── Pod → ServiceAccount (only if the token is actually mounted) ──────
    for pod in inv.pods:
        if token_mounted(inv, pod):
            said = b.node("serviceaccount", pod.namespace, pod.service_account)
            b.edge(pod_ids[(pod.namespace, pod.name)], said, "runs_as",
                   "ServiceAccount token auto-mounted", {"token_mounted": True})

    # ── Pod → Secret (volume or env reference) ────────────────────────────
    for pod in inv.pods:
        refs = set(pod.secret_volumes) | {r for c in pod.containers for r in c.secret_env_refs}
        for secret in sorted(refs):
            sec = b.node("secret", pod.namespace, secret, sink=True)
            how = "volume" if secret in pod.secret_volumes else "env"
            b.edge(pod_ids[(pod.namespace, pod.name)], sec, "mounts", f"Secret {how} reference",
                   {"secret_reference": how})

    # ── Pod → Node (PSS-baseline host-boundary violations) ────────────────
    for pod in inv.pods:
        ha = host_access(pod)
        if ha.breaks_host_boundary and pod.node_name:
            nid = b.node("node", None, pod.node_name, sink=True)
            b.edge(pod_ids[(pod.namespace, pod.name)], nid, "host_access",
                   "PSS baseline violations: " + ", ".join(ha.baseline_violations),
                   {**b.nodes[pod_ids[(pod.namespace, pod.name)]].properties})

    # ── Pod → Pod network reachability (targets = pods behind a Service) ──
    listening = {(p.namespace, p.name): p for pods in service_targets.values() for p in pods}
    for dst in listening.values():
        for src in inv.pods:
            if (src.namespace, src.name) == (dst.namespace, dst.name):
                continue
            r = reachable(inv, src, dst)
            if r.allowed:
                b.edge(pod_ids[(src.namespace, src.name)], pod_ids[(dst.namespace, dst.name)], "connects_to",
                       "NetworkPolicy allows" if (r.dst_ingress_isolated or r.src_egress_isolated)
                       else "No NetworkPolicy isolates either pod",
                       {"same_namespace": src.namespace == dst.namespace,
                        "dst_ingress_isolated": r.dst_ingress_isolated,
                        "src_egress_isolated": r.src_egress_isolated,
                        "allowing_policies": r.policies,
                        **{k: v for k, v in b.nodes[pod_ids[(dst.namespace, dst.name)]].properties.items()
                           if k not in ("images",)}})

    # ── RBAC: ServiceAccount → binding → role, binding → granted objects ──
    admin_roles = set()
    for role in inv.roles:
        if role.kind == "clusterrole" and any(
            "*" in r.verbs and "*" in r.resources and "*" in r.api_groups for r in role.rules
        ):
            admin_roles.add(role.name)

    sa_keys = {(sa.namespace, sa.name) for sa in inv.service_accounts} | {
        (p.namespace, p.service_account) for p in inv.pods}
    for sa_ns, sa_name in sorted(sa_keys):
        grants = rbac.grants_for(inv, sa_ns, sa_name)
        if not grants:
            continue
        said = b.node("serviceaccount", sa_ns, sa_name)
        by_binding: dict[tuple, list[rbac.Grant]] = defaultdict(list)
        for g in grants:
            by_binding[(g.binding.kind, g.binding.namespace, g.binding.name)].append(g)

        for (bkind, bns, bname), gs in by_binding.items():
            bid = b.node(bkind, bns, bname)
            role = gs[0].role
            is_admin = role.kind == "clusterrole" and role.name in admin_roles
            rid = b.node(role.kind, role.namespace, role.name, sink=is_admin,
                         bump_i=3.5 if is_admin else 0.0)   # cluster-admin = full control (impact 10)
            scope = gs[0].scope
            b.edge(said, bid, "bound_to", f"Subject of {bkind} {bname}",
                   {"binding_scope": "cluster" if scope is None else "namespace"})
            b.edge(bid, rid, "grants", f"roleRef {role.kind}/{role.name}",
                   {"binding_scope": "cluster" if scope is None else "namespace",
                    "role_has_wildcard": any("*" in r.verbs or "*" in r.resources for r in role.rules)})

            def perm_features(perm, matched):
                return {
                    "permission": [perm],
                    "binding_scope": "cluster" if scope is None else "namespace",
                    "via_wildcard": any("*" in g.rule.verbs or "*" in g.rule.resources for g in matched),
                    "restricted_by_resource_names": all(g.rule.resource_names for g in matched),
                }

            namespaces = [scope] if scope else sorted(inv.namespaces)
            for perm, verbs, resource, group, target_kind in rbac.SENSITIVE_PERMISSIONS:
                if target_kind == "secret":
                    targets = [(ns, n) for ns, n, _ in inv.secrets if ns in namespaces]
                elif target_kind == "pod":
                    targets = [(p.namespace, p.name) for p in inv.pods if p.namespace in namespaces]
                elif target_kind == "serviceaccount":
                    targets = sorted({k for k in sa_keys if k[0] in namespaces})
                elif target_kind == "clusterrole":
                    targets = [(None, r) for r in sorted(admin_roles)]
                elif target_kind == "node":
                    targets = [(None, n) for n in inv.nodes] if scope is None else []
                else:
                    targets = []
                for tns, tname in targets:
                    matched = [g for v in verbs
                               for g in rbac.allowed(gs, v, resource, group, tns, tname)]
                    if not matched:
                        continue
                    rel = {"secret": "can_read", "pod": "can_exec", "node": "can_proxy",
                           "clusterrole": "can_bind"}.get(target_kind)
                    if target_kind == "serviceaccount":
                        if (tns, tname) == (sa_ns, sa_name):
                            continue
                        rel = {"create_sa_tokens": "can_create_token",
                               "impersonate_sa": "can_impersonate"}.get(perm, "can_run_as")
                    tid = b.node(target_kind, tns, tname,
                                 sink=target_kind in ("secret", "node") or (target_kind == "clusterrole"))
                    b.edge(bid, tid, rel, f"{perm} via {role.kind}/{role.name}", perm_features(perm, matched))

    return ClusterGraph(nodes=list(b.nodes.values()), edges=list(b.edges.values()))
