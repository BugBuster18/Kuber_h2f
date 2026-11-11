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

# Pods with this label are treated as attack entry points (sources).
ENTRY_POINT_LABEL = "kubeattackviz.io/entry-point"

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


# Kubernetes' own components. Excluded by default: the analysis targets the
# application attack surface (use include_system=True / --include-system to
# keep them).
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "local-path-storage"}
_BROAD_GROUPS = {"system:serviceaccounts", "system:authenticated", "system:unauthenticated"}


def scope_to_apps(inv: Inventory) -> Inventory:
    """Inventory restricted to application namespaces.

    ClusterRoles are all kept (bindings reference them). A ClusterRoleBinding
    is kept only if it can apply to an application identity: a ServiceAccount
    in an app namespace, that namespace's SA group, or a cluster-wide group
    every ServiceAccount belongs to (a binding to those IS an app risk).
    """
    from dataclasses import replace

    app_ns = {ns for ns in inv.namespaces if ns not in SYSTEM_NAMESPACES} | {
        p.namespace for p in inv.pods if p.namespace not in SYSTEM_NAMESPACES}

    def relevant_crb(binding) -> bool:
        # Bootstrap bindings managed by kubeadm / the API server itself.
        if binding.name.startswith(("system:", "kubeadm:")):
            return False
        for s in binding.subjects:
            if s.kind == "serviceaccount" and s.namespace in app_ns:
                return True
            if s.kind == "user" and not s.name.startswith("system:"):
                return True
            if s.kind == "group" and (s.name in _BROAD_GROUPS or (
                    s.name.startswith("system:serviceaccounts:") and s.name.split(":", 2)[2] in app_ns)):
                return True
        return False

    return replace(
        inv,
        namespaces={k: v for k, v in inv.namespaces.items() if k in app_ns},
        pods=[p for p in inv.pods if p.namespace in app_ns],
        services=[s for s in inv.services if s.namespace in app_ns],
        ingresses=[i for i in inv.ingresses if i.namespace in app_ns],
        service_accounts=[s for s in inv.service_accounts if s.namespace in app_ns],
        secrets=[s for s in inv.secrets if s[0] in app_ns],
        configmaps=[c for c in inv.configmaps if c[0] in app_ns],
        roles=[r for r in inv.roles if r.kind == "clusterrole" or r.namespace in app_ns],
        bindings=[b for b in inv.bindings if (b.kind == "rolebinding" and b.namespace in app_ns)
                  or (b.kind == "clusterrolebinding" and relevant_crb(b))],
        network_policies=[n for n in inv.network_policies if n.namespace in app_ns],
    )


def build_cluster_graph(inv: Inventory, include_system: bool = False) -> ClusterGraph:
    """Build the attack graph. By default scoped to application namespaces,
    with RBAC bindings kept only when they grant a sensitive permission,
    Services only when exposed, and isolated nodes dropped."""
    if not include_system:
        inv = scope_to_apps(inv)
    b = _Builder(inv)

    # ── Exposure: internet → LoadBalancer/NodePort services and ingresses ──
    exposed_services = {(s.namespace, s.name) for s in inv.services if s.type in ("LoadBalancer", "NodePort")}
    if exposed_services or inv.ingresses:
        b.node("externalactor", None, "internet", source=True)
    # Services are folded into the edge they enable (internet → pod "via
    # Service X"): the Service hop itself is a configuration fact with no
    # uncertainty, so a separate node adds size but no information.
    ingress_ids = {}
    for ing in inv.ingresses:
        iid = b.node("ingress", ing.namespace, ing.name)
        ingress_ids[(ing.namespace, ing.name)] = iid
        b.edge(INTERNET_ID, iid, "exposes", f"Ingress {ing.namespace}/{ing.name}", {"service_type": "Ingress"})

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
        entry = pod.labels.get(ENTRY_POINT_LABEL)
        if entry is not None:
            # Declared in the manifests: this workload is a place an attacker
            # can start (e.g. a CI runner executing third-party code).
            b.nodes[pid].is_source = True
            b.nodes[pid].properties["entry_point"] = entry or "declared"

    # Internal (ClusterIP) Services add no attack hop: in-cluster
    # reachability is modelled pod-to-pod (connects_to) below.
    for (ns, name), pods in service_targets.items():
        svc = next(s for s in inv.services if s.namespace == ns and s.name == name)
        entries = []
        if (ns, name) in exposed_services:
            entries.append((INTERNET_ID, "exposes", f"via Service {ns}/{name} (type {svc.type})"))
        for ing in inv.ingresses:
            if ing.namespace == ns and name in ing.backend_services:
                entries.append((ingress_ids[(ing.namespace, ing.name)], "routes_to", f"via Service {ns}/{name}"))
        for src_id, rel, evidence in entries:
            for pod in pods:
                pid = pod_ids[(pod.namespace, pod.name)]
                b.edge(src_id, pid, rel, evidence,
                       {"feasibility": "conditional", "service_type": svc.type, "service": f"{ns}/{name}",
                        "ports": svc.ports,
                        **{k: v for k, v in b.nodes[pid].properties.items() if k not in ("images",)}})

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
            # Kubernetes documents privileged containers as having host-level
            # access by design (PSS: "Privileged Pods disable most security
            # mechanisms"), so that case is decided by configuration. Other
            # baseline violations weaken isolation without deciding the outcome.
            b.edge(pod_ids[(pod.namespace, pod.name)], nid, "host_access",
                   "PSS baseline violations: " + ", ".join(ha.baseline_violations),
                   {**b.nodes[pod_ids[(pod.namespace, pod.name)]].properties,
                    "feasibility": "exact" if ha.privileged else "conditional"})

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

    # ── RBAC: identity → binding → role, binding → granted objects ───────
    # Identities: ServiceAccounts, and human Users named in bindings. A User
    # is an entry point (source): a compromised developer/operator
    # credential grants exactly what RBAC allows that User.
    admin_roles = set()
    for role in inv.roles:
        if role.kind == "clusterrole" and any(
            "*" in r.verbs and "*" in r.resources and "*" in r.api_groups for r in role.rules
        ):
            admin_roles.add(role.name)

    sa_keys = {(sa.namespace, sa.name) for sa in inv.service_accounts} | {
        (p.namespace, p.service_account) for p in inv.pods}
    users = sorted({s.name for bd in inv.bindings for s in bd.subjects
                    if s.kind == "user" and not s.name.startswith("system:")})
    identities = [("serviceaccount", ns, n) for ns, n in sorted(sa_keys)] + [("user", None, u) for u in users]

    for id_kind, id_ns, id_name in identities:
        grants = rbac.grants_for(inv, id_ns, id_name, kind=id_kind)
        if not grants:
            continue
        said = node_id(id_kind, id_ns, id_name)
        by_binding: dict[tuple, list[rbac.Grant]] = defaultdict(list)
        for g in grants:
            by_binding[(g.binding.kind, g.binding.namespace, g.binding.name)].append(g)

        for (bkind, bns, bname), gs in by_binding.items():
            bid = node_id(bkind, bns, bname)
            role = gs[0].role
            is_admin = role.kind == "clusterrole" and role.name in admin_roles
            scope = gs[0].scope
            permission_edges = []        # created only if the binding grants something sensitive

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
                        if id_kind == "serviceaccount" and (tns, tname) == (id_ns, id_name):
                            continue
                        rel = {"create_sa_tokens": "can_create_token",
                               "impersonate_sa": "can_impersonate"}.get(perm, "can_run_as")
                    permission_edges.append((target_kind, tns, tname, rel,
                                             f"{perm} via {role.kind}/{role.name}", perm_features(perm, matched)))

            if not permission_edges and not is_admin:
                continue              # grants nothing an attacker could use: not part of the attack graph
            b.node(id_kind, id_ns, id_name, source=(id_kind == "user"),
                   props={"entry_point": "compromised user credential"} if id_kind == "user" else None)
            b.node(bkind, bns, bname)
            rid = b.node(role.kind, role.namespace, role.name, sink=is_admin,
                         bump_i=3.5 if is_admin else 0.0)   # cluster-admin = full control (impact 10)
            b.edge(said, bid, "bound_to", f"Subject of {bkind} {bname}",
                   {"binding_scope": "cluster" if scope is None else "namespace"})
            b.edge(bid, rid, "grants", f"roleRef {role.kind}/{role.name}",
                   {"binding_scope": "cluster" if scope is None else "namespace",
                    "role_has_wildcard": any("*" in r.verbs or "*" in r.resources for r in role.rules)})
            for target_kind, tns, tname, rel, evidence, feats in permission_edges:
                tid = b.node(target_kind, tns, tname,
                             sink=target_kind in ("secret", "node") or (target_kind == "clusterrole"))
                b.edge(bid, tid, rel, evidence, feats)

    return _prune(b, prune_dead_ends=not include_system)


def _prune(b: "_Builder", prune_dead_ends: bool) -> ClusterGraph:
    """Drop nodes that cannot be on any source → sink attack path.

    Isolated nodes are always dropped. With prune_dead_ends, non-target nodes
    with nowhere to go (e.g. a ServiceAccount with no permissions) are
    removed iteratively — they can be reached but lead to nothing of value.
    """
    nodes = dict(b.nodes)
    edges = list(b.edges.values())
    while prune_dead_ends:
        out_degree: dict[str, int] = defaultdict(int)
        for e in edges:
            out_degree[e.source] += 1
        dead = {nid for nid, n in nodes.items() if not n.is_sink and out_degree[nid] == 0}
        if not dead:
            break
        for nid in dead:
            nodes.pop(nid)
        edges = [e for e in edges if e.source in nodes and e.target in nodes]
    connected = {e.source for e in edges} | {e.target for e in edges}
    return ClusterGraph(nodes=[n for nid, n in nodes.items() if nid in connected], edges=edges)
