"""
Scenario generation for lab experiments.

A scenario is a list of Kubernetes objects. Configurations are randomized
over the dimensions the feasibility engine models — RBAC rules (wildcards,
subresources, resourceNames), binding scope and subject kinds (SA, SA
groups), NetworkPolicies (default-deny, AND/OR peers, ports, egress) and
token automount at pod and ServiceAccount level. Outcomes are NOT generated:
they are measured on the cluster (groundtruth.py).

Every pod runs `busybox httpd` on PROBE_PORT so reachability can be probed.
All objects carry the label LAB_LABEL=<scenario> for teardown.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

from .kube import LAB_LABEL

PROBE_PORT = 8080
OTHER_PORT = 9090
IMAGE = "busybox:1.36"


def _meta(name: str, scenario: str, ns: str | None = None, labels: dict | None = None) -> dict:
    m: dict[str, Any] = {"name": name, "labels": {LAB_LABEL: scenario, **(labels or {})}}
    if ns:
        m["namespace"] = ns
    return m


def pod_manifest(scenario, ns, name, labels, sa, *, automount=None, security_context=None,
                 host_network=False, secret_volumes=()) -> dict:
    container = {
        "name": "app", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["sh", "-c", f"mkdir -p /tmp/www && echo ok > /tmp/www/index.html && "
                                f"exec httpd -f -p {PROBE_PORT} -h /tmp/www"],
        "ports": [{"containerPort": PROBE_PORT}],
        "readinessProbe": {"tcpSocket": {"port": PROBE_PORT}, "periodSeconds": 2},
    }
    if security_context:
        container["securityContext"] = security_context
    spec: dict[str, Any] = {"serviceAccountName": sa, "containers": [container],
                            "terminationGracePeriodSeconds": 0}
    if automount is not None:
        spec["automountServiceAccountToken"] = automount
    if host_network:
        spec["hostNetwork"] = True
    if secret_volumes:
        spec["volumes"] = [{"name": f"s{i}", "secret": {"secretName": s}} for i, s in enumerate(secret_volumes)]
        container["volumeMounts"] = [{"name": f"s{i}", "mountPath": f"/secrets/{i}"} for i in range(len(secret_volumes))]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": _meta(name, scenario, ns, labels), "spec": spec}


# ─── Randomized scenarios ────────────────────────────────────────────────────

_APPS = ["web", "api", "db", "worker"]
_TEAMS = ["red", "blue"]


def _rule_pool(secret_names: list[str]) -> list[dict]:
    return [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["list", "watch"]},
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"],
         "resourceNames": [random.choice(secret_names)]},
        {"apiGroups": ["*"], "resources": ["secrets"], "verbs": ["*"]},
        {"apiGroups": [""], "resources": ["*"], "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["pods", "pods/attach"], "verbs": ["create", "get"]},
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
        {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create", "patch"]},
        {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["serviceaccounts"], "verbs": ["impersonate"]},
        {"apiGroups": [""], "resources": ["nodes/proxy"], "verbs": ["get"]},
        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["bind"]},
        {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]},
    ]


def random_scenario(index: int, seed: int) -> dict[str, Any]:
    rng = random.Random(seed * 1000 + index)
    random.seed(seed * 1000 + index)      # _rule_pool uses module-level random
    sc = f"kav-s{index:03d}"
    nss = [f"{sc}-{x}" for x in "abc"]
    objects: list[dict] = []
    ns_team = {ns: rng.choice(_TEAMS) for ns in nss}

    for ns in nss:
        objects.append({"apiVersion": "v1", "kind": "Namespace",
                        "metadata": _meta(ns, sc, labels={"team": ns_team[ns]})})

    secrets, sas, pods = [], [], []
    host_network_used = False
    for ns in nss:
        for s in rng.sample(["db-creds", "api-key", "tls"], k=rng.randint(1, 3)):
            secrets.append((ns, s))
            objects.append({"apiVersion": "v1", "kind": "Secret", "metadata": _meta(s, sc, ns),
                            "type": "Opaque", "stringData": {"value": "lab-placeholder"}})
        for i in range(2):
            sa_name = f"sa-{i}"
            sas.append((ns, sa_name))
            sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": _meta(sa_name, sc, ns)}
            sa_auto = rng.choice([None, None, True, False])
            if sa_auto is not None:
                sa["automountServiceAccountToken"] = sa_auto
            objects.append(sa)
        for i in range(rng.randint(2, 3)):
            app = rng.choice(_APPS)
            name = f"{app}-{i}"
            host_net = (not host_network_used) and rng.random() < 0.08
            host_network_used = host_network_used or host_net
            pods.append((ns, name))
            objects.append(pod_manifest(
                sc, ns, name, {"app": app, "tier": rng.choice(["fe", "be"])}, f"sa-{rng.randint(0, 1)}",
                automount=rng.choice([None, None, True, False]),
                security_context={"runAsUser": rng.choice([0, 1000])},
                host_network=host_net,
                secret_volumes=[s for (sns, s) in secrets if sns == ns and rng.random() < 0.3],
            ))
        for app in _APPS:
            objects.append({"apiVersion": "v1", "kind": "Service", "metadata": _meta(app, sc, ns),
                            "spec": {"selector": {"app": app}, "ports": [{"port": PROBE_PORT}]}})

    # ── RBAC ──
    pool = _rule_pool([s for _, s in secrets])
    roles = []
    for ns in nss:
        for i in range(rng.randint(1, 2)):
            name = f"role-{i}"
            roles.append(("Role", ns, name))
            objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                            "metadata": _meta(name, sc, ns), "rules": rng.sample(pool, k=rng.randint(1, 3))})
    for i in range(2):
        name = f"{sc}-cr-{i}"
        roles.append(("ClusterRole", None, name))
        objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                        "metadata": _meta(name, sc), "rules": rng.sample(pool, k=rng.randint(1, 3))})

    def subject():
        kind = rng.choices(["sa", "sa-other-ns", "group-ns", "group-all"], weights=[5, 2, 2, 1])[0]
        ns, name = rng.choice(sas)
        if kind in ("sa", "sa-other-ns"):
            return {"kind": "ServiceAccount", "name": name, "namespace": ns}
        if kind == "group-ns":
            return {"kind": "Group", "name": f"system:serviceaccounts:{rng.choice(nss)}",
                    "apiGroup": "rbac.authorization.k8s.io"}
        return {"kind": "Group", "name": "system:serviceaccounts", "apiGroup": "rbac.authorization.k8s.io"}

    for i in range(rng.randint(3, 6)):
        kind, rns, rname = rng.choice(roles)
        subjects = [subject() for _ in range(rng.randint(1, 2))]
        if kind == "Role":
            objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                            "metadata": _meta(f"rb-{i}", sc, rns), "subjects": subjects,
                            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": rname}})
        elif rng.random() < 0.6:
            objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                            "metadata": _meta(f"rb-{i}", sc, rng.choice(nss)), "subjects": subjects,
                            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": rname}})
        else:
            objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                            "metadata": _meta(f"{sc}-crb-{i}", sc), "subjects": subjects,
                            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": rname}})

    # ── NetworkPolicies ──
    def peer():
        form = rng.choice(["pod", "ns", "ns+pod", "all-ns"])
        if form == "pod":
            return {"podSelector": {"matchLabels": {"app": rng.choice(_APPS)}}}
        if form == "ns":
            return {"namespaceSelector": {"matchLabels": {"team": rng.choice(_TEAMS)}}}
        if form == "ns+pod":
            return {"namespaceSelector": {"matchLabels": {"team": rng.choice(_TEAMS)}},
                    "podSelector": {"matchLabels": {"app": rng.choice(_APPS)}}}
        return {"namespaceSelector": {}}

    for ns in nss:
        if rng.random() < 0.5:
            objects.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                            "metadata": _meta("default-deny-ingress", sc, ns),
                            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}})
        if rng.random() < 0.2:
            objects.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                            "metadata": _meta("default-deny-egress", sc, ns),
                            "spec": {"podSelector": {}, "policyTypes": ["Egress"]}})
        for i in range(rng.randint(0, 2)):
            rule = {"from": [peer() for _ in range(rng.randint(1, 2))]}
            if rng.random() < 0.6:
                rule["ports"] = [{"port": rng.choice([PROBE_PORT, PROBE_PORT, OTHER_PORT])}]
            objects.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                            "metadata": _meta(f"allow-in-{i}", sc, ns),
                            "spec": {"podSelector": {"matchLabels": {"app": rng.choice(_APPS)}},
                                     "policyTypes": ["Ingress"], "ingress": [rule]}})
        if rng.random() < 0.25:
            objects.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                            "metadata": _meta("allow-egress", sc, ns),
                            "spec": {"podSelector": {"matchLabels": {"app": rng.choice(_APPS)}},
                                     "policyTypes": ["Egress"],
                                     "egress": [{"to": [peer()]}]}})

    order = {"Namespace": 0, "ServiceAccount": 1, "Secret": 1, "Role": 2, "ClusterRole": 2,
             "RoleBinding": 3, "ClusterRoleBinding": 3, "NetworkPolicy": 4, "Service": 5, "Pod": 6}
    objects.sort(key=lambda o: order.get(o["kind"], 9))
    return {"name": sc, "namespaces": nss, "objects": objects, "seed": seed, "index": index}


# ─── The hand-built lab fixture as a deployable scenario ────────────────────

def fixture_scenario() -> dict[str, Any]:
    """The k8s/fixtures lab cluster, made deployable.

    Lab remaps (recorded so results are interpretable): images → busybox
    httpd; nodeName dropped (scheduler places pods); PSA enforce labels
    dropped (otherwise admission rejects pods the fixture describes);
    runAsNonRoot pods get runAsUser 65534 (busybox defaults to root);
    host-level settings dropped (not measured); LoadBalancer → NodePort.
    """
    raw = json.loads((Path(__file__).resolve().parent.parent / "k8s" / "fixtures" / "lab-cluster.raw.json")
                     .read_text(encoding="utf-8"))
    sc = "kav-fixture"
    rename_ns = {ns: f"{sc}-{ns}" for ns in [i["metadata"]["name"] for i in raw["namespaces"]["items"]]}
    objects = []

    def ns_of(item):
        return rename_ns[item["metadata"]["namespace"]]

    for item in raw["namespaces"]["items"]:
        labels = {k: v for k, v in (item["metadata"].get("labels") or {}).items() if not k.startswith("pod-security")}
        objects.append({"apiVersion": "v1", "kind": "Namespace",
                        "metadata": _meta(rename_ns[item["metadata"]["name"]], sc, labels=labels)})
    for item in raw["serviceaccounts"]["items"]:
        if item["metadata"]["name"] == "default":
            continue
        objects.append({"apiVersion": "v1", "kind": "ServiceAccount",
                        "metadata": _meta(item["metadata"]["name"], sc, ns_of(item))})
    for item in raw["secrets"]["items"]:
        objects.append({"apiVersion": "v1", "kind": "Secret", "metadata": _meta(item["metadata"]["name"], sc, ns_of(item)),
                        "type": "Opaque", "stringData": {"value": "lab-placeholder"}})
    for kind, key in (("Role", "roles"), ("ClusterRole", "clusterroles")):
        for item in raw[key]["items"]:
            if kind == "ClusterRole" and item["metadata"]["name"] == "cluster-admin":
                continue                                    # built in
            name = item["metadata"]["name"] if kind == "Role" else f"{sc}-{item['metadata']['name']}"
            objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind,
                            "metadata": _meta(name, sc, ns_of(item) if kind == "Role" else None),
                            "rules": item["rules"]})

    def fix_subject(s):
        s = dict(s)
        if s.get("namespace"):
            s["namespace"] = rename_ns[s["namespace"]]
        if s["kind"] == "Group":
            for old, new in rename_ns.items():
                s["name"] = s["name"].replace(f":{old}", f":{new}")
            s["apiGroup"] = "rbac.authorization.k8s.io"
        return s

    def fix_ref(ref):
        if ref["kind"] == "ClusterRole" and ref["name"] != "cluster-admin":
            return {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": f"{sc}-{ref['name']}"}
        return {"apiGroup": "rbac.authorization.k8s.io", **ref}

    for item in raw["rolebindings"]["items"]:
        objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                        "metadata": _meta(item["metadata"]["name"], sc, ns_of(item)),
                        "subjects": [fix_subject(s) for s in item["subjects"]], "roleRef": fix_ref(item["roleRef"])})
    for item in raw["clusterrolebindings"]["items"]:
        objects.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                        "metadata": _meta(f"{sc}-{item['metadata']['name']}", sc),
                        "subjects": [fix_subject(s) for s in item["subjects"]], "roleRef": fix_ref(item["roleRef"])})
    for item in raw["networkpolicies"]["items"]:
        spec = json.loads(json.dumps(item["spec"]))
        objects.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                        "metadata": _meta(item["metadata"]["name"], sc, ns_of(item)), "spec": spec})
    for item in raw["services"]["items"]:
        spec = {k: v for k, v in item["spec"].items()}
        spec["ports"] = [{"port": PROBE_PORT}]
        if spec.get("type") == "LoadBalancer":
            spec["type"] = "NodePort"                       # kind has no LB controller
        objects.append({"apiVersion": "v1", "kind": "Service",
                        "metadata": _meta(item["metadata"]["name"], sc, ns_of(item)), "spec": spec})
    for item in raw["pods"]["items"]:
        spec = item["spec"]
        c = spec["containers"][0]
        # Host-level settings (privileged, hostPID, hostPath, added
        # capabilities) are not measured by the lab, so lab pods never run
        # with them; only user-identity settings are kept.
        sec = {k: v for k, v in (c.get("securityContext") or {}).items()
               if k in ("runAsUser", "runAsNonRoot", "allowPrivilegeEscalation")}
        if sec.get("runAsNonRoot") and "runAsUser" not in sec:
            sec["runAsUser"] = 65534
        objects.append(pod_manifest(
            sc, ns_of(item), item["metadata"]["name"], item["metadata"].get("labels") or {},
            spec.get("serviceAccountName", "default"), automount=spec.get("automountServiceAccountToken"),
            security_context=sec or None,
            secret_volumes=[v["secret"]["secretName"] for v in spec.get("volumes", []) if v.get("secret")],
        ))
    order = {"Namespace": 0, "ServiceAccount": 1, "Secret": 1, "Role": 2, "ClusterRole": 2,
             "RoleBinding": 3, "ClusterRoleBinding": 3, "NetworkPolicy": 4, "Service": 5, "Pod": 6}
    objects.sort(key=lambda o: order.get(o["kind"], 9))
    return {"name": sc, "namespaces": list(rename_ns.values()), "objects": objects, "seed": None, "index": -1}
