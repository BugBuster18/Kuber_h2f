"""
Generate lab-cluster.raw.json — a small cluster in raw `kubectl get -o json`
format whose RBAC / NetworkPolicy / pod-security answers are known by
construction. Used by the built-in tests.

Layout
  shop      web-frontend (LoadBalancer + Ingress, token mounted, web-sa)
            checkout     (ClusterIP, automountServiceAccountToken: false)
            debug-pod    (privileged, hostPID, hostPath "/", on worker-1)
  payments  payments-api (mounts secret db-creds); NetworkPolicy:
            default-deny ingress + allow only shop/app=checkout
  ci        deployer SA bound to cluster-admin

RBAC
  web-sa          Role shop/config-reader: get/list secrets in shop
  payments-sa     ClusterRole secret-reader via RoleBinding in payments,
                  restricted to resourceNames [db-creds]
  group system:serviceaccounts:shop  ClusterRole pod-exec in shop
  ci/deployer     ClusterRoleBinding → cluster-admin

Run:  python -m kube_attack_viz.k8s.fixtures.make_lab_fixture
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).with_name("lab-cluster.raw.json")


def meta(name, ns=None, labels=None):
    m = {"name": name}
    if ns:
        m["namespace"] = ns
    if labels:
        m["labels"] = labels
    return m


def pod(name, ns, labels, sa, image, *, automount=None, node="worker-1", sc=None,
        host_pid=False, host_paths=(), secret_vols=(), env_secret=None):
    container = {"name": name, "image": image, "ports": [{"containerPort": 8080}]}
    if sc:
        container["securityContext"] = sc
    if env_secret:
        container["env"] = [{"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": env_secret, "key": "t"}}}]
    spec = {"serviceAccountName": sa, "nodeName": node, "containers": [container],
            "volumes": [{"name": f"h{i}", "hostPath": {"path": p}} for i, p in enumerate(host_paths)]
            + [{"name": f"s{i}", "secret": {"secretName": s}} for i, s in enumerate(secret_vols)]}
    if automount is not None:
        spec["automountServiceAccountToken"] = automount
    if host_pid:
        spec["hostPID"] = True
    return {"metadata": meta(name, ns, labels), "spec": spec}


def lst(items):
    return {"apiVersion": "v1", "kind": "List", "items": items}


raw = {
    "namespaces": lst([
        {"metadata": meta("shop", labels={"team": "shop"})},
        {"metadata": meta("payments", labels={"team": "payments",
                                              "pod-security.kubernetes.io/enforce": "restricted"})},
        {"metadata": meta("ci")},
        {"metadata": meta("kube-system")},
    ]),
    "nodes": lst([{"metadata": meta("worker-1")}]),
    "pods": lst([
        pod("web-frontend", "shop", {"app": "web"}, "web-sa", "nginx:1.25.3",
            sc={"runAsNonRoot": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}),
        pod("checkout", "shop", {"app": "checkout"}, "checkout-sa", "shop/checkout:2.1",
            automount=False, sc={"runAsUser": 1000}),
        pod("debug-pod", "shop", {"app": "debug"}, "default", "busybox:1.36",
            sc={"privileged": True}, host_pid=True, host_paths=["/"]),
        pod("payments-api", "payments", {"app": "payments"}, "payments-sa", "payments/api:4.0",
            secret_vols=["db-creds"], sc={"runAsUser": 0, "capabilities": {"add": ["NET_ADMIN"]}}),
        pod("deployer-runner", "ci", {"app": "runner"}, "deployer", "ci/runner:1.0", env_secret="registry-token"),
    ]),
    "services": lst([
        {"metadata": meta("web", "shop"), "spec": {"type": "LoadBalancer", "selector": {"app": "web"},
                                                   "ports": [{"port": 80}]}},
        {"metadata": meta("checkout", "shop"), "spec": {"type": "ClusterIP", "selector": {"app": "checkout"},
                                                        "ports": [{"port": 8080}]}},
        {"metadata": meta("payments", "payments"), "spec": {"type": "ClusterIP", "selector": {"app": "payments"},
                                                            "ports": [{"port": 8080}]}},
    ]),
    "ingresses": lst([
        {"metadata": meta("shop-ingress", "shop"), "spec": {"rules": [{"http": {"paths": [
            {"path": "/", "backend": {"service": {"name": "web", "port": {"number": 80}}}}]}}]}},
    ]),
    "serviceaccounts": lst([
        {"metadata": meta("web-sa", "shop")},
        {"metadata": meta("checkout-sa", "shop")},
        {"metadata": meta("default", "shop")},
        {"metadata": meta("payments-sa", "payments")},
        {"metadata": meta("deployer", "ci")},
    ]),
    # Metadata only, as fetch_raw_state() returns them — no data fields.
    "secrets": lst([
        {"metadata": meta("web-tls", "shop"), "type": "kubernetes.io/tls"},
        {"metadata": meta("db-creds", "payments"), "type": "Opaque"},
        {"metadata": meta("api-key", "payments"), "type": "Opaque"},
        {"metadata": meta("registry-token", "ci"), "type": "Opaque"},
        {"metadata": meta("bootstrap", "kube-system"), "type": "Opaque"},
    ]),
    "configmaps": lst([]),
    "roles": lst([
        {"metadata": meta("config-reader", "shop"),
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]},
    ]),
    "clusterroles": lst([
        {"metadata": meta("secret-reader"),
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"], "resourceNames": ["db-creds"]}]},
        {"metadata": meta("pod-exec"),
         "rules": [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
                   {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]},
        {"metadata": meta("cluster-admin"),
         "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
    ]),
    "rolebindings": lst([
        {"metadata": meta("web-config", "shop"), "roleRef": {"kind": "Role", "name": "config-reader"},
         "subjects": [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "shop"}]},
        {"metadata": meta("payments-read", "payments"), "roleRef": {"kind": "ClusterRole", "name": "secret-reader"},
         "subjects": [{"kind": "ServiceAccount", "name": "payments-sa", "namespace": "payments"}]},
        {"metadata": meta("shop-debug-exec", "shop"), "roleRef": {"kind": "ClusterRole", "name": "pod-exec"},
         "subjects": [{"kind": "Group", "name": "system:serviceaccounts:shop"}]},
    ]),
    "clusterrolebindings": lst([
        {"metadata": meta("ci-admin"), "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
         "subjects": [{"kind": "ServiceAccount", "name": "deployer", "namespace": "ci"}]},
    ]),
    "networkpolicies": lst([
        {"metadata": meta("default-deny", "payments"),
         "spec": {"podSelector": {}, "policyTypes": ["Ingress"]}},
        {"metadata": meta("allow-checkout", "payments"),
         "spec": {"podSelector": {"matchLabels": {"app": "payments"}}, "policyTypes": ["Ingress"],
                  "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"team": "shop"}},
                                         "podSelector": {"matchLabels": {"app": "checkout"}}}],
                               "ports": [{"port": 8080}]}]}},
    ]),
}

if __name__ == "__main__":
    OUT.write_text(json.dumps(raw, indent=1), encoding="utf-8")
    print(f"wrote {OUT}")
