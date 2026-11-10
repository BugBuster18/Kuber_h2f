"""Built-in tests for the exact feasibility engine (run via `run-tests`)."""

from __future__ import annotations

import json
from pathlib import Path

FIXTURE = Path(__file__).with_name("fixtures") / "lab-cluster.raw.json"


def _lab():
    from .inventory import parse_inventory
    return parse_inventory(json.loads(FIXTURE.read_text(encoding="utf-8")))


def _pod(inv, ns, name):
    return next(p for p in inv.pods if p.namespace == ns and p.name == name)


def run_k8s_tests(result) -> None:
    from . import rbac
    from .netpol import reachable
    from .podsec import host_access, token_mounted
    from .selectors import matches

    # ── Label selectors ──────────────────────────────────────────────────────
    try:
        assert matches(None, {"a": "1"}) is False, "nil selector matches nothing"
        assert matches({}, {"a": "1"}) is True, "empty selector matches everything"
        sel = {"matchLabels": {"app": "web"},
               "matchExpressions": [{"key": "tier", "operator": "In", "values": ["fe", "be"]},
                                    {"key": "legacy", "operator": "DoesNotExist"}]}
        assert matches(sel, {"app": "web", "tier": "fe"})
        assert not matches(sel, {"app": "web", "tier": "db"})
        assert not matches(sel, {"app": "web", "tier": "fe", "legacy": "y"})
        assert matches({"matchExpressions": [{"key": "x", "operator": "NotIn", "values": ["1"]}]}, {})
        result.ok("Label selectors: nil/empty, matchLabels, In/NotIn/Exists/DoesNotExist")
    except AssertionError as e:
        result.fail("Label selectors", str(e))

    inv = _lab()

    # ── RBAC evaluation ──────────────────────────────────────────────────────
    try:
        web = rbac.grants_for(inv, "shop", "web-sa")
        assert rbac.allowed(web, "get", "secrets", "", "shop", "web-tls"), "Role grants secrets in its ns"
        assert not rbac.allowed(web, "get", "secrets", "", "payments", "db-creds"), "Role must not leak across ns"

        pay = rbac.grants_for(inv, "payments", "payments-sa")
        assert rbac.allowed(pay, "get", "secrets", "", "payments", "db-creds"), "resourceNames allows named secret"
        assert not rbac.allowed(pay, "get", "secrets", "", "payments", "api-key"), "resourceNames blocks others"
        assert not rbac.allowed(pay, "list", "secrets", "", "payments"), "resourceNames never allows list"
        assert not rbac.allowed(pay, "get", "secrets", "", "shop", "db-creds"), "ClusterRole via RoleBinding is ns-scoped"

        # Group subject system:serviceaccounts:shop
        checkout = rbac.grants_for(inv, "shop", "checkout-sa")
        assert rbac.allowed(checkout, "create", "pods/exec", "", "shop"), "group binding applies to SA"
        assert not rbac.allowed(checkout, "create", "pods/exec", "", "payments")
        assert not rbac.grants_for(inv, "payments", "default"), "other ns SAs not in the shop group"

        # Cluster-scoped resources are never granted by a RoleBinding
        assert not rbac.allowed(checkout, "get", "nodes/proxy", "", None)
        dep = rbac.grants_for(inv, "ci", "deployer")
        assert rbac.is_cluster_admin_equivalent(dep)
        assert rbac.allowed(dep, "get", "nodes/proxy", "", None)
        assert rbac.allowed(dep, "get", "secrets", "", "kube-system", "bootstrap")
        assert not rbac.is_cluster_admin_equivalent(web)
        result.ok("RBAC: ns scoping, resourceNames, group subjects, cluster-scoped rules, wildcards")
    except (AssertionError, StopIteration) as e:
        result.fail("RBAC evaluation", str(e))

    # ── NetworkPolicy reachability ───────────────────────────────────────────
    try:
        web_fe, checkout_p, pay_api = _pod(inv, "shop", "web-frontend"), _pod(inv, "shop", "checkout"), \
            _pod(inv, "payments", "payments-api")
        r = reachable(inv, web_fe, pay_api, 8080)
        assert not r.allowed and r.dst_ingress_isolated, "default-deny must block web-frontend"
        r = reachable(inv, checkout_p, pay_api, 8080)
        assert r.allowed and "allow-checkout" in r.policies, "ns+pod selector (AND) must allow checkout"
        assert not reachable(inv, checkout_p, pay_api, 9999).allowed, "port not in rule must be blocked"
        assert reachable(inv, pay_api, web_fe).allowed, "un-isolated destination allows all"

        # Egress isolation on the source side
        from .inventory import NetworkPolicy
        inv.network_policies.append(NetworkPolicy(
            namespace="shop", name="deny-egress", pod_selector={"matchLabels": {"app": "checkout"}},
            policy_types=["Egress"], ingress=[], egress=[]))
        r = reachable(inv, checkout_p, pay_api, 8080)
        assert not r.allowed and r.src_egress_isolated, "egress default-deny must block"
        inv.network_policies.pop()
        result.ok("NetworkPolicy: default-deny, ns+pod AND peers, ports, egress isolation")
    except (AssertionError, StopIteration) as e:
        result.fail("NetworkPolicy reachability", str(e))

    # ── Pod security / token mounting ────────────────────────────────────────
    try:
        dbg = host_access(_pod(inv, "shop", "debug-pod"))
        assert dbg.baseline_violations == ["privileged", "hostPID", "hostPath"], dbg.baseline_violations
        web_ha = host_access(_pod(inv, "shop", "web-frontend"))
        assert not web_ha.breaks_host_boundary and web_ha.run_as_root is False
        pay_ha = host_access(_pod(inv, "payments", "payments-api"))
        assert pay_ha.non_baseline_capabilities == ["NET_ADMIN"] and pay_ha.run_as_root is True
        assert token_mounted(inv, _pod(inv, "shop", "checkout")) is False, "pod automount=false wins"
        assert token_mounted(inv, _pod(inv, "shop", "web-frontend")) is True, "default is mounted"
        result.ok("Pod security: PSS-baseline violations, root, capabilities, token automount precedence")
    except (AssertionError, StopIteration) as e:
        result.fail("Pod security properties", str(e))

    # ── Graph built from the lab cluster ─────────────────────────────────────
    try:
        from ..graph_builder import build_attack_graph
        from ..algorithms.dijkstra import shortest_attack_path
        from .graph import build_cluster_graph

        cg = build_cluster_graph(inv)
        E = {(e.source, e.target, e.relationship): e for e in cg.edges}
        assert ("pod:shop/checkout", "serviceaccount:shop/checkout-sa", "runs_as") not in E, \
            "no runs_as edge when token is not mounted"
        assert ("pod:shop/web-frontend", "pod:payments/payments-api", "connects_to") not in E, \
            "no network edge where NetworkPolicy denies"
        assert ("rolebinding:payments/payments-read", "secret:payments/api-key", "can_read") not in E
        assert ("rolebinding:payments/payments-read", "secret:payments/db-creds", "can_read") in E
        host = E[("pod:shop/debug-pod", "node:cluster/worker-1", "host_access")]
        assert host.features["feasibility"] == "exact" and "privileged" in host.evidence, \
            "privileged pod → node is decided by configuration"
        weak = E[("pod:payments/payments-api", "node:cluster/worker-1", "host_access")]
        assert weak.features["feasibility"] == "conditional", "NET_ADMIN alone is not decisive"
        assert E[("rolebinding:shop/web-config", "secret:shop/web-tls", "can_read")].features["feasibility"] == "exact"

        G = build_attack_graph(cg, weight_mode="static")
        path = shortest_attack_path(G, "externalactor:cluster/internet", "secret:payments/db-creds")
        assert path is not None and "pod:shop/checkout" in path.path_nodes, \
            f"path to db-creds must go via checkout: {path and path.path_names}"
        result.ok(f"Lab graph: exact edges only where allowed; db-creds path = {' → '.join(path.path_names)}")
    except (AssertionError, KeyError, StopIteration) as e:
        result.fail("Lab cluster graph", str(e))

    # ── Secrets are never fetched with values ────────────────────────────────
    try:
        from .. import ingestion
        calls = []

        def fake_kubectl(args):
            calls.append(args)
            if args[:2] == ["get", "secrets"]:
                return "shop  web-tls  kubernetes.io/tls\n"
            return json.dumps({"items": []})

        original = ingestion._kubectl
        ingestion._kubectl = fake_kubectl
        try:
            raw = ingestion.fetch_raw_state()
        finally:
            ingestion._kubectl = original
        secret_calls = [a for a in calls if a[:2] == ["get", "secrets"]]
        assert secret_calls and all("json" not in " ".join(a) for a in secret_calls), secret_calls
        assert any(a.startswith("custom-columns=") for a in secret_calls[0])
        assert raw["secrets"]["items"][0] == {"metadata": {"namespace": "shop", "name": "web-tls"},
                                              "type": "kubernetes.io/tls"}
        # Even a full Secret object passed in never exposes data downstream
        from .inventory import parse_inventory
        inv2 = parse_inventory({"secrets": {"items": [
            {"metadata": {"namespace": "a", "name": "s"}, "type": "Opaque", "data": {"k": "c2VjcmV0"}}]}})
        assert inv2.secrets == [("a", "s", "Opaque")]
        result.ok("Secrets: fetched as metadata only (custom-columns), values never parsed")
    except AssertionError as e:
        result.fail("Secret metadata-only ingestion", str(e))

    # ── Parallel edges & round-trip ──────────────────────────────────────────
    try:
        from ..graph_builder import build_attack_graph
        from ..models import ClusterGraph, EdgeData, NodeData

        cg = ClusterGraph(
            nodes=[NodeData(id="a", type="rolebinding", name="a", namespace="n", risk_score=1, is_source=True),
                   NodeData(id="b", type="serviceaccount", name="b", namespace="n", risk_score=1,
                            is_sink=True, impact=7.0, properties={"x": 1})],
            edges=[EdgeData(source="a", target="b", relationship="can_run_as", weight=4.0),
                   EdgeData(source="a", target="b", relationship="can_impersonate", weight=3.0,
                            features={"permission": ["impersonate_sa"]}, evidence="test")],
        )
        G = build_attack_graph(cg, weight_mode="static")
        e = G.edges["a", "b"]
        assert e["relationship"] == "can_impersonate" and e["weight"] == 3.0, "easiest edge must win"
        assert [x["relationship"] for x in e["alternatives"]] == ["can_run_as"]
        back = ClusterGraph.from_dict(json.loads(json.dumps(cg.to_dict())))
        assert back.nodes[1].impact == 7.0 and back.nodes[1].properties == {"x": 1}
        assert back.edges[1].features == {"permission": ["impersonate_sa"]} and back.edges[1].evidence == "test"
        result.ok("Graph: easiest parallel edge kept (+alternatives); impact/features/evidence round-trip")
    except (AssertionError, KeyError) as e:
        result.fail("Parallel edges / round-trip", str(e))
