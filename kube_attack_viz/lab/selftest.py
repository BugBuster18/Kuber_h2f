"""Built-in tests for the lab harness (no cluster needed)."""

from __future__ import annotations

import json


def run_lab_tests(result) -> None:
    from .groundtruth import _json_stream
    from .kube import LAB_LABEL, Kube, LabSafetyError
    from .report import confusion
    from .runner import _request_name
    from .scenarios import fixture_scenario, random_scenario

    # Safety: only kind-* contexts
    try:
        for bad in ("prod", "gke_project_cluster", "arn:aws:eks:x", "minikube"):
            try:
                Kube(bad)
            except LabSafetyError:
                continue
            raise AssertionError(f"context '{bad}' was not refused")
        result.ok("Lab safety: non-kind contexts refused before any kubectl call")
    except AssertionError as e:
        result.fail("Lab safety guard", str(e))

    # Scenarios: reproducible, labelled, valid ordering
    try:
        a, b = random_scenario(3, seed=7), random_scenario(3, seed=7)
        assert json.dumps(a["objects"], sort_keys=True) == json.dumps(b["objects"], sort_keys=True), \
            "same seed must give the same scenario"
        assert json.dumps(random_scenario(4, 7)["objects"]) != json.dumps(a["objects"])
        for sc in (a, fixture_scenario()):
            kinds = [o["kind"] for o in sc["objects"]]
            assert kinds.index("Namespace") == 0 and kinds[-1] == "Pod", "namespaces first, pods last"
            for o in sc["objects"]:
                assert o["metadata"]["labels"][LAB_LABEL] == sc["name"], f"{o['kind']} not labelled"
                ns = o["metadata"].get("namespace")
                assert ns is None or ns in sc["namespaces"], f"{o['kind']} outside scenario namespaces"
                if o["kind"] in ("ClusterRole", "ClusterRoleBinding"):
                    assert o["metadata"]["name"].startswith(sc["name"]), "cluster-scoped names must be unique"
            pods = [o for o in sc["objects"] if o["kind"] == "Pod"]
            assert all(not (o["spec"]["containers"][0].get("securityContext") or {}).get("privileged") for o in pods)
            assert all("hostPath" not in json.dumps(o) for o in pods), "lab pods never mount host paths"
        result.ok("Lab scenarios: seed-reproducible, labelled for teardown, scoped, no host access")
    except (AssertionError, ValueError, KeyError) as e:
        result.fail("Lab scenario generator", str(e))

    # Request names & metrics & parsing
    try:
        assert _request_name("list", "secrets", "x") is None
        assert _request_name("create", "pods", "x") is None
        assert _request_name("create", "pods", "x") is None and _request_name("get", "secrets", "x") == "x"
        assert _request_name("create", "serviceaccounts", "sa") == "sa"     # serviceaccounts/token is named
        c = confusion([{"engine": e, "truth": t} for e, t in
                       [(1, 1), (1, 1), (1, 0), (0, 1), (0, 0), (0, 0), (0, 0)]])
        assert (c["tp"], c["fp"], c["fn"], c["tn"]) == (2, 1, 1, 3)
        assert abs(c["precision"] - 2 / 3) < 1e-12 and abs(c["recall"] - 2 / 3) < 1e-12
        assert _json_stream('{"a":1}\n{"b":2}  {"c":3}') == [{"a": 1}, {"b": 2}, {"c": 3}]
        result.ok("Lab harness: unnamed collection requests, confusion metrics, kubectl JSON stream")
    except AssertionError as e:
        result.fail("Lab harness helpers", str(e))
