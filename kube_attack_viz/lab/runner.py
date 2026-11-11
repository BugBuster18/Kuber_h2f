"""
Run lab scenarios: apply → wait → scan with the engine → measure → compare.

Each result row pairs the engine's prediction with the measured outcome for
one check, plus the features of that check (used for analysis and models):

  kind=rbac     can <ServiceAccount> <verb> <resource> [<name>] in <namespace>?
  kind=network  can pod A reach pod B on PROBE_PORT?
  kind=token    is the ServiceAccount token mounted in pod P?
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .. import ingestion
from ..k8s import rbac
from ..k8s.inventory import parse_inventory
from ..k8s.netpol import reachable
from ..k8s.podsec import token_mounted
from ..ml.paths import DATA_DIR
from .groundtruth import access_reviews, probe_many, token_injected
from .kube import LAB_LABEL, Kube
from .scenarios import IMAGE, PROBE_PORT, fixture_scenario, random_scenario

LAB_DIR = DATA_DIR / "lab"

# Requests for a collection or a brand-new object carry no name.
_UNNAMED = {("list", None), ("watch", None), ("create", "pods"), ("create", "deployments")}


def _request_name(verb: str, resource: str, name: str | None) -> str | None:
    if (verb, None) in _UNNAMED or (verb, resource) in _UNNAMED:
        return None
    return name


def preload_image(kube: Kube, log: Callable[[str], None]) -> None:
    cluster = kube.context.removeprefix("kind-")
    for cmd in (["docker", "pull", "-q", IMAGE], ["kind", "load", "docker-image", IMAGE, "--name", cluster]):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            log(f"  (image preload step failed, pods will pull directly: {r.stderr.strip()[:120]})")
            return
    log(f"  ✓ {IMAGE} loaded into {cluster}")


def teardown(kube: Kube, scenario: dict) -> None:
    kube.run(["delete", "namespace", *scenario["namespaces"], "--ignore-not-found", "--wait=true",
              "--timeout=180s"], check=False, timeout=240)
    kube.run(["delete", "clusterrole,clusterrolebinding", "-l", f"{LAB_LABEL}={scenario['name']}",
              "--ignore-not-found"], check=False)


def _rbac_checks(inv, nss: list[str]) -> list[dict[str, Any]]:
    sas = [(sa.namespace, sa.name) for sa in inv.service_accounts if sa.namespace in nss]
    secrets = [(ns, n) for ns, n, _ in inv.secrets if ns in nss]
    pods = [(p.namespace, p.name) for p in inv.pods if p.namespace in nss]
    targets = {"secret": secrets, "pod": pods, "serviceaccount": sas,
               "clusterrole": [(None, "cluster-admin")], "node": [(None, n) for n in inv.nodes]}
    checks = []
    for sa_ns, sa_name in sas:
        grants = rbac.grants_for(inv, sa_ns, sa_name)
        for perm, verbs, resource, group, tkind in rbac.SENSITIVE_PERMISSIONS:
            base, _, sub = resource.partition("/")
            for tns, tname in targets[tkind]:
                for verb in verbs:
                    name = _request_name(verb, base, tname)
                    matched = rbac.allowed(grants, verb, resource, group, tns, name)
                    checks.append({
                        "kind": "rbac", "sa_ns": sa_ns, "sa_name": sa_name, "permission": perm,
                        "verb": verb, "resource": base, "subresource": sub or None, "group": group,
                        "namespace": tns, "name": name, "engine": bool(matched),
                        "features": {
                            "same_namespace": tns == sa_ns,
                            "cluster_scoped_target": tns is None,
                            "n_grants": len(grants),
                            "via_wildcard": any("*" in g.rule.verbs or "*" in g.rule.resources
                                                or "*" in g.rule.api_groups for g in matched),
                            "via_resource_names": any(g.rule.resource_names for g in matched),
                            "via_group_subject": any(any(s.kind == "group" for s in g.binding.subjects)
                                                     for g in matched),
                            "via_cluster_binding": any(g.scope is None for g in matched),
                        },
                    })
    return checks


def run_scenario(kube: Kube, scenario: dict, out: Path, log: Callable[[str], None]) -> list[dict]:
    name, nss = scenario["name"], scenario["namespaces"]
    (out / "scenarios").mkdir(parents=True, exist_ok=True)
    (out / "scenarios" / f"{name}.json").write_text(json.dumps(scenario, indent=1), encoding="utf-8")

    t0 = time.time()
    kube.apply(scenario["objects"])
    for ns in nss:
        kube.run(["wait", "--for=condition=Ready", "pod", "--all", "-n", ns, "--timeout=180s"],
                 check=False, timeout=200)

    # ── Engine: scan the cluster exactly as a user would ─────────────────
    raw = ingestion.fetch_raw_state(context=kube.context)
    inv = parse_inventory(raw)
    if raw["_errors"]:
        log(f"  [WARN] scan errors: {raw['_errors']}")

    rows: list[dict] = []

    # ── RBAC: engine vs SubjectAccessReview ───────────────────────────────
    checks = _rbac_checks(inv, nss)
    truth = access_reviews(kube, checks)
    for c, t in zip(checks, truth):
        rows.append({**c, "truth": t})

    # ── Tokens: engine vs injected projected token volume ────────────────
    raw_pods = {(p["metadata"]["namespace"], p["metadata"]["name"]): p for p in raw["pods"]["items"]}
    lab_pods = [p for p in inv.pods if p.namespace in nss]
    for p in lab_pods:
        rows.append({"kind": "token", "namespace": p.namespace, "pod": p.name,
                     "engine": token_mounted(inv, p), "truth": token_injected(raw_pods[(p.namespace, p.name)]),
                     "features": {"pod_automount": p.automount_token,
                                  "sa_automount": getattr(inv.service_account(p.namespace, p.service_account),
                                                          "automount_token", None)}})

    # ── Network: engine vs HTTP probe ─────────────────────────────────────
    ready = []
    for p in lab_pods:
        rp = raw_pods[(p.namespace, p.name)]
        conds = {c["type"]: c["status"] for c in (rp.get("status") or {}).get("conditions") or []}
        ip = (rp.get("status") or {}).get("podIP")
        if conds.get("Ready") == "True" and ip:
            ready.append((p, ip))
    not_ready = len(lab_pods) - len(ready)
    if not_ready:
        log(f"  [WARN] {not_ready} pod(s) not ready; excluded from network checks")
    pairs, meta = [], []
    for src, _ in ready:
        for dst, dst_ip in ready:
            if src is dst:
                continue
            r = reachable(inv, src, dst, PROBE_PORT)
            pairs.append((src.namespace, src.name, dst_ip))
            meta.append({
                "kind": "network", "src": f"{src.namespace}/{src.name}", "dst": f"{dst.namespace}/{dst.name}",
                "engine": r.allowed,
                "features": {"same_namespace": src.namespace == dst.namespace,
                             "dst_ingress_isolated": r.dst_ingress_isolated,
                             "src_egress_isolated": r.src_egress_isolated,
                             "n_allowing_policies": len(r.policies),
                             "src_host_network": src.host_network, "dst_host_network": dst.host_network},
            })
    for m, t in zip(meta, probe_many(kube, pairs)):
        rows.append({**m, "truth": t})

    for r in rows:
        r["scenario"] = name
    with open(out / "results.jsonl", "a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    counts = {k: sum(1 for r in rows if r["kind"] == k) for k in ("rbac", "token", "network")}
    wrong = sum(1 for r in rows if r["engine"] != r["truth"])
    log(f"  {name}: {counts['rbac']} RBAC, {counts['token']} token, {counts['network']} network checks; "
        f"{wrong} disagreement(s)  [{time.time() - t0:.0f}s]")
    return rows


def run_lab(context: str, n_scenarios: int, seed: int, include_fixture: bool = True,
            keep: bool = False, log: Callable[[str], None] = print) -> Path:
    kube = Kube(context)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = LAB_DIR / run_id
    out.mkdir(parents=True, exist_ok=True)

    version = json.loads(kube.run(["version", "-o", "json"]))
    (out / "run.json").write_text(json.dumps({
        "run_id": run_id, "context": context, "seed": seed, "n_scenarios": n_scenarios,
        "include_fixture": include_fixture, "probe_port": PROBE_PORT, "image": IMAGE,
        "server_version": version.get("serverVersion", {}).get("gitVersion"),
        "client_version": version.get("clientVersion", {}).get("gitVersion"),
        "cni": "kindnet (kind default)",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")

    preload_image(kube, log)
    scenarios = ([fixture_scenario()] if include_fixture else []) + \
                [random_scenario(i, seed) for i in range(n_scenarios)]
    for sc in scenarios:
        try:
            run_scenario(kube, sc, out, log)
        except Exception as e:                       # record and continue
            log(f"  ✗ {sc['name']} failed: {e}")
            with open(out / "errors.log", "a", encoding="utf-8") as f:
                f.write(f"{sc['name']}: {e}\n")
        finally:
            if not keep:
                teardown(kube, sc)
    log(f"✓ results in {out}")
    return out
