"""
Ground-truth measurement on a live (lab) cluster.

  * RBAC: SubjectAccessReview — the API server's own authorizer decides.
    Each review carries the ServiceAccount's real user name AND the groups a
    ServiceAccount token authenticates with (system:serviceaccounts,
    system:serviceaccounts:<ns>, system:authenticated), exactly as a request
    made with that token would.
  * Network: an HTTP GET from the source pod to the destination pod's IP on
    PROBE_PORT, executed inside the source pod. Success = the CNI allowed it.
  * Tokens: whether the API server's admission injected a projected
    ServiceAccount token volume into the running pod.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .kube import Kube
from .scenarios import PROBE_PORT

SAR_CHUNK = 150


def sa_user(ns: str, name: str) -> tuple[str, list[str]]:
    return (f"system:serviceaccount:{ns}:{name}",
            ["system:serviceaccounts", f"system:serviceaccounts:{ns}", "system:authenticated"])


def _json_stream(text: str) -> list[dict[str, Any]]:
    """kubectl prints one JSON document per created object, concatenated."""
    decoder = json.JSONDecoder()
    docs, i = [], 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        doc, i = decoder.raw_decode(text, i)
        docs.append(doc)
    return docs


def access_reviews(kube: Kube, checks: list[dict[str, Any]]) -> list[bool]:
    """checks: dicts with sa_ns, sa_name, verb, resource, subresource, group, namespace, name."""
    results: list[bool] = []
    for start in range(0, len(checks), SAR_CHUNK):
        items = []
        for c in checks[start:start + SAR_CHUNK]:
            user, groups = sa_user(c["sa_ns"], c["sa_name"])
            attrs = {"verb": c["verb"], "group": c["group"], "resource": c["resource"]}
            if c.get("subresource"):
                attrs["subresource"] = c["subresource"]
            if c.get("namespace"):
                attrs["namespace"] = c["namespace"]
            if c.get("name"):
                attrs["name"] = c["name"]
            items.append({"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                          "spec": {"user": user, "groups": groups, "resourceAttributes": attrs}})
        out = kube.run(["create", "-f", "-", "-o", "json"],
                       stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
        reviews = _json_stream(out)
        if len(reviews) == 1 and reviews[0].get("kind") == "List":
            reviews = reviews[0].get("items", [])
        if len(reviews) != len(items):
            raise RuntimeError(f"expected {len(items)} SubjectAccessReviews, got {len(reviews)}")
        results.extend(bool(r.get("status", {}).get("allowed")) for r in reviews)
    return results


def probe(kube: Kube, src_ns: str, src_pod: str, dst_ip: str, port: int = PROBE_PORT) -> bool:
    rc = kube.rc(["exec", "-n", src_ns, src_pod, "--", "wget", "-q", "-T", "3", "-O", "/dev/null",
                  f"http://{dst_ip}:{port}/"], timeout=20)
    return rc == 0


def probe_many(kube: Kube, pairs: list[tuple[str, str, str]], workers: int = 8) -> list[bool]:
    """pairs: (src_ns, src_pod, dst_ip). Each probe is retried once on failure
    to rule out transient exec/network hiccups (a policy block fails both)."""
    def one(p):
        return probe(kube, *p) or probe(kube, *p)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, pairs))


def token_injected(pod_json: dict[str, Any]) -> bool:
    for v in (pod_json.get("spec") or {}).get("volumes") or []:
        for src in (v.get("projected") or {}).get("sources") or []:
            if "serviceAccountToken" in src:
                return True
    return False
