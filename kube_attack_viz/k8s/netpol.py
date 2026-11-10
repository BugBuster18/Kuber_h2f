"""
NetworkPolicy pod-to-pod reachability (networking.k8s.io/v1 semantics).

  * A pod is ingress-isolated iff some policy in its namespace selects it
    and lists "Ingress" in policyTypes (likewise for egress).
  * Non-isolated directions allow everything.
  * A connection needs egress allowed at the source AND ingress allowed at
    the destination. Policies are additive (allow-lists; union of rules).
  * Peers: podSelector (same namespace as the policy), namespaceSelector,
    or both (AND). An empty `from`/`to` list allows all peers.

Assumption (surfaced as a feature, not hidden): the CNI plugin enforces
NetworkPolicy. Some plugins (e.g. plain flannel) silently do not.
Limitations: ipBlock peers are not matched against pod IPs (pod IPs are not
in the inventory); named ports are treated as matching.
"""

from __future__ import annotations

from dataclasses import dataclass

from .inventory import Inventory, NetworkPolicy, Pod
from .selectors import matches


@dataclass
class Reachability:
    allowed: bool
    dst_ingress_isolated: bool
    src_egress_isolated: bool
    policies: list[str]          # policies that allowed the traffic (when isolated)


def _ns_labels(inv: Inventory, ns: str) -> dict[str, str]:
    labels = dict(inv.namespaces.get(ns, {}))
    labels.setdefault("kubernetes.io/metadata.name", ns)
    return labels


def _selecting(inv: Inventory, pod: Pod, direction: str) -> list[NetworkPolicy]:
    return [
        p for p in inv.network_policies
        if p.namespace == pod.namespace and direction in p.policy_types
        and matches(p.pod_selector, pod.labels)
    ]


def _peer_matches(inv: Inventory, policy: NetworkPolicy, peer: dict, other: Pod) -> bool:
    pod_sel = peer.get("podSelector")
    ns_sel = peer.get("namespaceSelector")
    if pod_sel is None and ns_sel is None:
        return False                                  # ipBlock-only peer
    if ns_sel is not None:
        if not matches(ns_sel, _ns_labels(inv, other.namespace)):
            return False
    elif other.namespace != policy.namespace:
        return False                                  # podSelector alone = policy's namespace
    return pod_sel is None or matches(pod_sel, other.labels)


def _port_ok(rule: dict, port: int | None) -> bool:
    ports = rule.get("ports")
    if not ports or port is None:
        return True
    for p in ports:
        value = p.get("port")
        end = p.get("endPort")
        if value is None or isinstance(value, str):
            return True                               # all ports / named port
        if value == port or (end is not None and value <= port <= end):
            return True
    return False


def _direction_allows(inv, policies, other, port, key) -> list[str]:
    allowed_by = []
    for pol in policies:
        rules = pol.ingress if key == "from" else pol.egress
        for rule in rules:
            peers = rule.get(key)
            if not _port_ok(rule, port):
                continue
            if not peers or any(_peer_matches(inv, pol, peer, other) for peer in peers):
                allowed_by.append(pol.name)
                break
    return allowed_by


def reachable(inv: Inventory, src: Pod, dst: Pod, port: int | None = None) -> Reachability:
    ingress_pols = _selecting(inv, dst, "Ingress")
    egress_pols = _selecting(inv, src, "Egress")

    ok_in, by_in = True, []
    if ingress_pols:
        by_in = _direction_allows(inv, ingress_pols, src, port, "from")
        ok_in = bool(by_in)
    ok_out, by_out = True, []
    if egress_pols:
        by_out = _direction_allows(inv, egress_pols, dst, port, "to")
        ok_out = bool(by_out)

    return Reachability(
        allowed=ok_in and ok_out,
        dst_ingress_isolated=bool(ingress_pols),
        src_egress_isolated=bool(egress_pols),
        policies=sorted(set(by_in + by_out)),
    )
