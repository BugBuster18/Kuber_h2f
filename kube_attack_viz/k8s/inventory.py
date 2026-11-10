"""
Typed cluster inventory parsed from raw `kubectl get <kind> -A -o json`.

Input is a dict of resource lists, e.g. {"pods": {...}, "services": {...}}
— exactly what ingestion.fetch_raw_state() returns and `dump-raw` saves.
Secrets are expected as metadata only (see ingestion.fetch_raw_state);
if a full Secret object is passed, its data/stringData are ignored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

RESOURCE_KEYS = (
    "namespaces", "nodes", "pods", "services", "ingresses", "serviceaccounts",
    "secrets", "configmaps", "roles", "clusterroles", "rolebindings",
    "clusterrolebindings", "networkpolicies",
)


@dataclass
class Container:
    name: str
    image: str | None
    privileged: bool = False
    run_as_root: bool | None = None          # None = unknown (image default)
    allow_privilege_escalation: bool | None = None
    capabilities_add: list[str] = field(default_factory=list)
    capabilities_drop: list[str] = field(default_factory=list)
    secret_env_refs: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)


@dataclass
class Pod:
    namespace: str
    name: str
    labels: dict[str, str]
    service_account: str
    automount_token: bool | None             # pod-level setting (None = inherit)
    node_name: str | None
    host_network: bool
    host_pid: bool
    host_ipc: bool
    host_paths: list[str]
    secret_volumes: list[str]
    containers: list[Container]

    @property
    def privileged(self) -> bool:
        return any(c.privileged for c in self.containers)

    @property
    def images(self) -> list[str]:
        return [c.image for c in self.containers if c.image]


@dataclass
class Service:
    namespace: str
    name: str
    type: str
    selector: dict[str, str]
    ports: list[int]


@dataclass
class Ingress:
    namespace: str
    name: str
    backend_services: list[str]


@dataclass
class ServiceAccount:
    namespace: str
    name: str
    automount_token: bool | None


@dataclass
class Rule:
    api_groups: list[str]
    resources: list[str]
    verbs: list[str]
    resource_names: list[str]


@dataclass
class Role:
    kind: str                                # "role" | "clusterrole"
    namespace: str | None                    # None for ClusterRole
    name: str
    rules: list[Rule]


@dataclass
class Subject:
    kind: str                                # serviceaccount | user | group
    name: str
    namespace: str | None


@dataclass
class Binding:
    kind: str                                # "rolebinding" | "clusterrolebinding"
    namespace: str | None                    # scope (None = cluster-wide)
    name: str
    role_kind: str                           # "role" | "clusterrole"
    role_name: str
    subjects: list[Subject]


@dataclass
class NetworkPolicy:
    namespace: str
    name: str
    pod_selector: dict
    policy_types: list[str]
    ingress: list[dict]
    egress: list[dict]


@dataclass
class Inventory:
    namespaces: dict[str, dict[str, str]] = field(default_factory=dict)   # name -> labels
    nodes: list[str] = field(default_factory=list)
    pods: list[Pod] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    ingresses: list[Ingress] = field(default_factory=list)
    service_accounts: list[ServiceAccount] = field(default_factory=list)
    secrets: list[tuple[str, str, str]] = field(default_factory=list)      # (ns, name, type)
    configmaps: list[tuple[str, str]] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    bindings: list[Binding] = field(default_factory=list)
    network_policies: list[NetworkPolicy] = field(default_factory=list)

    def role(self, kind: str, namespace: str | None, name: str) -> Role | None:
        for r in self.roles:
            if r.kind == kind and r.name == name and (kind == "clusterrole" or r.namespace == namespace):
                return r
        return None

    def service_account(self, namespace: str, name: str) -> ServiceAccount | None:
        for sa in self.service_accounts:
            if sa.namespace == namespace and sa.name == name:
                return sa
        return None


def _items(raw: dict[str, Any], key: str) -> list[dict]:
    block = raw.get(key) or {}
    return block.get("items", []) if isinstance(block, dict) else list(block)


def _meta(item: dict) -> tuple[str | None, str, dict[str, str]]:
    m = item.get("metadata") or {}
    return m.get("namespace"), m.get("name", "unknown"), dict(m.get("labels") or {})


def _parse_container(c: dict, pod_sc: dict) -> Container:
    sc = c.get("securityContext") or {}
    caps = sc.get("capabilities") or {}
    run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
    run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    if run_as_user is not None:
        root = run_as_user == 0
    elif run_as_non_root is True:
        root = False
    else:
        root = None
    secret_env = []
    for env in c.get("env") or []:
        ref = ((env.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name")
        if ref:
            secret_env.append(ref)
    for src in c.get("envFrom") or []:
        ref = (src.get("secretRef") or {}).get("name")
        if ref:
            secret_env.append(ref)
    return Container(
        name=c.get("name", "container"),
        image=c.get("image"),
        privileged=bool(sc.get("privileged", False)),
        run_as_root=root,
        allow_privilege_escalation=sc.get("allowPrivilegeEscalation"),
        capabilities_add=[x.upper() for x in caps.get("add") or []],
        capabilities_drop=[x.upper() for x in caps.get("drop") or []],
        secret_env_refs=sorted(set(secret_env)),
        ports=[p.get("containerPort") for p in c.get("ports") or [] if p.get("containerPort")],
    )


def parse_inventory(raw: dict[str, Any]) -> Inventory:
    inv = Inventory()

    for item in _items(raw, "namespaces"):
        _, name, labels = _meta(item)
        inv.namespaces[name] = labels
    inv.nodes = [_meta(i)[1] for i in _items(raw, "nodes")]

    for item in _items(raw, "pods"):
        ns, name, labels = _meta(item)
        spec = item.get("spec") or {}
        pod_sc = spec.get("securityContext") or {}
        volumes = spec.get("volumes") or []
        containers = [
            _parse_container(c, pod_sc)
            for c in (spec.get("containers") or []) + (spec.get("initContainers") or [])
        ]
        inv.pods.append(Pod(
            namespace=ns or "default", name=name, labels=labels,
            service_account=spec.get("serviceAccountName") or spec.get("serviceAccount") or "default",
            automount_token=spec.get("automountServiceAccountToken"),
            node_name=spec.get("nodeName"),
            host_network=bool(spec.get("hostNetwork")), host_pid=bool(spec.get("hostPID")),
            host_ipc=bool(spec.get("hostIPC")),
            host_paths=[v["hostPath"].get("path", "") for v in volumes if v.get("hostPath")],
            secret_volumes=[v["secret"]["secretName"] for v in volumes
                            if (v.get("secret") or {}).get("secretName")],
            containers=containers,
        ))
        inv.namespaces.setdefault(ns or "default", {})

    for item in _items(raw, "services"):
        ns, name, _ = _meta(item)
        spec = item.get("spec") or {}
        inv.services.append(Service(
            namespace=ns or "default", name=name, type=spec.get("type", "ClusterIP"),
            selector=dict(spec.get("selector") or {}),
            ports=[p.get("port") for p in spec.get("ports") or [] if p.get("port")],
        ))

    for item in _items(raw, "ingresses"):
        ns, name, _ = _meta(item)
        spec = item.get("spec") or {}
        backends = set()
        default = ((spec.get("defaultBackend") or {}).get("service") or {}).get("name")
        if default:
            backends.add(default)
        for rule in spec.get("rules") or []:
            for p in (rule.get("http") or {}).get("paths") or []:
                svc = ((p.get("backend") or {}).get("service") or {}).get("name")
                if svc:
                    backends.add(svc)
        inv.ingresses.append(Ingress(namespace=ns or "default", name=name, backend_services=sorted(backends)))

    for item in _items(raw, "serviceaccounts"):
        ns, name, _ = _meta(item)
        inv.service_accounts.append(ServiceAccount(
            namespace=ns or "default", name=name,
            automount_token=item.get("automountServiceAccountToken"),
        ))

    for item in _items(raw, "secrets"):
        # Metadata only — values are never read, even if present.
        ns, name, _ = _meta(item)
        inv.secrets.append((ns or "default", name, item.get("type", "Opaque")))

    for item in _items(raw, "configmaps"):
        ns, name, _ = _meta(item)
        inv.configmaps.append((ns or "default", name))

    for key, kind in (("roles", "role"), ("clusterroles", "clusterrole")):
        for item in _items(raw, key):
            ns, name, _ = _meta(item)
            rules = [
                Rule(
                    api_groups=list(r.get("apiGroups") or [""]),
                    resources=list(r.get("resources") or []),
                    verbs=[v.lower() for v in r.get("verbs") or []],
                    resource_names=list(r.get("resourceNames") or []),
                )
                for r in item.get("rules") or [] if r.get("resources")   # nonResourceURLs ignored
            ]
            inv.roles.append(Role(kind=kind, namespace=ns if kind == "role" else None, name=name, rules=rules))

    for key, kind in (("rolebindings", "rolebinding"), ("clusterrolebindings", "clusterrolebinding")):
        for item in _items(raw, key):
            ns, name, _ = _meta(item)
            ref = item.get("roleRef") or {}
            subjects = [
                Subject(
                    kind=(s.get("kind") or "").lower(), name=s.get("name", ""),
                    namespace=s.get("namespace") or (ns if (s.get("kind") or "").lower() == "serviceaccount" else None),
                )
                for s in item.get("subjects") or []
            ]
            inv.bindings.append(Binding(
                kind=kind, namespace=ns if kind == "rolebinding" else None, name=name,
                role_kind=(ref.get("kind") or "Role").lower(), role_name=ref.get("name", ""),
                subjects=subjects,
            ))

    for item in _items(raw, "networkpolicies"):
        ns, name, _ = _meta(item)
        spec = item.get("spec") or {}
        types = spec.get("policyTypes") or (["Ingress", "Egress"] if spec.get("egress") is not None else ["Ingress"])
        inv.network_policies.append(NetworkPolicy(
            namespace=ns or "default", name=name, pod_selector=spec.get("podSelector") or {},
            policy_types=types, ingress=spec.get("ingress") or [], egress=spec.get("egress") or [],
        ))

    return inv
