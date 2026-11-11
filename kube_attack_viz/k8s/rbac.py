"""
Exact RBAC evaluation, following the Kubernetes authorizer's rules.

  * A RoleBinding grants its Role/ClusterRole only inside its namespace.
  * A ClusterRoleBinding grants its ClusterRole cluster-wide.
  * '*' matches any verb / resource / apiGroup; resourceNames restricts
    a rule to named objects (and never matches list/watch/create).
  * ServiceAccounts are also members of the groups system:serviceaccounts,
    system:serviceaccounts:<namespace> and system:authenticated.

Limitations (documented, not hidden): aggregated ClusterRoles are evaluated
from the rules the API server has already materialized on them;
nonResourceURLs and admission webhooks are not modelled.
"""

from __future__ import annotations

from dataclasses import dataclass

from .inventory import Binding, Inventory, Role, Rule

CORE = ""
RBAC_GROUP = "rbac.authorization.k8s.io"
APPS = "apps"

CLUSTER_SCOPED = {"nodes", "namespaces", "clusterroles", "clusterrolebindings", "persistentvolumes"}

# Permissions that RBAC audit tools treat as sensitive, with the graph edge
# each one creates. (permission, verbs-any-of, resource, apiGroup, edge kind)
SENSITIVE_PERMISSIONS = [
    ("read_secrets", ("get", "list", "watch"), "secrets", CORE, "secret"),
    ("exec_pods", ("create",), "pods/exec", CORE, "pod"),
    ("attach_pods", ("create",), "pods/attach", CORE, "pod"),
    ("create_pods", ("create",), "pods", CORE, "serviceaccount"),
    ("create_deployments", ("create", "update", "patch"), "deployments", APPS, "serviceaccount"),
    ("create_sa_tokens", ("create",), "serviceaccounts/token", CORE, "serviceaccount"),
    ("impersonate_sa", ("impersonate",), "serviceaccounts", CORE, "serviceaccount"),
    ("bind_roles", ("bind",), "clusterroles", RBAC_GROUP, "clusterrole"),
    ("escalate_roles", ("escalate",), "clusterroles", RBAC_GROUP, "clusterrole"),
    ("node_proxy", ("get", "create"), "nodes/proxy", CORE, "node"),
]


@dataclass(frozen=True)
class Grant:
    binding: Binding
    role: Role
    rule: Rule
    scope: str | None          # namespace, or None = cluster-wide


def subject_identities(sa_namespace: str | None, sa_name: str,
                       kind: str = "serviceaccount") -> set[tuple[str, str, str | None]]:
    """All (kind, name, namespace) identities a subject authenticates as.

    ServiceAccounts are also in system:serviceaccounts[:<ns>]; every
    authenticated subject (ServiceAccount or User) is in system:authenticated.
    """
    if kind == "user":
        return {("user", sa_name, None), ("group", "system:authenticated", None)}
    return {
        ("serviceaccount", sa_name, sa_namespace),
        ("group", "system:serviceaccounts", None),
        ("group", f"system:serviceaccounts:{sa_namespace}", None),
        ("group", "system:authenticated", None),
    }


def _binding_matches(binding: Binding, identities: set[tuple[str, str, str | None]]) -> bool:
    for s in binding.subjects:
        key = (s.kind, s.name, s.namespace if s.kind == "serviceaccount" else None)
        if key in identities:
            return True
    return False


def grants_for(inv: Inventory, sa_namespace: str | None, sa_name: str,
               kind: str = "serviceaccount") -> list[Grant]:
    """Every (binding, role, rule) that applies to a ServiceAccount (or User)."""
    identities = subject_identities(sa_namespace, sa_name, kind)
    grants: list[Grant] = []
    for b in inv.bindings:
        if not _binding_matches(b, identities):
            continue
        role = inv.role(b.role_kind, b.namespace, b.role_name)
        if role is None:
            continue   # dangling roleRef grants nothing
        scope = b.namespace if b.kind == "rolebinding" else None
        for rule in role.rules:
            grants.append(Grant(binding=b, role=role, rule=rule, scope=scope))
    return grants


def rule_allows(rule: Rule, verb: str, resource: str, api_group: str, name: str | None = None) -> bool:
    if "*" not in rule.verbs and verb not in rule.verbs:
        return False
    if "*" not in rule.api_groups and api_group not in rule.api_groups:
        return False
    if "*" not in rule.resources and resource not in rule.resources:
        # "*/scale"-style subresource wildcards
        sub = resource.split("/", 1)[1] if "/" in resource else None
        if not (sub and f"*/{sub}" in rule.resources):
            return False
    if rule.resource_names:
        if verb in ("list", "watch", "create", "deletecollection") or name is None:
            return False
        if name not in rule.resource_names:
            return False
    return True


def allowed(
    grants: list[Grant], verb: str, resource: str, api_group: str,
    namespace: str | None, name: str | None = None,
) -> list[Grant]:
    """Grants that authorize the request (empty list = denied)."""
    cluster_scoped = resource.split("/")[0] in CLUSTER_SCOPED
    out = []
    for g in grants:
        if cluster_scoped and g.scope is not None:
            continue                    # RoleBindings never grant cluster-scoped resources
        if not cluster_scoped and g.scope is not None and g.scope != namespace:
            continue
        if rule_allows(g.rule, verb, resource, api_group, name):
            out.append(g)
    return out


def is_cluster_admin_equivalent(grants: list[Grant]) -> bool:
    """'*' on '*' in '*' via a cluster-wide grant."""
    return any(
        g.scope is None and "*" in g.rule.verbs and "*" in g.rule.resources and "*" in g.rule.api_groups
        for g in grants
    )
