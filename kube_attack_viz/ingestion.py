"""
Data Ingestion Module for KubeAttackViz.

Supports two ingestion modes:
  1. JSON file ingestion — reads a pre-built cluster graph JSON.
  2. kubectl live ingestion — queries a real Kubernetes cluster and constructs
     the attack graph from raw resource data.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .models import ClusterGraph, NodeData, EdgeData


# ─── Weight heuristics ───────────────────────────────────────────────────────

_RELATIONSHIP_BASE_WEIGHTS: dict[str, float] = {
    "runs_as": 2.0,
    "binds_to": 3.0,
    "grants": 4.0,
    "accesses": 5.0,
    "mounts": 3.5,
    "exposes": 2.5,
    "connects_to": 2.0,
    "uses": 3.0,
    "escalates_to": 6.0,
    "has_secret": 4.5,
    "reads": 3.0,
    "writes": 4.0,
}

_RESOURCE_IMPACT_SCORES: dict[str, float] = {
    "pod": 4.0,
    "service": 3.0,
    "serviceaccount": 5.0,
    "role": 4.5,
    "clusterrole": 6.5,
    "rolebinding": 3.5,
    "clusterrolebinding": 6.0,
    "secret": 9.0,         # High value
    "configmap": 3.0,
    "namespace": 1.0,
    "database": 10.0,      # Maximum value target
    "node": 7.0,
    "ingress": 4.0,
}

_RESOURCE_BASE_LIKELIHOOD: dict[str, float] = {
    "pod": 2.0,
    "service": 3.0,
    "serviceaccount": 2.0,
    "role": 1.0,
    "secret": 1.5,
    "database": 1.0,
}


def ingest_from_json(filepath: str | Path) -> ClusterGraph:
    """Ingest a cluster graph from a JSON file.

    Args:
        filepath: Path to the JSON file matching the ClusterGraph schema.

    Returns:
        Parsed ClusterGraph instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
        KeyError: If required schema fields are missing.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    return ClusterGraph.from_dict(raw)


def export_graph_to_json(graph: ClusterGraph, filepath: str | Path) -> None:
    """Export a ClusterGraph to a JSON file.

    Args:
        graph: ClusterGraph instance to export.
        filepath: Output file path.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(graph.to_dict(), f, indent=2)


# ─── kubectl ingestion ───────────────────────────────────────────────────────


def _run_kubectl(resource: str) -> dict[str, Any]:
    """Execute a kubectl get command and return parsed JSON.

    Args:
        resource: Kubernetes resource type to query.

    Returns:
        Parsed JSON output from kubectl.

    Raises:
        RuntimeError: If kubectl command fails.
    """
    cmd = ["kubectl", "get", resource, "--all-namespaces", "-o", "json"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "kubectl not found. Ensure kubectl is installed and in PATH."
        )

    if result.returncode != 0:
        raise RuntimeError(
            f"kubectl command failed for resource '{resource}': {result.stderr.strip()}"
        )

    return json.loads(result.stdout)


def _make_node_id(kind: str, namespace: str, name: str) -> str:
    """Generate a deterministic node ID.

    Args:
        kind: Resource kind (lowercase).
        namespace: Namespace name.
        name: Resource name.

    Returns:
        Formatted node ID string.
    """
    ns = namespace or "cluster"
    return f"{kind}:{ns}/{name}"


def _extract_pods(raw: dict[str, Any]) -> list[NodeData]:
    """Extract pod nodes from kubectl JSON output."""
    nodes: list[NodeData] = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")
        node_id = _make_node_id("pod", ns, name)

        is_source = spec.get("hostNetwork", False)

        # Baseline Impact and Likelihood
        impact = _RESOURCE_IMPACT_SCORES.get("pod", 4.0)
        likelihood = _RESOURCE_BASE_LIKELIHOOD.get("pod", 2.0)
        
        if spec.get("hostNetwork", False):
            likelihood += 3.0
            
        # Elevate likelihood/impact for privileged containers
        image_name = None
        containers = spec.get("containers", [])
        for c in containers:
            if not image_name:
                image_name = c.get("image")
            sec = c.get("securityContext", {})
            if sec.get("privileged", False):
                likelihood += 3.0      # Easier breakout -> Higher likelihood
                impact += 1.0          # Access to host -> Higher impact
            if sec.get("runAsUser") == 0:
                likelihood += 2.0      # Root user -> Easier exploit

        # Risk = Normalized Likelihood * Impact
        likelihood = min(likelihood, 10.0)
        impact = min(impact, 10.0)
        risk = (likelihood / 10.0) * impact

        nodes.append(
            NodeData(
                id=node_id,
                type="pod",
                name=name,
                namespace=ns,
                risk_score=risk,
                likelihood=likelihood,
                impact=impact,
                is_source=is_source,
                is_sink=False,
                cves=[],
                image=image_name
            )
        )
    return nodes


def _extract_services(raw: dict[str, Any]) -> list[NodeData]:
    """Extract service nodes from kubectl JSON output."""
    nodes: list[NodeData] = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")
        node_id = _make_node_id("service", ns, name)

        svc_type = spec.get("type", "ClusterIP")
        is_source = svc_type in ("LoadBalancer", "NodePort")
        
        # Baseline
        impact = _RESOURCE_IMPACT_SCORES.get("service", 3.0)
        likelihood = _RESOURCE_BASE_LIKELIHOOD.get("service", 3.0)
        
        if is_source:
            likelihood += 3.0  # Reachable from internet -> Higher likelihood
            impact += 1.0      # Pivot point -> Slightly higher impact

        likelihood = min(likelihood, 10.0)
        impact = min(impact, 10.0)
        risk = (likelihood / 10.0) * impact

        nodes.append(
            NodeData(
                id=node_id,
                type="service",
                name=name,
                namespace=ns,
                risk_score=risk,
                likelihood=likelihood,
                impact=impact,
                is_source=is_source,
                is_sink=False,
                cves=[],
            )
        )
    return nodes


def _extract_serviceaccounts(raw: dict[str, Any]) -> list[NodeData]:
    """Extract ServiceAccount nodes."""
    nodes: list[NodeData] = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")
        node_id = _make_node_id("serviceaccount", ns, name)
        
        # Baseline
        impact = _RESOURCE_IMPACT_SCORES.get("serviceaccount", 5.0)
        likelihood = _RESOURCE_BASE_LIKELIHOOD.get("serviceaccount", 2.0)
        risk = (likelihood / 10.0) * impact

        nodes.append(
            NodeData(
                id=node_id,
                type="serviceaccount",
                name=name,
                namespace=ns,
                risk_score=risk,
                likelihood=likelihood,
                impact=impact,
                is_source=False,
                is_sink=False,
                cves=[],
            )
        )
    return nodes


def _extract_secrets(raw: dict[str, Any]) -> list[NodeData]:
    """Extract Secret nodes — these are high-value sinks."""
    nodes: list[NodeData] = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")
        node_id = _make_node_id("secret", ns, name)

        # Baseline
        impact = _RESOURCE_IMPACT_SCORES.get("secret", 9.0)
        likelihood = _RESOURCE_BASE_LIKELIHOOD.get("secret", 1.5)
        risk = (likelihood / 10.0) * impact

        nodes.append(
            NodeData(
                id=node_id,
                type="secret",
                name=name,
                namespace=ns,
                risk_score=risk,
                likelihood=likelihood,
                impact=impact,
                is_source=False,
                is_sink=True,
                cves=[],
            )
        )
    return nodes


def _extract_configmaps(raw: dict[str, Any]) -> list[NodeData]:
    """Extract ConfigMap nodes."""
    nodes: list[NodeData] = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")
        node_id = _make_node_id("configmap", ns, name)
        
        # Baseline
        impact = _RESOURCE_IMPACT_SCORES.get("configmap", 3.0)
        likelihood = _RESOURCE_BASE_LIKELIHOOD.get("configmap", 1.5)
        risk = (likelihood / 10.0) * impact

        nodes.append(
            NodeData(
                id=node_id,
                type="configmap",
                name=name,
                namespace=ns,
                risk_score=risk,
                likelihood=likelihood,
                impact=impact,
                is_source=False,
                is_sink=False,
                cves=[],
            )
        )
    return nodes


def _build_rbac_edges(
    rolebindings_raw: dict[str, Any],
    clusterrolebindings_raw: dict[str, Any],
    node_index: dict[str, NodeData],
) -> list[EdgeData]:
    """Construct edges from RBAC bindings.

    Parses RoleBindings and ClusterRoleBindings to create:
      - ServiceAccount → Role/ClusterRole (binds_to)
      - Role/ClusterRole → Secret/ConfigMap (grants access)
    """
    edges: list[EdgeData] = []
    seen_edges: set[tuple[str, str, str]] = set()

    for raw_data, binding_type in [
        (rolebindings_raw, "rolebinding"),
        (clusterrolebindings_raw, "clusterrolebinding"),
    ]:
        for item in raw_data.get("items", []):
            meta = item.get("metadata", {})
            ns = meta.get("namespace", "cluster")
            role_ref = item.get("roleRef", {})
            subjects = item.get("subjects", [])

            role_kind = role_ref.get("kind", "Role").lower()
            role_name = role_ref.get("name", "unknown")
            role_ns = ns if role_kind == "role" else "cluster"
            role_id = _make_node_id(role_kind, role_ns, role_name)

            # Create role node if it doesn't exist yet
            if role_id not in node_index:
                impact = _RESOURCE_IMPACT_SCORES.get(role_kind, 4.5)
                likelihood = _RESOURCE_BASE_LIKELIHOOD.get(role_kind, 1.0)
                risk = (likelihood / 10.0) * impact

                node_index[role_id] = NodeData(
                    id=role_id,
                    type=role_kind,
                    name=role_name,
                    namespace=role_ns,
                    risk_score=risk,
                    likelihood=likelihood,
                    impact=impact,
                    is_source=False,
                    is_sink=False,
                    cves=[],
                )

            for subject in subjects:
                subj_kind = subject.get("kind", "").lower()
                subj_name = subject.get("name", "unknown")
                subj_ns = subject.get("namespace", ns)

                if subj_kind == "serviceaccount":
                    subj_id = _make_node_id("serviceaccount", subj_ns, subj_name)
                elif subj_kind == "user":
                    subj_id = _make_node_id("user", "cluster", subj_name)
                elif subj_kind == "group":
                    subj_id = _make_node_id("group", "cluster", subj_name)
                else:
                    continue

                # Ensure subject node exists
                if subj_id not in node_index:
                    impact = _RESOURCE_IMPACT_SCORES.get(subj_kind, 3.0)
                    likelihood = _RESOURCE_BASE_LIKELIHOOD.get(subj_kind, 1.0)
                    risk = (likelihood / 10.0) * impact

                    node_index[subj_id] = NodeData(
                        id=subj_id,
                        type=subj_kind,
                        name=subj_name,
                        namespace=subj_ns,
                        risk_score=risk,
                        likelihood=likelihood,
                        impact=impact,
                        is_source=False,
                        is_sink=False,
                        cves=[],
                    )

                edge_key = (subj_id, role_id, "binds_to")
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    weight = _RELATIONSHIP_BASE_WEIGHTS.get("binds_to", 3.0)
                    edges.append(
                        EdgeData(
                            source=subj_id,
                            target=role_id,
                            relationship="binds_to",
                            weight=weight,
                        )
                    )

    return edges


def _build_pod_sa_edges(
    pods_raw: dict[str, Any],
    node_index: dict[str, NodeData],
) -> list[EdgeData]:
    """Build edges from pods to their service accounts (runs_as relationship)."""
    edges: list[EdgeData] = []
    seen: set[tuple[str, str]] = set()

    for item in pods_raw.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        pod_name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")
        sa_name = spec.get("serviceAccountName", "default")

        pod_id = _make_node_id("pod", ns, pod_name)
        sa_id = _make_node_id("serviceaccount", ns, sa_name)

        if (pod_id, sa_id) not in seen and pod_id in node_index:
            seen.add((pod_id, sa_id))
            # Ensure SA exists
            if sa_id not in node_index:
                impact = _RESOURCE_IMPACT_SCORES.get("serviceaccount", 5.0)
                likelihood = _RESOURCE_BASE_LIKELIHOOD.get("serviceaccount", 2.0)
                risk = (likelihood / 10.0) * impact

                node_index[sa_id] = NodeData(
                    id=sa_id,
                    type="serviceaccount",
                    name=sa_name,
                    namespace=ns,
                    risk_score=risk,
                    likelihood=likelihood,
                    impact=impact,
                    is_source=False,
                    is_sink=False,
                    cves=[],
                )
            edges.append(
                EdgeData(
                    source=pod_id,
                    target=sa_id,
                    relationship="runs_as",
                    weight=_RELATIONSHIP_BASE_WEIGHTS.get("runs_as", 2.0),
                )
            )

    return edges


def _build_pod_secret_edges(
    pods_raw: dict[str, Any],
    node_index: dict[str, NodeData],
) -> list[EdgeData]:
    """Build edges from pods to secrets they mount."""
    edges: list[EdgeData] = []
    seen: set[tuple[str, str]] = set()

    for item in pods_raw.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        pod_name = meta.get("name", "unknown")
        ns = meta.get("namespace", "default")
        pod_id = _make_node_id("pod", ns, pod_name)

        if pod_id not in node_index:
            continue

        for vol in spec.get("volumes", []):
            secret_ref = vol.get("secret", {})
            secret_name = secret_ref.get("secretName")
            if secret_name:
                secret_id = _make_node_id("secret", ns, secret_name)
                if (pod_id, secret_id) not in seen:
                    seen.add((pod_id, secret_id))
                    if secret_id not in node_index:
                        impact = _RESOURCE_IMPACT_SCORES.get("secret", 9.0)
                        likelihood = _RESOURCE_BASE_LIKELIHOOD.get("secret", 1.5)
                        risk = (likelihood / 10.0) * impact

                        node_index[secret_id] = NodeData(
                            id=secret_id,
                            type="secret",
                            name=secret_name,
                            namespace=ns,
                            risk_score=risk,
                            likelihood=likelihood,
                            impact=impact,
                            is_source=False,
                            is_sink=True,
                            cves=[],
                        )
                    edges.append(
                        EdgeData(
                            source=pod_id,
                            target=secret_id,
                            relationship="mounts",
                            weight=_RELATIONSHIP_BASE_WEIGHTS.get("mounts", 3.5),
                        )
                    )

    return edges


def ingest_from_kubectl() -> ClusterGraph:
    """Ingest cluster state directly from a live Kubernetes cluster via kubectl.

    Queries pods, services, rolebindings, clusterrolebindings, serviceaccounts,
    secrets, and configmaps, then constructs a complete attack graph.

    Returns:
        ClusterGraph built from live cluster state.

    Raises:
        RuntimeError: If kubectl is unavailable or commands fail.
    """
    # Query resources
    resources = {
        "pods": _run_kubectl("pods"),
        "services": _run_kubectl("services"),
        "serviceaccounts": _run_kubectl("serviceaccounts"),
        "secrets": _run_kubectl("secrets"),
        "configmaps": _run_kubectl("configmaps"),
        "rolebindings": _run_kubectl("rolebindings.rbac.authorization.k8s.io"),
        "clusterrolebindings": _run_kubectl(
            "clusterrolebindings.rbac.authorization.k8s.io"
        ),
    }

    # Extract nodes
    node_index: dict[str, NodeData] = {}

    for node in _extract_pods(resources["pods"]):
        node_index[node.id] = node
    for node in _extract_services(resources["services"]):
        node_index[node.id] = node
    for node in _extract_serviceaccounts(resources["serviceaccounts"]):
        node_index[node.id] = node
    for node in _extract_secrets(resources["secrets"]):
        node_index[node.id] = node
    for node in _extract_configmaps(resources["configmaps"]):
        node_index[node.id] = node

    # Build edges
    all_edges: list[EdgeData] = []
    all_edges.extend(
        _build_rbac_edges(
            resources["rolebindings"],
            resources["clusterrolebindings"],
            node_index,
        )
    )
    all_edges.extend(_build_pod_sa_edges(resources["pods"], node_index))
    all_edges.extend(_build_pod_secret_edges(resources["pods"], node_index))

    return ClusterGraph(
        nodes=list(node_index.values()),
        edges=all_edges,
    )


def dump_raw_kubernetes_state(filepath: str | Path) -> None:
    """Query core resources and dump the raw JSON to a file for diagnostics.

    Args:
        filepath: Output file path.
    """
    resources = {
        "pods": _run_kubectl("pods"),
        "services": _run_kubectl("services"),
        "serviceaccounts": _run_kubectl("serviceaccounts"),
        "secrets": _run_kubectl("secrets"),
        "configmaps": _run_kubectl("configmaps"),
        "rolebindings": _run_kubectl("rolebindings.rbac.authorization.k8s.io"),
        "clusterrolebindings": _run_kubectl(
            "clusterrolebindings.rbac.authorization.k8s.io"
        ),
    }

    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(resources, f, indent=2)


def enrich_cluster_graph(cluster: ClusterGraph) -> int:
    """Scan cluster for CVEs and fetch live CVSS scores from NVD.

    Returns:
        Number of successfully enriched items.
    """
    from .cve_service import enricher
    from rich.progress import Progress

    enriched_count = 0
    cves_to_check = set()

    # Collect all CVEs
    for node in cluster.nodes:
        # 1. Existing CVEs
        for cve in node.cves:
            cves_to_check.add(cve)
        
        # 2. Dynamic Image Discovery
        if node.type == "pod" and node.image:
            discovered = enricher.discover_cves_for_image(node.image)
            for d in discovered:
                if d["id"] not in node.cves:
                    node.cves.append(d["id"])
                # Increase node risk by discovered CVSS
                node.risk_score = max(node.risk_score, d["cvss"])
                enriched_count += 1

    for edge in cluster.edges:
        if edge.cve:
            cves_to_check.add(edge.cve)

    if not cves_to_check:
        return 0

    with Progress() as progress:
        task = progress.add_task("[cyan]Enriching CVEs from NVD...", total=len(cves_to_check))
        
        cve_map = {}
        for cve in cves_to_check:
            score = enricher.get_cvss(cve)
            if score is not None:
                cve_map[cve] = score
                enriched_count += 1
            progress.update(task, advance=1)

    # Apply scores
    for node in cluster.nodes:
        # Update Node Likelihood based on CVSS
        max_cvss = 0.0
        for cve in node.cves:
            if cve in cve_map:
                max_cvss = max(max_cvss, cve_map[cve])
        
        if max_cvss > 0:
            # Shift likelihood up by up to 5 points (half of CVSS)
            node.likelihood = min(10.0, (node.likelihood or 0.1) + (max_cvss / 2.0))
            # Recalculate Risk Score: (L/10) * I
            node.risk_score = (node.likelihood / 10.0) * (node.impact or 1.0)

    for edge in cluster.edges:
        if edge.cve in cve_map:
            edge.cvss = cve_map[edge.cve]

    return enriched_count
