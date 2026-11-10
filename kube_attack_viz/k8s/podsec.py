"""
Pod host-access properties, defined by the Kubernetes Pod Security Standards.

The PSS "baseline" profile lists the pod settings that break the
container/host boundary; we report a pod's violations of it as host-access
vectors (https://kubernetes.io/docs/concepts/security/pod-security-standards/).
Nothing here is a heuristic weight — each item is a documented PSS control.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .inventory import Inventory, Pod

# PSS baseline: capabilities allowed to be ADDED; anything else violates it.
PSS_BASELINE_ALLOWED_CAPS = {
    "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
    "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
}

PSA_LABEL = "pod-security.kubernetes.io/enforce"


@dataclass
class HostAccess:
    privileged: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    host_network: bool = False
    host_path_mounts: list[str] = field(default_factory=list)
    non_baseline_capabilities: list[str] = field(default_factory=list)
    run_as_root: bool | None = None
    allow_privilege_escalation: bool | None = None

    @property
    def baseline_violations(self) -> list[str]:
        v = []
        if self.privileged:
            v.append("privileged")
        if self.host_pid:
            v.append("hostPID")
        if self.host_ipc:
            v.append("hostIPC")
        if self.host_network:
            v.append("hostNetwork")
        if self.host_path_mounts:
            v.append("hostPath")
        if self.non_baseline_capabilities:
            v.append("capabilities")
        return v

    @property
    def breaks_host_boundary(self) -> bool:
        """Any PSS-baseline host-isolation control is violated."""
        return bool(self.baseline_violations)


def host_access(pod: Pod) -> HostAccess:
    caps = sorted({c for ct in pod.containers for c in ct.capabilities_add} - PSS_BASELINE_ALLOWED_CAPS)
    roots = [c.run_as_root for c in pod.containers]
    escal = [c.allow_privilege_escalation for c in pod.containers]
    return HostAccess(
        privileged=pod.privileged,
        host_pid=pod.host_pid,
        host_ipc=pod.host_ipc,
        host_network=pod.host_network,
        host_path_mounts=sorted(set(pod.host_paths)),
        non_baseline_capabilities=caps,
        run_as_root=True if any(r is True for r in roots) else (False if roots and all(r is False for r in roots) else None),
        allow_privilege_escalation=True if any(e is True for e in escal) else (False if escal and all(e is False for e in escal) else None),
    )


def namespace_enforce_level(inv: Inventory, namespace: str) -> str:
    """Pod Security Admission enforce level: privileged | baseline | restricted."""
    return inv.namespaces.get(namespace, {}).get(PSA_LABEL, "privileged")


def token_mounted(inv: Inventory, pod: Pod) -> bool:
    """Is the ServiceAccount token auto-mounted into the pod?

    Pod setting wins over ServiceAccount setting; default is True.
    """
    if pod.automount_token is not None:
        return pod.automount_token
    sa = inv.service_account(pod.namespace, pod.service_account)
    if sa is not None and sa.automount_token is not None:
        return sa.automount_token
    return True
