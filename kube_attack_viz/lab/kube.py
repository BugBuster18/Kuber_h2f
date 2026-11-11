"""kubectl access for lab experiments, restricted to local kind clusters."""

from __future__ import annotations

import json
import subprocess
from typing import Any

LAB_LABEL = "kubeattackviz.lab"


class LabSafetyError(RuntimeError):
    pass


class Kube:
    """Runs kubectl against ONE context, which must be a local kind cluster."""

    def __init__(self, context: str):
        if not context.startswith("kind-"):
            raise LabSafetyError(
                f"Refusing to run lab experiments against context '{context}'. "
                "Lab runs create and delete resources; only local kind-* clusters are allowed."
            )
        contexts = self.run(["config", "get-contexts", "-o", "name"], with_context=False).split()
        if context not in contexts:
            raise LabSafetyError(f"Context '{context}' not found. Create it with: kind create cluster --name "
                                 f"{context.removeprefix('kind-')}")
        server = self.run(["config", "view", "--minify", "--context", context, "-o",
                           "jsonpath={.clusters[0].cluster.server}"], with_context=False)
        if not any(h in server for h in ("127.0.0.1", "localhost", "[::1]")):
            raise LabSafetyError(f"Context '{context}' points at {server}, not a local cluster.")
        self.context = context

    def run(self, args: list[str], *, stdin: str | None = None, check: bool = True,
            timeout: int = 120, with_context: bool = True) -> str:
        cmd = ["kubectl", *(["--context", self.context] if with_context else []), *args]
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            raise RuntimeError(f"kubectl {' '.join(args[:3])}: {r.stderr.strip()[:500]}")
        return r.stdout

    def rc(self, args: list[str], timeout: int = 30) -> int:
        cmd = ["kubectl", "--context", self.context, *args]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            return 124

    def apply(self, objects: list[dict[str, Any]]) -> str:
        doc = {"apiVersion": "v1", "kind": "List", "items": objects}
        return self.run(["apply", "-f", "-"], stdin=json.dumps(doc))

    def get_json(self, args: list[str]) -> dict[str, Any]:
        return json.loads(self.run(["get", *args, "-o", "json"]))
