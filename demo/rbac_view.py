"""Colourful RBAC summary of a demo cluster (used by demo/present.sh).

    python3 demo/rbac_view.py kind-kav-prod
"""

import json
import subprocess
import sys

B, D, R = "\033[1m", "\033[2m", "\033[0m"
RED, YEL, MAG = "\033[1;31m", "\033[33m", "\033[35m"
APP_NS = ("shop", "payments", "ci")
SKIP = ("system:", "kubeadm:", "kindnet", "local-path")


def kubectl_json(ctx, *args):
    out = subprocess.run(["kubectl", "--context", ctx, *args, "-o", "json"],
                         capture_output=True, text=True).stdout
    return json.loads(out or '{"items": []}')["items"]


def subjects(binding):
    parts = []
    for s in binding.get("subjects") or []:
        who = f"{s['namespace']}/{s['name']}" if s.get("namespace") else s["name"]
        colour = RED if s["kind"] == "User" else MAG
        parts.append(f"{colour}{s['kind']}{R}:{who}")
    return ", ".join(parts)


def main(ctx):
    for b in kubectl_json(ctx, "get", "clusterrolebindings"):
        name = b["metadata"]["name"]
        if name.startswith(SKIP) or name == "cluster-admin":   # built-in
            continue
        print(f"  {RED}cluster-wide{R}  {name:<28} → {B}{b['roleRef']['name']:<18}{R} {subjects(b)}")
    for ns in APP_NS:
        for b in kubectl_json(ctx, "get", "rolebindings", "-n", ns):
            print(f"  {YEL}ns {ns:<9}{R}  {b['metadata']['name']:<28} → {B}{b['roleRef']['name']:<18}{R} {subjects(b)}")
    print(f"\n  {D}kubectl --context {ctx} get rolebindings,clusterrolebindings -A{R}")


if __name__ == "__main__":
    main(sys.argv[1])
