#!/usr/bin/env bash
# Create the demo clusters (kind) and deploy their workloads.
#   ./demo/setup.sh            # dev staging prod
#   ./demo/setup.sh dev prod   # selected clusters
#   ./demo/setup.sh bench      # public benchmark, small live-demo set (12-node graph)
#   BENCH_FULL=1 ./demo/setup.sh bench   # all of Kubernetes Goat + all 8 Bad Pods
# Idempotent: existing clusters are reused, manifests re-applied.
set -euo pipefail
cd "$(dirname "$0")"

CLUSTERS=("${@:-dev staging prod}")
# shellcheck disable=SC2206
CLUSTERS=(${CLUSTERS[*]})

for env in "${CLUSTERS[@]}"; do
  name="kav-${env}"
  ctx="kind-${name}"
  manifest="clusters/${env}.yaml"
  [[ "$env" == bench ]] && manifest="benchmark/"
  [[ -e "$manifest" ]] || { echo "unknown cluster '$env' (no $manifest)"; exit 1; }

  if kind get clusters 2>/dev/null | grep -x "$name" >/dev/null; then
    echo "• $name exists"
  else
    echo "• creating $name"
    kind create cluster --name "$name" --wait 180s
  fi

  if [[ "$env" == bench ]]; then
    # Upstream manifests, unmodified. Default: a small set for the live demo
    # (12-node graph). BENCH_FULL=1: all of Kubernetes Goat + all eight Bad
    # Pods, the set behind benchmark/results-full.json.
    if [[ -n "${BENCH_FULL:-}" ]]; then
      goat=(benchmark/goat/*.yaml); bad=(benchmark/badpods/*.yaml)
    else
      goat=(benchmark/goat/{system-monitor,hunger-check,internal-proxy}.yaml)
      bad=(benchmark/badpods/{priv,hostpid}.yaml)
    fi
    echo "• applying Kubernetes Goat (${#goat[@]} files) → $ctx"
    for f in "${goat[@]}"; do kubectl --context "$ctx" apply -f "$f"; done
    echo "• applying Bad Pods (${#bad[@]}) → $ctx (namespace badpods)"
    kubectl --context "$ctx" create namespace badpods --dry-run=client -o yaml | kubectl --context "$ctx" apply -f -
    for f in "${bad[@]}"; do kubectl --context "$ctx" apply -n badpods -f "$f"; done
  else
    echo "• applying $manifest → $ctx"
    kubectl --context "$ctx" apply -f "$manifest"
  fi
done

for env in "${CLUSTERS[@]}"; do
  ctx="kind-kav-${env}"
  echo "• waiting for pods in $ctx"
  namespaces="shop payments ci"
  [[ "$env" == bench ]] && namespaces="default big-monolith badpods"
  for ns in $namespaces; do
    kubectl --context "$ctx" wait --for=condition=Ready pod --all -n "$ns" --timeout=300s || true
  done
  kubectl --context "$ctx" get pods -A -l 'app' -o wide --no-headers | awk '{printf "    %-10s %-14s %s\n", $1, $2, $4}'
done
echo "✓ demo clusters ready: $(printf 'kind-kav-%s ' "${CLUSTERS[@]}")"
