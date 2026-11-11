#!/usr/bin/env bash
# Create the three demo clusters (kind) and deploy their workloads.
#   ./demo/setup.sh            # all clusters
#   ./demo/setup.sh dev prod   # selected clusters
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
  [[ -f "$manifest" ]] || { echo "unknown cluster '$env' (no $manifest)"; exit 1; }

  if kind get clusters 2>/dev/null | grep -qx "$name"; then
    echo "• $name exists"
  else
    echo "• creating $name"
    kind create cluster --name "$name" --wait 180s
  fi

  echo "• applying $manifest → $ctx"
  kubectl --context "$ctx" apply -f "$manifest"
done

for env in "${CLUSTERS[@]}"; do
  ctx="kind-kav-${env}"
  echo "• waiting for pods in $ctx"
  for ns in shop payments ci; do
    kubectl --context "$ctx" wait --for=condition=Ready pod --all -n "$ns" --timeout=300s || true
  done
  kubectl --context "$ctx" get pods -A -l 'app' -o wide --no-headers | awk '{printf "    %-10s %-14s %s\n", $1, $2, $4}'
done
echo "✓ demo clusters ready: $(printf 'kind-kav-%s ' "${CLUSTERS[@]}")"
