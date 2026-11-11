#!/usr/bin/env bash
# Introduce (or revert) a realistic misconfiguration in a demo cluster, to
# show the live monitor detecting it.
#
#   ./demo/drift.sh <dev|staging|prod> <scenario>        apply
#   ./demo/drift.sh <dev|staging|prod> <scenario> revert undo
#
# Scenarios (configuration changes only — nothing is exploited):
#   admin-sa       bind the shop/frontend ServiceAccount to cluster-admin
#   open-payments  delete the payments NetworkPolicies
#   expose-redis   expose payments/redis as a NodePort service
set -euo pipefail
cd "$(dirname "$0")"
env="${1:?cluster: dev|staging|prod}"; scenario="${2:?scenario}"; action="${3:-apply}"
ctx="kind-kav-$env"
[[ "$ctx" == kind-kav-* ]] || { echo "refusing non-demo context"; exit 1; }
k() { kubectl --context "$ctx" "$@"; }
say() { printf '\033[1;35m[drift:%s]\033[0m %s\n' "$env" "$*"; }

case "$scenario:$action" in
  admin-sa:apply)
    say "binding shop/frontend ServiceAccount → cluster-admin"
    k create clusterrolebinding kav-drift-frontend-admin --clusterrole=cluster-admin \
      --serviceaccount=shop:frontend --dry-run=client -o yaml | k apply -f - ;;
  admin-sa:revert)
    say "removing the cluster-admin binding"
    k delete clusterrolebinding kav-drift-frontend-admin --ignore-not-found ;;
  open-payments:apply)
    say "deleting payments NetworkPolicies"
    k delete networkpolicy --all -n payments ;;
  open-payments:revert)
    say "restoring payments NetworkPolicies from clusters/$env.yaml"
    k apply -f "clusters/$env.yaml" ;;
  expose-redis:apply)
    say "exposing payments/redis as NodePort"
    k patch service redis -n payments -p '{"spec": {"type": "NodePort"}}' ;;
  expose-redis:revert)
    say "making payments/redis ClusterIP again"
    k patch service redis -n payments --type=json \
      -p '[{"op":"replace","path":"/spec/type","value":"ClusterIP"},{"op":"remove","path":"/spec/ports/0/nodePort"}]' ;;
  *) echo "unknown scenario/action: $scenario $action"; exit 1 ;;
esac
say "done — watch the live monitor"
