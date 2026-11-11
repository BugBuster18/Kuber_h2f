#!/usr/bin/env bash
# Prints the drift commands, then leaves an interactive shell in the repo.
cat <<'TXT'
[1mDemo drift commands[0m (configuration changes only)
  ./demo/drift.sh prod admin-sa            bind shop/frontend SA to cluster-admin
  ./demo/drift.sh prod open-payments       delete the payments NetworkPolicies
  ./demo/drift.sh staging expose-redis     expose payments/redis as NodePort
  … add "revert" to undo, e.g.  ./demo/drift.sh prod admin-sa revert

  kubectl --context kind-kav-prod get pods -A
TXT
exec bash
