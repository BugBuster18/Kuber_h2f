#!/usr/bin/env bash
# Delete the demo clusters.   ./demo/teardown.sh [dev staging prod]
set -euo pipefail
CLUSTERS=("${@:-dev staging prod}")
# shellcheck disable=SC2206
CLUSTERS=(${CLUSTERS[*]})
for env in "${CLUSTERS[@]}"; do
  kind delete cluster --name "kav-${env}" || true
done
