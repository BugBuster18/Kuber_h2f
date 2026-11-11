#!/usr/bin/env bash
# Stream Kubernetes events from all demo clusters, prefixed with the cluster.
CLUSTERS=(${@:-dev staging prod})
colors=(36 33 35)
i=0
for env in "${CLUSTERS[@]}"; do
  c=${colors[$((i % 3))]}
  kubectl --context "kind-kav-$env" get events -A --watch-only \
    -o custom-columns='NS:.metadata.namespace,TYPE:.type,REASON:.reason,OBJECT:.involvedObject.name,MESSAGE:.message' \
    --no-headers 2>/dev/null | sed -u "s/^/\x1b[${c}m[$env]\x1b[0m /" &
  i=$((i + 1))
done
printf '\033[2mStreaming events from: %s (Ctrl+C to stop)\033[0m\n' "${CLUSTERS[*]}"
trap 'kill $(jobs -p) 2>/dev/null' EXIT
wait
