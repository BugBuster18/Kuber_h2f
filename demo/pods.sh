#!/usr/bin/env bash
# Live pod overview across the demo clusters (refreshes every 3s).
CLUSTERS=(${@:-dev staging prod})
while true; do
  out=$(
    printf '\033[1m%-9s %-10s %-14s %-9s %-8s %-6s %s\033[0m\n' CLUSTER NAMESPACE POD STATUS RESTARTS AGE IMAGE
    for env in "${CLUSTERS[@]}"; do
      kubectl --context "kind-kav-$env" get pods -A --no-headers \
        -o custom-columns='NS:.metadata.namespace,POD:.metadata.name,STATUS:.status.phase,RESTARTS:.status.containerStatuses[0].restartCount,START:.status.startTime,IMAGE:.spec.containers[0].image' \
        2>/dev/null | awk -v env="$env" '$1!="kube-system" && $1!="local-path-storage" {
          cmd="date -d " $5 " +%s"; cmd | getline t; close(cmd);
          age=systime()-t; a=(age>3600)? int(age/3600) "h" : (age>60 ? int(age/60) "m" : age "s");
          color=($3=="Running")?"\033[32m":"\033[33m";
          printf "%-9s %-10s %-14s %s%-9s\033[0m %-8s %-6s %s\n", env, $1, $2, color, $3, $4, a, $6 }'
      echo
    done
    printf '\033[2m%s · kubectl get pods -A (every 3s)\033[0m\n' "$(date +%T)"
  )
  clear
  printf '%s\n' "$out"
  sleep 3
done
