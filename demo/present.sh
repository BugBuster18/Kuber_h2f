#!/usr/bin/env bash
# KubeAttackViz — interactive presentation menu.
#   ./demo/present.sh
# List clusters → pick one → pods, RBAC, ML attack-path analysis, live
# dashboard in the browser, inject/revert misconfigurations.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/demo/_python.sh"   # sets $PY: a Python with the project dependencies
export PATH="$HOME/.local/bin:$PATH"
PORT="${PORT:-8765}"
URL="http://127.0.0.1:$PORT/"
ALL=(dev staging prod)
APP_NS="shop payments ci"

# ── colours ──────────────────────────────────────────────────────────────────
B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; MAG=$'\e[35m'; CYN=$'\e[36m'
BRED=$'\e[1;31m'; BGRN=$'\e[1;32m'; BYEL=$'\e[1;33m'; BMAG=$'\e[1;35m'; BCYN=$'\e[1;36m'

posture() {
  case "$1" in
    dev)     echo "${RED}loose${R}    cluster-admin CI + dev-bob, privileged pod, no NetworkPolicies" ;;
    staging) echo "${YEL}mixed${R}    some NetworkPolicies, CI reads every secret, on-call edit" ;;
    prod)    echo "${GRN}hardened${R} PSS restricted, default-deny, no token mounts, break-glass only" ;;
  esac
}

banner() {
  clear
  printf '%s\n' "${BMAG}╔════════════════════════════════════════════════════════════════════╗${R}"
  printf '%s\n' "${BMAG}║${R}  ${B}KubeAttackViz${R} · Kubernetes attack paths with ML-learned weights   ${BMAG}║${R}"
  printf '%s\n' "${BMAG}╚════════════════════════════════════════════════════════════════════╝${R}"
}

link() {  # clickable in kitty and most modern terminals
  printf '\e]8;;%s\e\\%s%s%s\e]8;;\e\\' "$1" "${BCYN}" "$1" "${R}"
}

cluster_state() {  # running | stopped | missing
  local name="kav-$1"
  kind get clusters 2>/dev/null | grep -qx "$name" || { echo missing; return; }
  [[ "$(docker inspect -f '{{.State.Running}}' "$name-control-plane" 2>/dev/null)" == "true" ]] && echo running || echo stopped
}

app_pods() {
  kubectl --context "kind-kav-$1" get pods -A --no-headers 2>/dev/null \
    | awk '$1!="kube-system" && $1!="local-path-storage"' | wc -l
}

pause() { printf '\n%s' "${D}Press Enter to continue…${R}"; read -r _; }

list_clusters() {
  printf '\n  %s%-3s %-12s %-10s %-6s %s%s\n' "$B" "#" "CLUSTER" "STATE" "PODS" "POSTURE" "$R"
  local i=1
  for env in "${ALL[@]}"; do
    local st pods col
    st=$(cluster_state "$env")
    case "$st" in
      running) col=$BGRN; pods=$(app_pods "$env") ;;
      stopped) col=$BYEL; pods="-" ;;
      *)       col=$BRED; pods="-" ;;
    esac
    printf '  %s%-3s%s %s%-12s%s %s%-10s%s %-6s %s\n' "$BCYN" "$i)" "$R" "$B" "kav-$env" "$R" "$col" "$st" "$R" "$pods" "$(posture "$env")"
    i=$((i + 1))
  done
}

ensure_cluster() {
  local env="$1" st
  st=$(cluster_state "$env")
  if [[ "$st" == "missing" ]]; then
    printf '%s\n' "${BYEL}• kav-$env does not exist — creating it (1–2 min)…${R}"
    ./demo/setup.sh "$env"
  elif [[ "$st" == "stopped" ]]; then
    printf '%s\n' "${BYEL}• starting kav-$env…${R}"
    docker start "kav-$env-control-plane" >/dev/null && sleep 8
  fi
}

show_pods() {
  local env="$1"
  printf '\n%s\n' "${BCYN}━━ Pods in kav-$env ━━${R}"
  printf '%s%-10s %-16s %-9s %-4s %-14s %s%s\n' "$B" NAMESPACE POD STATUS READY "SERVICE ACCT" IMAGE "$R"
  for ns in $APP_NS; do
    kubectl --context "kind-kav-$env" get pods -n "$ns" --no-headers \
      -o custom-columns='NAME:.metadata.name,PHASE:.status.phase,READY:.status.containerStatuses[0].ready,SA:.spec.serviceAccountName,IMAGE:.spec.containers[0].image' 2>/dev/null \
      | while read -r name phase ready sa image; do
          c=$GRN; [[ "$phase" != "Running" ]] && c=$YEL
          r="✔"; [[ "$ready" != "true" ]] && r="✘"
          printf '%-10s %s%-16s%s %s%-9s%s %-4s %-14s %s%s%s\n' "$ns" "$B" "$name" "$R" "$c" "$phase" "$R" "$r" "$sa" "$D" "$image" "$R"
        done
  done
  printf '\n%s\n' "${D}kubectl --context kind-kav-$env get pods -A${R}"
}

show_rbac() {
  local env="$1" ctx="kind-kav-$1"
  printf '\n%s\n' "${BCYN}━━ Who can do what in kav-$env (RBAC) ━━${R}"
  "$PY" demo/rbac_view.py "$ctx"
  printf '\n%s\n' "${BCYN}━━ NetworkPolicies ━━${R}"
  local np
  np=$(kubectl --context "$ctx" get networkpolicies -A --no-headers 2>/dev/null | awk '{printf "  %-10s %s\n", $1, $2}')
  if [[ -n "$np" ]]; then printf '%s\n' "$np"; else printf '  %s\n' "${BRED}none — every pod can reach every other pod${R}"; fi
}

run_analysis() {
  local env="$1"
  printf '\n%s\n' "${D}python main.py --weights learned --scan-images analyze -c kind-kav-$env${R}"
  COLUMNS="${COLUMNS:-$(tput cols)}" "$PY" main.py --weights learned --scan-images analyze -c "kind-kav-$env" -n 5
}

explain_edges() {
  local env="$1"
  printf '\n%s\n' "${D}python main.py --weights learned --scan-images ml-edges -k   (context kind-kav-$env)${R}"
  KAV_KUBE_CONTEXT="kind-kav-$env" COLUMNS="${COLUMNS:-$(tput cols)}" \
    "$PY" main.py --weights learned --scan-images ml-edges -k
}

live_monitor() {  # args: env names
  ./demo/stop.sh >/dev/null 2>&1
  local ctx=()
  for env in "$@"; do ensure_cluster "$env"; ctx+=(--context "kind-kav-$env"); done
  mkdir -p data/live
  printf '\n%s %s\n' "${BGRN}● Live dashboard:${R}" "$(link "$URL")"
  printf '%s\n\n' "${D}opens in your browser after the first scan · Ctrl+C returns to the menu${R}"
  (
    for _ in $(seq 1 90); do
      curl -s "$URL/api/clusters" | grep -q '"version": [1-9]' && break
      sleep 2
    done
    if [[ -n "${NO_BROWSER:-}" ]]; then
      :
    elif command -v google-chrome >/dev/null; then
      setsid google-chrome --new-window "$URL" >/dev/null 2>&1 < /dev/null &
    else
      xdg-open "$URL" >/dev/null 2>&1 &
    fi
  ) &
  local opener=$!
  trap 'true' INT
  COLUMNS="${COLUMNS:-$(tput cols)}" PYTHONUNBUFFERED=1 \
    "$PY" main.py --weights learned --scan-images serve "${ctx[@]}" --interval 15 --port "$PORT" 2>&1 \
    | tee data/live/serve.log
  trap - INT
  kill "$opener" 2>/dev/null
  printf '\n%s\n' "${BYEL}■ live monitor stopped${R}"
}

drift_menu() {
  local env="$1"
  printf '\n%s\n' "${BCYN}━━ Inject a misconfiguration into kav-$env ━━${R}  ${D}(configuration only; nothing is exploited)${R}"
  printf '  %s1)%s admin-sa       bind shop/frontend ServiceAccount to cluster-admin\n' "$BCYN" "$R"
  printf '  %s2)%s open-payments  delete the payments NetworkPolicies\n' "$BCYN" "$R"
  printf '  %s3)%s expose-redis   expose payments/redis as a NodePort\n' "$BCYN" "$R"
  printf '  %s4)%s revert all\n' "$BCYN" "$R"
  printf '  %sb)%s back\n' "$BCYN" "$R"
  read -rp "${B}choose › ${R}" c
  case "$c" in
    1) ./demo/drift.sh "$env" admin-sa ;;
    2) ./demo/drift.sh "$env" open-payments ;;
    3) ./demo/drift.sh "$env" expose-redis ;;
    4) for s in admin-sa open-payments expose-redis; do ./demo/drift.sh "$env" "$s" revert 2>/dev/null | tail -1; done ;;
    *) return ;;
  esac
  printf '%s\n' "${D}Run the analysis (3) or the live monitor (5) to see the effect.${R}"
}

cluster_menu() {
  local env="$1"
  ensure_cluster "$env"
  while true; do
    banner
    printf '\n  %s %s%s%s   %s\n' "${B}Cluster:${R}" "$BMAG" "kav-$env" "$R" "$(posture "$env")"
    printf '\n  %s1)%s Show pods\n' "$BCYN" "$R"
    printf '  %s2)%s Show RBAC & NetworkPolicies\n' "$BCYN" "$R"
    printf '  %s3)%s %sRun ML attack-path analysis%s  (scan → CVEs → ML weights → paths → blast radius)\n' "$BCYN" "$R" "$B" "$R"
    printf '  %s4)%s Explain ML weight of every edge\n' "$BCYN" "$R"
    printf '  %s5)%s %sLive monitor + open dashboard in browser%s\n' "$BCYN" "$R" "$B" "$R"
    printf '  %s6)%s Inject / revert a misconfiguration\n' "$BCYN" "$R"
    printf '  %sb)%s Back to clusters\n' "$BCYN" "$R"
    read -rp $'\n'"${B}choose › ${R}" c
    case "$c" in
      1) show_pods "$env"; pause ;;
      2) show_rbac "$env"; pause ;;
      3) run_analysis "$env"; pause ;;
      4) explain_edges "$env"; pause ;;
      5) live_monitor "$env"; pause ;;
      6) drift_menu "$env"; pause ;;
      b|B) return ;;
    esac
  done
}

main_menu() {
  while true; do
    banner
    list_clusters
    printf '\n  %s1-3)%s select a cluster    %sa)%s live monitor ALL clusters    %sc)%s create missing clusters    %sq)%s quit\n' \
      "$BCYN" "$R" "$BCYN" "$R" "$BCYN" "$R" "$BCYN" "$R"
    read -rp $'\n'"${B}choose › ${R}" c
    case "$c" in
      1|2|3) cluster_menu "${ALL[$((c - 1))]}" ;;
      a|A) live_monitor "${ALL[@]}"; pause ;;
      c|C) ./demo/setup.sh; pause ;;
      q|Q) printf '%s\n' "${D}bye — clusters keep running (./demo/teardown.sh deletes them)${R}"; exit 0 ;;
    esac
  done
}

for tool in kind kubectl docker python3; do
  command -v "$tool" >/dev/null || { echo "${BRED}missing: $tool${R}"; exit 1; }
done
main_menu
