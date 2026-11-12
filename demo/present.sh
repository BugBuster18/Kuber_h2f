#!/usr/bin/env bash
# KubeAttackViz — the one script to run the project.
#   ./demo/present.sh
# Pick a cluster → pods, RBAC, live dashboard, old-vs-ML weight views, and
# the benchmark against attack paths documented by Kubernetes Goat and Bad Pods.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/demo/_python.sh"   # sets $PY: a Python with the project dependencies
export PATH="$HOME/.local/bin:$PATH"
PORT="${PORT:-8765}"
URL="http://127.0.0.1:$PORT/"
ALL=(bench dev staging prod)

app_namespaces() {
  case "$1" in
    bench) echo "default big-monolith badpods" ;;
    *)     echo "shop payments ci" ;;
  esac
}

# ── colours ──────────────────────────────────────────────────────────────────
B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; MAG=$'\e[35m'; CYN=$'\e[36m'
BRED=$'\e[1;31m'; BGRN=$'\e[1;32m'; BYEL=$'\e[1;33m'; BMAG=$'\e[1;35m'; BCYN=$'\e[1;36m'

posture() {
  case "$1" in
    bench)   echo "${BMAG}public${R}   Kubernetes Goat + Bad Pods (unmodified upstream manifests, 12-node demo set)" ;;
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
  kind get clusters 2>/dev/null | grep -x "$name" >/dev/null || { echo missing; return; }
  [[ "$(docker inspect -f '{{.State.Running}}' "$name-control-plane" 2>/dev/null)" == "true" ]] && echo running || echo stopped
}

app_pods() {
  kubectl --context "kind-kav-$1" get pods -A --no-headers 2>/dev/null \
    | awk '$1!="kube-system" && $1!="local-path-storage"' | wc -l
}

pause() { printf '\n%s' "${D}Press Enter to continue…${R}"; read -r _; }

list_clusters() {   # $1 = current cluster (marked ▶)
  local cur="${1:-}" e k=0 letters=(a b c d e f g h)
  printf '\n  %s%-3s %-12s %-10s %-6s %s%s\n' "$B" "" "CLUSTER" "STATE" "PODS" "POSTURE" "$R"
  for e in "${ALL[@]}"; do
    local st pods col mark="  "
    st=$(cluster_state "$e")
    case "$st" in
      running) col=$BGRN; pods=$(app_pods "$e") ;;
      stopped) col=$BYEL; pods="-" ;;
      *)       col=$BRED; pods="-" ;;
    esac
    [[ "$e" == "$cur" ]] && mark="${BMAG}▶${R} "
    printf '  %s%s%s)%s %s%-12s%s %s%-10s%s %-6s %s\n' "$mark" "$BCYN" "${letters[$k]}" "$R" "$B" "kav-$e" "$R" "$col" "$st" "$R" "$pods" "$(posture "$e")"
    k=$((k + 1))
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
  local nw=10 pw=16 sw=14                 # column widths; the benchmark has long upstream names
  [[ "$env" == bench ]] && nw=17 pw=48 sw=15
  printf "%s%-${nw}s %-${pw}s %-9s %-5s %-${sw}s %s%s\n" "$B" NAMESPACE POD STATUS READY "SERVICE ACCT" IMAGE "$R"
  for ns in $(app_namespaces "$env"); do
    kubectl --context "kind-kav-$env" get pods -n "$ns" --no-headers \
      -o custom-columns='NAME:.metadata.name,PHASE:.status.phase,READY:.status.containerStatuses[0].ready,SA:.spec.serviceAccountName,IMAGE:.spec.containers[0].image' 2>/dev/null \
      | while read -r name phase ready sa image; do
          c=$GRN; [[ "$phase" != "Running" ]] && c=$YEL
          r="✔"; [[ "$ready" != "true" ]] && r="✘"
          printf "%-${nw}s %s%-${pw}s%s %s%-9s%s %-5s %-${sw}s %s%s%s\n" "$ns" "$B" "$name" "$R" "$c" "$phase" "$R" "$r" "$sa" "$D" "$image" "$R"
        done
  done
  printf '\n%s\n' "${D}kubectl --context kind-kav-$env get pods -A${R}"
}

weight_views() {   # the 4 dashboard views: sample/live cluster x old/ML weights
  local env="$1"
  ./demo/views.sh "$env"
}

run_benchmark() {
  ensure_cluster bench
  printf '\n%s\n' "${D}python main.py --scan-images benchmark -c kind-kav-bench${R}"
  COLUMNS="${COLUMNS:-$(tput cols)}" "$PY" main.py --scan-images benchmark -c kind-kav-bench || return
  printf '\n%s %s\n' "${BGRN}● See it live:${R}" "$(link "${URL}?tab=bench")"
  printf '%s\n' "${D}kav-bench in the dashboard: views 3/4 = old/ML weights, tab “Benchmark” = the table above with links; click a row to light up that path${R}"
  read -rp $'\n'"${B}Enter = open it live in the browser, q = back to menu › ${R}" k
  [[ "${k,,}" == q ]] && return
  VIEW=4 TAB=bench ./demo/views.sh bench
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

main_menu() {   # one menu: the cluster table on top, actions below; s then a-d switches cluster
  local env="${ALL[0]}" i k
  while true; do
    banner
    list_clusters "$env"
    printf '\n  %s1)%s Show pods\n' "$BCYN" "$R"
    printf '  %s2)%s Show RBAC & NetworkPolicies\n' "$BCYN" "$R"
    printf '  %s3)%s %sLive monitor + open dashboard in browser%s\n' "$BCYN" "$R" "$B" "$R"
    printf '  %s4)%s %sOld vs ML weights%s  (4 dashboard views: sample / this cluster × old / ML)\n' "$BCYN" "$R" "$B" "$R"
    printf '  %s5)%s %sBenchmark%s  (our paths vs paths documented by Kubernetes Goat + Bad Pods)\n' "$BCYN" "$R" "$B" "$R"
    printf '\n  %ss)%s switch cluster (now %s%s%s)    %sq)%s quit\n' "$BCYN" "$R" "$BMAG" "kav-$env" "$R" "$BCYN" "$R"
    read -rp $'\n'"${B}choose › ${R}" c
    case "$c" in
      1) ensure_cluster "$env"; show_pods "$env"; pause ;;
      2) ensure_cluster "$env"; show_rbac "$env"; pause ;;
      3) live_monitor "$env"; pause ;;
      4) ensure_cluster "$env"; weight_views "$env" ;;
      5) run_benchmark ;;
      s|S) read -rp "  ${B}which cluster [a-$(printf "\\x$(printf %x $((96 + ${#ALL[@]})))")] › ${R}" k
           i=$(( $(printf '%d' "'${k,,}") - 97 ))
           if [[ ${#k} -eq 1 ]] && (( i >= 0 && i < ${#ALL[@]} )); then env="${ALL[$i]}"; fi ;;
      q|Q) printf '%s\n' "${D}bye — clusters keep running (./demo/teardown.sh deletes them)${R}"; exit 0 ;;
    esac
  done
}

for tool in kind kubectl docker python3; do
  command -v "$tool" >/dev/null || { echo "${BRED}missing: $tool${R}"; exit 1; }
done
main_menu
