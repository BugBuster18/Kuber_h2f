#!/usr/bin/env bash
# Presentation: the four views, switched from this terminal.
#
#   ./demo/views.sh              live cluster = prod (default)
#   ./demo/views.sh dev          live cluster = dev
#   ./demo/views.sh bench        live cluster = the public benchmark (Goat + Bad Pods)
#   SAMPLE=other.json ./demo/views.sh
#   VIEW=4 TAB=bench ./demo/views.sh bench   start on view 4 with the benchmark tab open
#
#   1) Sample cluster · old weights      3) Live cluster · old weights
#   2) Sample cluster · ML weights       4) Live cluster · ML weights
#
# Starts the dashboard server (if it isn't running), opens the browser, then
# every key you press here switches the view in the browser within a second.
# Views 3-4 keep rescanning the live cluster, so a change made in the cluster
# (e.g. ./demo/drift.sh prod admin-sa) shows up in them on its own.
# Stop the server with ./demo/stop.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/demo/_python.sh"   # sets $PY: a Python with the project dependencies
export PATH="$HOME/.local/bin:$PATH"
PORT="${PORT:-8765}"
INTERVAL="${INTERVAL:-15}"
URL="http://127.0.0.1:$PORT"
PAGE="$URL/${TAB:+?tab=$TAB}"   # the browser link (TAB=bench opens the benchmark answer key)
SAMPLE="${SAMPLE:-mock-cluster-graph.json}"
ENV_NAME="${1:-prod}"
CTX="kind-kav-$ENV_NAME"

B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
BMAG=$'\e[1;35m'; BCYN=$'\e[1;36m'; BGRN=$'\e[1;32m'; BRED=$'\e[1;31m'; BYEL=$'\e[1;33m'; VIO=$'\e[38;5;99m'

case "$ENV_NAME" in bench|dev|staging|prod) ;; *) echo "usage: $0 [bench|dev|staging|prod]"; exit 1 ;; esac
[[ -f "$SAMPLE" ]] || { echo "${BRED}sample cluster not found:${R} $SAMPLE"; exit 1; }
if ! kubectl config get-contexts -o name 2>/dev/null | grep -x "$CTX" >/dev/null; then
  echo "${BRED}cluster $CTX not found.${R} Create it with: ./demo/setup.sh $ENV_NAME"; exit 1
fi

demo_state() { curl -s --max-time 2 "$URL/api/demo" 2>/dev/null; }

# 1. server: reuse a running one only if it is already in presentation mode for this cluster
state="$(demo_state)"
if [[ "$state" != *'"enabled": true'* || "$state" != *"\"context\": \"$CTX\""* ]]; then
  ./demo/stop.sh >/dev/null 2>&1 || true
  mkdir -p data/live
  echo "• starting the dashboard server (live cluster: ${B}$CTX${R}, sample: ${B}$SAMPLE${R})"
  setsid env COLUMNS=200 PYTHONUNBUFFERED=1 "$PY" main.py --weights learned --scan-images serve \
      --context "$CTX" --demo-sample "$SAMPLE" --interval "$INTERVAL" --port "$PORT" \
      > data/live/views.log 2>&1 < /dev/null &
  for _ in $(seq 1 60); do
    [[ "$(demo_state)" == *'"enabled": true'* ]] && break
    sleep 1
  done
  [[ "$(demo_state)" == *'"enabled": true'* ]] || { echo "${BRED}server did not start${R} — see data/live/views.log"; exit 1; }
  OPEN=1
fi
[[ -n "${VIEW:-}" ]] && curl -s --max-time 3 -X POST "$URL/api/demo/view?view=$VIEW" >/dev/null
if [[ -n "${OPEN:-}" || -n "${TAB:-}" ]]; then
  if command -v google-chrome >/dev/null; then
    setsid google-chrome --new-window "$PAGE" >/dev/null 2>&1 < /dev/null &
  else
    xdg-open "$PAGE" >/dev/null 2>&1 &
  fi
  echo "• dashboard opened: $PAGE   (server log: data/live/views.log)"
fi

# 2. menu
show() {  # $1 = view number
  curl -s --max-time 3 -X POST "$URL/api/demo/view?view=$1" >/dev/null || echo "${BRED}server unreachable${R}"
}

status_line() {  # readiness of the live views + top path of the current view
  "$PY" - "$URL" <<'EOF' 2>/dev/null
import json, sys, urllib.request
url = sys.argv[1]
s = json.load(urllib.request.urlopen(url + "/api/demo", timeout=3))
L = s["live"]
live = (f"live {L['context'].removeprefix('kind-')}: scan #{L['scans']} ({L['scan_seconds']}s)"
        if L["scans"] else f"live {L['context'].removeprefix('kind-')}: first scan running…")
v = next(x for x in s["views"] if x["id"] == s["view"])
line = f"  now showing view {v['id']}: {v['cluster_label']} · {v['weights_label']}   [{live}]"
if v["ready"]:
    g = json.load(urllib.request.urlopen(f"{url}/api/demo/graph?view={v['id']}", timeout=5))
    for i, p in enumerate(g.get("attack_paths", [])[:4], 1):
        score = (f"P={p['success_probability'] * 100:.1f}%" if p.get("success_probability") is not None
                 else f"risk {p['total_risk']:.2f}")
        line += f"\n     #{i} {' → '.join(p['path_names'])}   ({score}, {p['severity']})"
else:
    line += "\n     (waiting for the first scan of the live cluster — the view appears by itself)"
print(line)
EOF
}

menu() {
  clear
  printf '%s\n' "${BMAG}╔══════════════════════════════════════════════════════════════════╗${R}"
  printf '%s\n' "${BMAG}║${R}  ${B}KubeAttackViz${R} · presentation views  ${D}(browser follows this menu)${R} ${BMAG}║${R}"
  printf '%s\n' "${BMAG}╚══════════════════════════════════════════════════════════════════╝${R}"
  echo
  echo "  ${B}Sample cluster${R} ${D}($SAMPLE)${R}"
  echo "    ${BCYN}1${R}) old weights  ${D}— paper-style hand-set coefficients${R}"
  echo "    ${BCYN}2${R}) ${VIO}ML weights${R}   ${D}— weight = −ln P(success), CVE model trained on NVD + CISA KEV${R}"
  echo
  echo "  ${B}Live cluster${R} ${D}($CTX, rescanned every ${INTERVAL}s)${R}"
  echo "    ${BCYN}3${R}) old weights"
  echo "    ${BCYN}4${R}) ${VIO}ML weights${R}"
  echo
  printf '  %s %s\n\n' "${B}Dashboard:${R}" "$(printf '\e]8;;%s\e\\%s%s%s\e]8;;\e\\' "$PAGE" "$BCYN" "$PAGE" "$R")"
  echo "    ${BCYN}q${R}) quit menu  ${D}(server keeps running; stop it with ./demo/stop.sh)${R}"
  echo
  status_line
  echo
}

menu
while true; do
  read -rsn1 -p "  ${B}view [1-4, q]:${R} " key || break
  echo
  case "$key" in
    1|2|3|4) show "$key"; sleep 0.3; menu ;;
    q|Q) echo "  bye — dashboard still at $URL/"; break ;;
    "") menu ;;
    *) echo "  ${BYEL}press 1, 2, 3, 4 or q${R}" ;;
  esac
done
