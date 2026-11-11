#!/usr/bin/env bash
# One command to run the live demo.
#
#   ./demo/start.sh                 all clusters (dev staging prod)
#   ./demo/start.sh dev             just dev
#   ./demo/start.sh dev prod        a selection
#   ./demo/start.sh --here dev      run the monitor in THIS terminal (no kitty window)
#   ./demo/start.sh --no-browser    don't open Chrome
#
# Creates any missing cluster (kind), starts the live monitor with ML weights
# and Trivy image scanning, opens kitty (monitor log · pods · events · drift
# shell) and opens the dashboard in Chrome once the first scan is ready.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.local/bin:$PATH"
PORT="${PORT:-8765}"
INTERVAL="${INTERVAL:-15}"
URL="http://127.0.0.1:$PORT/"

HERE=0; BROWSER=1; CLUSTERS=()
for arg in "$@"; do
  case "$arg" in
    --here) HERE=1 ;;
    --no-browser) BROWSER=0 ;;
    dev|staging|prod) CLUSTERS+=("$arg") ;;
    *) echo "usage: $0 [--here] [--no-browser] [dev] [staging] [prod]"; exit 1 ;;
  esac
done
[[ ${#CLUSTERS[@]} -gt 0 ]] || CLUSTERS=(dev staging prod)

for tool in kind kubectl docker python3; do
  command -v "$tool" >/dev/null || { echo "missing: $tool"; exit 1; }
done
command -v trivy >/dev/null || echo "• trivy not found — CVE scanning will be skipped"

# 1. clusters
missing=()
for env in "${CLUSTERS[@]}"; do
  kind get clusters 2>/dev/null | grep -qx "kav-$env" || missing+=("$env")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "• creating cluster(s): ${missing[*]}"
  ./demo/setup.sh "${missing[@]}"
fi
echo "• clusters: $(printf 'kav-%s ' "${CLUSTERS[@]}")"

# 2. stop a previous demo
./demo/stop.sh >/dev/null 2>&1 || true

CONTEXT_ARGS=()
for env in "${CLUSTERS[@]}"; do CONTEXT_ARGS+=(--context "kind-kav-$env"); done
SERVE=(python3 main.py --weights learned --scan-images serve "${CONTEXT_ARGS[@]}" --interval "$INTERVAL" --port "$PORT")

open_browser_when_ready() {
  for _ in $(seq 1 90); do
    if curl -s "$URL/api/clusters" | grep -q '"version": [1-9]'; then break; fi
    sleep 2
  done
  if command -v google-chrome >/dev/null; then
    setsid google-chrome --new-window "$URL" >/dev/null 2>&1 < /dev/null &
  else
    xdg-open "$URL" >/dev/null 2>&1 &
  fi
  echo "• dashboard opened: $URL"
}

mkdir -p data/live
if [[ $HERE -eq 1 || -z "$(command -v kitty)" ]]; then
  [[ $BROWSER -eq 1 ]] && open_browser_when_ready &
  echo "• live monitor in this terminal (Ctrl+C to stop) — dashboard: $URL"
  COLUMNS="${COLUMNS:-200}" PYTHONUNBUFFERED=1 "${SERVE[@]}" 2>&1 | tee data/live/serve.log
else
  CLUSTERS="${CLUSTERS[*]}" SERVE_CMD="${SERVE[*]}" ./demo/kitty-demo.sh
  [[ $BROWSER -eq 1 ]] && open_browser_when_ready
  echo
  echo "Demo running. Useful commands:"
  echo "  ./demo/drift.sh prod admin-sa         make a risky change (add 'revert' to undo)"
  echo "  ./demo/stop.sh                        stop the monitor (clusters keep running)"
  echo "  ./demo/teardown.sh                    delete the clusters"
fi
