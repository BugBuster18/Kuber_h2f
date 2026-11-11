#!/usr/bin/env bash
# Open the live demo in kitty (normally called by ./demo/start.sh):
#   Tab 1  left:  live monitor — kubectl scans, ML attack-path decisions, alerts
#          right: pods across clusters / Kubernetes events
#   Tab 2  a shell for drift commands
# Env: CLUSTERS="dev prod"  SERVE_CMD="python3 main.py ... serve ..."
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8765}"
INTERVAL="${INTERVAL:-15}"
CLUSTERS="${CLUSTERS:-dev staging prod}"
if [[ -z "${SERVE_CMD:-}" ]]; then
  ctx=""; for env in $CLUSTERS; do ctx+=" --context kind-kav-$env"; done
  SERVE_CMD="python3 main.py --weights learned --scan-images serve$ctx --interval $INTERVAL --port $PORT"
fi
mkdir -p "$ROOT/data/live"
: > "$ROOT/data/live/serve.log"
SESSION="$ROOT/data/live/kitty.session"
ENVSETUP="export PATH=\$HOME/.local/bin:\$PATH COLUMNS=230 PYTHONUNBUFFERED=1"

cat > "$SESSION" <<EOF
new_tab KubeAttackViz Live
layout tall:bias=62
cd $ROOT
launch --title "ML attack-path decisions · live monitor" bash -c "$ENVSETUP; $SERVE_CMD 2>&1 | tee data/live/serve.log; exec bash"
launch --title "Pods ($CLUSTERS)" bash -c "$ENVSETUP; ./demo/pods.sh $CLUSTERS"
launch --title "Kubernetes events" bash -c "$ENVSETUP; ./demo/events.sh $CLUSTERS"

new_tab Drift
cd $ROOT
launch --title "drift" bash -c "$ENVSETUP; ./demo/drift-help.sh"
EOF

kitty --detach --title "KubeAttackViz Live Demo" --session "$SESSION"
echo "• kitty launched (monitor · pods · events · drift)"
