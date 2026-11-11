#!/usr/bin/env bash
# Stop the live demo (kitty window + monitor). Clusters keep running;
# delete them with ./demo/teardown.sh
pkill -f "kitty --detach --title KubeAttackViz Live Demo" 2>/dev/null && echo "• closed kitty demo window" || true
pkill -f "main.py --weights learned --scan-images serve" 2>/dev/null && echo "• stopped live monitor" || true
pkill -f "demo/pods.sh" 2>/dev/null || true
pkill -f "demo/events.sh" 2>/dev/null || true
pkill -f "kubectl --context kind-kav-.* get events" 2>/dev/null || true
exit 0
