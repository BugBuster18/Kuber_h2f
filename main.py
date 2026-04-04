#!/usr/bin/env python3
"""
KubeAttackViz — Kubernetes Attack Path Visualizer

Entry point for the CLI application.

Usage:
    python main.py --help
    python main.py full-report --input mock-cluster-graph.json
    python main.py blast-radius --input mock-cluster-graph.json --source "web-frontend" --depth 4
    python main.py shortest-path --input mock-cluster-graph.json --source "web-frontend" --target "prod-database"
    python main.py cycles --input mock-cluster-graph.json
    python main.py critical-node --input mock-cluster-graph.json
"""

from kube_attack_viz.cli import app

if __name__ == "__main__":
    app()
