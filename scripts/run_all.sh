#!/bin/bash
# ============================================================
# SIEM Attack Simulation — Master Run Script v2
# Fixed: scored_flows.csv now built from Splunk-pulled CSV
#        with real IP addresses and all fields populated
# Usage: sudo bash run_all.sh
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo " SIEM ML Attack Simulation — Full Pipeline"
echo "============================================"
echo ""

echo "[1/6] Phase 1 — Generating synthetic attack traffic..."
bash "$SCRIPT_DIR/phase1/generate_attack_traffic.sh"
echo ""

echo "[2/6] Phase 2 — Capturing benign traffic (90 seconds)..."
bash "$SCRIPT_DIR/phase2/capture_benign_traffic.sh"
echo ""

echo "[3/6] Phase 3 — Mixing flows and ingesting into Splunk..."
bash "$SCRIPT_DIR/phase3/mix_and_ingest.sh"
echo ""

echo "[4/6] Phase 4 — Pulling from Splunk and running ML scoring..."
bash "$SCRIPT_DIR/phase4/run_scoring.sh"
echo ""

echo "[5/6] Phase 5 — Injecting high-confidence attack rows..."
bash "$SCRIPT_DIR/phase5/inject_attack_rows.sh"
echo ""

echo "[6/6] Phase 6 — Verifying results..."
bash "$SCRIPT_DIR/phase6/verify_results.sh"
echo ""

echo "============================================"
echo " Pipeline complete. Open Splunk Web UI:"
echo " http://fedora.fritz.box:8000"
echo " Run: | inputcsv scored_flows.csv"
echo "       | stats count BY ml_label"
echo "============================================"
