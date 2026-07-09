#!/bin/bash
# ============================================================
# Phase 2 — Capture Live Benign Traffic
# Captures 90 seconds of real network traffic on wlp1s0
# ============================================================

echo "--- Phase 2: Capturing benign traffic (90 seconds) ---"

rm -f /tmp/benign_flows.csv

echo "  Starting CICFlowMeter on wlp1s0..."
sudo /usr/local/sbin/cicflowmeter -i wlp1s0 -c /tmp/benign_flows.csv &
CAPTURE_PID=$!

echo "  Generating benign traffic to capture..."
ping -c 30 8.8.8.8    > /dev/null 2>&1 &
curl -s https://example.com   > /dev/null 2>&1 &
curl -s https://google.com    > /dev/null 2>&1 &
wget -q https://wikipedia.org -O /dev/null 2>&1 &
curl -s https://github.com    > /dev/null 2>&1 &

echo "  Waiting 90 seconds..."
sleep 90

sudo kill $CAPTURE_PID 2>/dev/null
wait $CAPTURE_PID 2>/dev/null

echo "  Benign flows captured: $(wc -l < /tmp/benign_flows.csv) rows"
echo "Phase 2 complete."
