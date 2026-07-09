#!/bin/bash
# ============================================================
# Phase 3 — Mix Flows and Verify Splunk Ingestion
# Combines benign + attack CSVs and shuffles for realism
# ============================================================

echo "--- Phase 3: Mixing flows and verifying Splunk ingestion ---"

if [ ! -f /tmp/attack_flows_v2.csv ]; then
    echo "ERROR: /tmp/attack_flows_v2.csv not found. Run Phase 1 first."
    exit 1
fi

if [ ! -f /tmp/benign_flows.csv ] || [ "$(wc -l < /tmp/benign_flows.csv)" -lt 2 ]; then
    echo "  WARNING: No benign flows found. Using attack flows only."
    cp /tmp/attack_flows_v2.csv /tmp/mixed_flows_shuffled.csv
else
    echo "  Combining benign and attack flows..."
    head -1 /tmp/attack_flows_v2.csv > /tmp/mixed_flows_shuffled.csv
    tail -n +2 /tmp/benign_flows.csv >> /tmp/mixed_flows_shuffled.csv
    tail -n +2 /tmp/attack_flows_v2.csv >> /tmp/mixed_flows_shuffled.csv
    echo "  Shuffling rows for realism..."
    shuf /tmp/mixed_flows_shuffled.csv -o /tmp/mixed_flows_shuffled.csv
fi

echo "  Mixed flow file: $(wc -l < /tmp/mixed_flows_shuffled.csv) rows"

# Check Splunk is running
echo "  Checking Splunk status..."
if ! sudo /opt/splunk/bin/splunk status 2>/dev/null | grep -q "splunkd is running"; then
    echo "  Splunk not running — starting..."
    sudo /opt/splunk/bin/splunk start 2>/dev/null
    sleep 20
fi
echo "  Splunk is running."

# Check index event count
echo "  Checking Splunk index event count..."
COUNT=$(sudo /opt/splunk/bin/splunk search \
    'index=network_flows sourcetype=cicflowmeter_csv | stats count' \
    -auth splunk:splunk@123 2>/dev/null | grep -o '[0-9]*' | tail -1)
echo "  Events in Splunk index: ${COUNT:-0}"

echo "Phase 3 complete."
