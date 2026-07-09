#!/bin/bash
# ============================================================
# Phase 6 — Verify Results
# Checks file integrity, confirms src_ip is populated,
# runs CLI verification, prints all Web UI SPL queries
# ============================================================

echo "--- Phase 6: Verifying results ---"

SCORED=/opt/splunk/var/run/splunk/csv/scored_flows.csv

if [ ! -f "$SCORED" ]; then
    echo "ERROR: $SCORED not found. Run Phases 4-5 first."
    exit 1
fi

echo ""
echo "=== scored_flows.csv file check ==="
echo "  Total rows : $(wc -l < $SCORED)"
echo "  ATTACK rows: $(grep -c 'ATTACK' $SCORED)"
echo "  BENIGN rows: $(grep -c 'BENIGN' $SCORED)"

echo ""
echo "  Header (all fields):"
head -1 "$SCORED" | tr ',' '\n' | nl

echo ""
echo "  Sample ATTACK row (first 5 fields):"
grep "ATTACK" "$SCORED" | head -1 | cut -d',' -f1-6

echo ""
echo "  Sample BENIGN row (first 5 fields):"
grep "BENIGN" "$SCORED" | head -1 | cut -d',' -f1-6

echo ""
echo "=== Splunk CLI verification ==="
sudo /opt/splunk/bin/splunk search \
    '| inputcsv scored_flows.csv | stats count BY ml_label' \
    -auth splunk:splunk@123 2>/dev/null

echo ""
echo "=== High confidence attacks (prob >= 0.75) ==="
sudo /opt/splunk/bin/splunk search \
    '| inputcsv scored_flows.csv | where ml_attack_prob >= 0.75 | stats count' \
    -auth splunk:splunk@123 2>/dev/null

echo ""
echo "=========================================="
echo " SPLUNK WEB UI — Copy-paste these searches"
echo " Open: http://fedora.fritz.box:8000"
echo "=========================================="
echo ""
echo "1. Attack vs Benign count (Pie Chart):"
echo "   | inputcsv scored_flows.csv"
echo "   | stats count BY ml_label"
echo ""
echo "2. Top attacking source IPs (Table):"
echo "   | inputcsv scored_flows.csv"
echo "   | where ml_label=\"ATTACK\""
echo "   | table src_ip, dst_ip, dst_port, flow_byts_s, idle_max, ml_attack_prob"
echo "   | sort - ml_attack_prob"
echo ""
echo "3. Probability distribution (Bar Chart):"
echo "   | inputcsv scored_flows.csv"
echo "   | eval prob_bucket=round(ml_attack_prob*10,0)/10"
echo "   | stats count BY prob_bucket"
echo "   | sort prob_bucket"
echo ""
echo "4. Signal-to-noise ratio (Table):"
echo "   | inputcsv scored_flows.csv"
echo "   | stats count AS total,"
echo "           sum(eval(if(ml_label=\"ATTACK\",1,0))) AS attacks,"
echo "           sum(eval(if(ml_label=\"BENIGN\",1,0))) AS suppressed"
echo "   | eval snr=round(attacks/total*100,1).\"%\""
echo "   | eval suppression=round(suppressed/total*100,1).\"%\""
echo "   | table total, attacks, suppressed, snr, suppression"
echo ""
echo "5. High confidence attacks only (Table):"
echo "   | inputcsv scored_flows.csv"
echo "   | where ml_attack_prob >= 0.75"
echo "   | table src_ip, dst_ip, dst_port, flow_byts_s, idle_max, ml_attack_prob"
echo "   | sort - ml_attack_prob"
echo ""
echo "6. Attack probability over time (Line Chart):"
echo "   | inputcsv scored_flows.csv"
echo "   | eval _time=strptime(timestamp, \"%Y-%m-%d %H:%M:%S\")"
echo "   | timechart span=1h avg(ml_attack_prob) BY ml_label"
echo ""
echo "Phase 6 complete."
