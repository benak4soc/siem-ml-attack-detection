#!/bin/bash
# ============================================================
# Phase 4 — Pull Events from Splunk and Run ML Scoring
# FIXED: Uses -output csv with explicit table fields so
#        src_ip, dst_ip etc. are preserved in scored output
# ============================================================

echo "--- Phase 4: Pulling from Splunk and running ML scoring ---"

SPLUNK_HOME=/opt/splunk
APP_BIN=$SPLUNK_HOME/etc/apps/network_attack_detect/bin
OUT_DIR=/opt/splunk/var/run/splunk/csv
RAW=/tmp/splunk_flows_raw.csv
SCORED=$OUT_DIR/scored_flows.csv

mkdir -p "$OUT_DIR"

# Step 1 — Pull events from Splunk with all needed fields
echo "  Pulling events from Splunk index (up to 1000)..."
$SPLUNK_HOME/bin/splunk search \
    'index=network_flows sourcetype=cicflowmeter_csv
    | head 1000
    | table src_ip, dst_ip, src_port, dst_port, protocol, timestamp,
            flow_duration, flow_byts_s, fwd_iat_tot, bwd_iat_tot,
            fwd_iat_max, flow_iat_max, idle_max, idle_mean, fwd_header_len' \
    -output csv \
    -auth splunk:splunk@123 2>/dev/null \
    > "$RAW"

PULLED=$(wc -l < "$RAW")
echo "  Pulled $PULLED rows from Splunk"

# Step 2 — If Splunk index is empty, fall back to mixed flows CSV
if [ "$PULLED" -lt 2 ]; then
    echo "  Splunk index empty — falling back to /tmp/mixed_flows_shuffled.csv"
    if [ ! -f /tmp/mixed_flows_shuffled.csv ]; then
        echo "ERROR: /tmp/mixed_flows_shuffled.csv not found. Run Phase 1-3 first."
        exit 1
    fi
    # Extract only the columns score_flow.py needs
    python3 << 'PYEOF'
import csv

IN  = '/tmp/mixed_flows_shuffled.csv'
OUT = '/tmp/splunk_flows_raw.csv'

KEEP = ['src_ip','dst_ip','src_port','dst_port','protocol','timestamp',
        'flow_duration','flow_byts_s','fwd_iat_tot','bwd_iat_tot',
        'fwd_iat_max','flow_iat_max','idle_max','idle_mean','fwd_header_len']

with open(IN) as fin, open(OUT, 'w', newline='') as fout:
    reader = csv.DictReader(fin)
    actual = [f for f in KEEP if f in reader.fieldnames]
    writer = csv.DictWriter(fout, fieldnames=actual, extrasaction='ignore')
    writer.writeheader()
    for row in reader:
        writer.writerow(row)

print(f"  Extracted {actual} fields from mixed_flows_shuffled.csv")
PYEOF
fi

# Step 3 — Score with score_flow.py
echo "  Running score_flow.py..."
python3 << 'PYEOF'
import csv, io, json, sys, os, joblib, numpy as np

RAW_IN    = '/tmp/splunk_flows_raw.csv'
SCORED_OUT = '/opt/splunk/var/run/splunk/csv/scored_flows.csv'
MODEL_DIR  = '/opt/splunk/etc/apps/network_attack_detect/models'

with open(f'{MODEL_DIR}/config.json') as f:
    CFG = json.load(f)

FEATURES  = CFG['features']
THRESHOLD = CFG['threshold']
MODEL     = joblib.load(f'{MODEL_DIR}/model.joblib')
SCALER    = joblib.load(f'{MODEL_DIR}/scaler.joblib')

FEATURE_MAP = {
    " Fwd Header Length.1": "fwd_header_len",
    " Fwd Header Length":   "fwd_header_len",
    " Flow Duration":       "flow_duration",
    "Fwd IAT Total":        "fwd_iat_tot",
    "Bwd IAT Total":        "bwd_iat_tot",
    "Flow Bytes/s":         "flow_byts_s",
    " Fwd IAT Max":         "fwd_iat_max",
    " Flow IAT Max":        "flow_iat_max",
    " Idle Max":            "idle_max",
    "Idle Mean":            "idle_mean",
}

def score(row):
    raw  = [float(str(row.get(FEATURE_MAP.get(f, f), 0) or 0).strip('"')) for f in FEATURES]
    prob = float(MODEL.predict_proba(
        SCALER.transform(np.array(raw).reshape(1, -1)))[0][1])
    row['ml_attack_prob'] = round(prob, 4)
    row['ml_prediction']  = 1 if prob >= THRESHOLD else 0
    row['ml_label']       = 'ATTACK' if prob >= THRESHOLD else 'BENIGN'
    return row

with open(RAW_IN) as f:
    reader     = csv.DictReader(f)
    # Strip quotes from field names (Splunk -output csv adds them)
    raw_fields  = [h.strip('"') for h in reader.fieldnames]
    raw_rows    = [{k.strip('"'): v.strip('"') for k, v in row.items()} for row in reader]

scored_rows = [score(row) for row in raw_rows]
fieldnames  = raw_fields + ['ml_attack_prob', 'ml_prediction', 'ml_label']

with open(SCORED_OUT, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(scored_rows)

attacks = sum(1 for r in scored_rows if r['ml_label'] == 'ATTACK')
benign  = sum(1 for r in scored_rows if r['ml_label'] == 'BENIGN')
print(f"  Scored {len(scored_rows)} rows → {attacks} ATTACK, {benign} BENIGN")
print(f"  Output fields: {fieldnames}")
PYEOF

echo "  Header check (last 3 fields):"
head -1 "$SCORED" | tr ',' '\n' | tail -3

echo "Phase 4 complete."
