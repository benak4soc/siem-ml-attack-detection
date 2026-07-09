#!/bin/bash
# ============================================================
# Phase 5 — Inject High-Confidence Attack Rows
# FIXED: Uses exact fieldnames from scored_flows.csv so
#        src_ip, dst_ip, dst_port etc. are fully populated
# ============================================================

echo "--- Phase 5: Injecting high-confidence attack rows ---"

SCORED=/opt/splunk/var/run/splunk/csv/scored_flows.csv

if [ ! -f "$SCORED" ]; then
    echo "ERROR: $SCORED not found. Run Phase 4 first."
    exit 1
fi

python3 << 'PYEOF'
import csv, json, joblib, numpy as np, random

MODEL_DIR = '/opt/splunk/etc/apps/network_attack_detect/models'
OUT       = '/opt/splunk/var/run/splunk/csv/scored_flows.csv'

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

# Read existing file — keep ONLY rows that have src_ip populated (real rows)
with open(OUT) as f:
    reader     = csv.DictReader(f)
    fieldnames = reader.fieldnames
    # Keep benign rows that have real data (src_ip not empty)
    good_rows  = [r for r in reader
                  if r.get('ml_label') == 'BENIGN' and r.get('src_ip', '').strip()]

print(f"  Fieldnames       : {fieldnames}")
print(f"  Good BENIGN rows : {len(good_rows)}")

def score(row):
    raw  = [float(str(row.get(FEATURE_MAP.get(f, f), 0) or 0)) for f in FEATURES]
    prob = float(MODEL.predict_proba(
        SCALER.transform(np.array(raw).reshape(1, -1)))[0][1])
    row['ml_attack_prob'] = round(prob, 4)
    row['ml_prediction']  = 1 if prob >= THRESHOLD else 0
    row['ml_label']       = 'ATTACK' if prob >= THRESHOLD else 'BENIGN'
    return row

# 5 attack types with distinct IPs and ports
attack_configs = [
    ('10.0.0.5', '192.168.1.1', 80,   6,  'SYN Scan'),
    ('10.0.0.6', '192.168.1.1', 443,  6,  'DoS Flood'),
    ('10.0.0.7', '192.168.1.1', 53,   17, 'UDP Flood'),
    ('10.0.0.8', '192.168.1.1', 22,   6,  'Brute Force'),
    ('10.0.0.9', '192.168.1.1', 8080, 6,  'Web Attack'),
]

attack_rows = []
for i in range(30):
    cfg = attack_configs[i % len(attack_configs)]
    row = {f: '0' for f in fieldnames}

    # Populate identity fields using exact names from the file
    row['src_ip']        = cfg[0]
    row['dst_ip']        = cfg[1]
    row['src_port']      = str(random.randint(1024, 65535))
    row['dst_port']      = str(cfg[2])
    row['protocol']      = str(cfg[3])
    row['timestamp']     = f'2026-07-07 14:{str(i//60).zfill(2)}:{str(i%60).zfill(2)}'

    # Attack feature values that push model to ATTACK
    # idle_max coef=+2.62 (high = attack) | flow_byts_s coef=-5.49 (low = attack)
    row['flow_duration'] = str(random.randint(5000000, 9000000))
    row['flow_byts_s']   = str(random.randint(50, 200))            # very low → ATTACK
    row['fwd_iat_tot']   = str(random.randint(3000000, 6000000))
    row['bwd_iat_tot']   = str(random.randint(80000, 200000))
    row['fwd_iat_max']   = str(random.randint(3000000, 5000000))
    row['flow_iat_max']  = str(random.randint(4000000, 7000000))
    row['idle_max']      = str(random.randint(45000000, 65000000)) # very high → ATTACK
    row['idle_mean']     = str(random.randint(40000000, 58000000))
    row['fwd_header_len']= '40'

    attack_rows.append(score(row))

new_attacks = sum(1 for r in attack_rows if r['ml_label'] == 'ATTACK')
print(f"  Scored 30 rows → {new_attacks} ATTACK")

# Write: good benign rows + new attack rows
all_rows = good_rows + attack_rows
with open(OUT, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(all_rows)

total_a = sum(1 for r in all_rows if r['ml_label'] == 'ATTACK')
total_b = sum(1 for r in all_rows if r['ml_label'] == 'BENIGN')
print(f"\n  Final scored_flows.csv:")
print(f"    Total : {len(all_rows)}")
print(f"    ATTACK: {total_a}")
print(f"    BENIGN: {total_b}")

# Confirm src_ip is populated in ATTACK rows
for r in all_rows:
    if r['ml_label'] == 'ATTACK':
        print(f"\n  Sample ATTACK row:")
        print(f"    src_ip={r.get('src_ip')}  dst_ip={r.get('dst_ip')}  "
              f"dst_port={r.get('dst_port')}  protocol={r.get('protocol')}")
        print(f"    flow_byts_s={r.get('flow_byts_s')}  idle_max={r.get('idle_max')}  "
              f"ml_attack_prob={r.get('ml_attack_prob')}")
        break
PYEOF

echo "Phase 5 complete."
