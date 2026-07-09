import sys, os, json, csv, io, joblib, numpy as np

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

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')

with open(os.path.join(MODEL_DIR, 'config.json')) as f:
    CFG = json.load(f)

FEATURES  = CFG['features']
THRESHOLD = CFG['threshold']
MODEL     = joblib.load(os.path.join(MODEL_DIR, 'model.joblib'))
SCALER    = joblib.load(os.path.join(MODEL_DIR, 'scaler.joblib'))

def score_record(record):
    try:
        raw = [float(record.get(FEATURE_MAP.get(f, f), 0) or 0) for f in FEATURES]
        X_s = SCALER.transform(np.array(raw).reshape(1, -1))
        prob = float(MODEL.predict_proba(X_s)[0][1])
        record['ml_attack_prob'] = round(prob, 4)
        record['ml_prediction']  = 1 if prob >= THRESHOLD else 0
        record['ml_label']       = 'ATTACK' if prob >= THRESHOLD else 'BENIGN'
    except Exception as e:
        record['ml_attack_prob'] = 0.0
        record['ml_prediction']  = 0
        record['ml_label']       = 'ERROR'
    return record

input_data = sys.stdin.read().strip()
if not input_data:
    sys.exit(0)

# Skip any Splunk metadata lines before the CSV header
lines = input_data.splitlines()
header_idx = 0
for i, line in enumerate(lines):
    if ',' in line and not line.startswith('Job') and not line.startswith('Result'):
        header_idx = i
        break

clean_input = '\n'.join(lines[header_idx:])
reader = csv.DictReader(io.StringIO(clean_input))

fieldnames = [f for f in reader.fieldnames if f not in ('ml_attack_prob','ml_prediction','ml_label')]
fieldnames += ['ml_attack_prob', 'ml_prediction', 'ml_label']

writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, extrasaction='ignore')
writer.writeheader()

for row in reader:
    writer.writerow(score_record(row))
