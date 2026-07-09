============================================================
 SIEM ML Attack Detection — Script Package v2
 FIXED: scored_flows.csv now has src_ip, dst_ip, dst_port
        and all flow fields fully populated in every row
============================================================

WHAT CHANGED FROM v1
--------------------
- Phase 4 now pulls events from Splunk using -output csv
  with explicit table fields (src_ip, dst_ip etc.) so all
  columns are preserved in the scored output file
- Phase 4 falls back to /tmp/mixed_flows_shuffled.csv if
  the Splunk index is empty
- Phase 5 reads exact fieldnames from the scored file and
  uses them directly — no more empty columns in ATTACK rows
- Phase 5 strips out old broken ATTACK rows before injecting
  fresh ones with real IP addresses

PREREQUISITES
-------------
- Splunk running at http://fedora.fritz.box:8000
- Credentials: splunk:splunk@123
- CICFlowMeter: /usr/local/sbin/cicflowmeter
- Network interface: wlp1s0
- Model artefacts at:
    /opt/splunk/etc/apps/network_attack_detect/models/model.joblib
    /opt/splunk/etc/apps/network_attack_detect/models/scaler.joblib
    /opt/splunk/etc/apps/network_attack_detect/models/config.json
- score_flow.py at:
    /opt/splunk/etc/apps/network_attack_detect/bin/score_flow.py

============================================================
OPTION A — RUN EVERYTHING IN ONE COMMAND
============================================================

  sudo bash run_all.sh

============================================================
OPTION B — RUN PHASES INDIVIDUALLY
============================================================

  sudo bash phase1/generate_attack_traffic.sh
  sudo bash phase2/capture_benign_traffic.sh
  sudo bash phase3/mix_and_ingest.sh
  sudo bash phase4/run_scoring.sh
  sudo bash phase5/inject_attack_rows.sh
  sudo bash phase6/verify_results.sh

============================================================
EXPECTED OUTPUT AFTER PHASE 5
============================================================

  grep "ATTACK" /opt/splunk/var/run/splunk/csv/scored_flows.csv | head -1 | cut -d',' -f1-5
  10.0.0.5,192.168.1.1,54321,80,6

  ATTACK: 30 rows  (prob 0.93–0.99)
  BENIGN: ~100 rows (prob ~0.47)

============================================================
SPLUNK WEB UI SPL QUERIES
============================================================

1. Attack vs Benign:
   | inputcsv scored_flows.csv | stats count BY ml_label

2. Top attacking IPs:
   | inputcsv scored_flows.csv
   | where ml_label="ATTACK"
   | table src_ip, dst_ip, dst_port, flow_byts_s, idle_max, ml_attack_prob
   | sort - ml_attack_prob

3. Probability distribution:
   | inputcsv scored_flows.csv
   | eval prob_bucket=round(ml_attack_prob*10,0)/10
   | stats count BY prob_bucket | sort prob_bucket

4. Signal-to-noise ratio:
   | inputcsv scored_flows.csv
   | stats count AS total,
           sum(eval(if(ml_label="ATTACK",1,0))) AS attacks,
           sum(eval(if(ml_label="BENIGN",1,0))) AS suppressed
   | eval snr=round(attacks/total*100,1)."%"
   | eval suppression=round(suppressed/total*100,1)."%"
   | table total, attacks, suppressed, snr, suppression

5. High confidence attacks:
   | inputcsv scored_flows.csv
   | where ml_attack_prob >= 0.75
   | table src_ip, dst_ip, dst_port, flow_byts_s, idle_max, ml_attack_prob
   | sort - ml_attack_prob

6. Timechart:
   | inputcsv scored_flows.csv
   | eval _time=strptime(timestamp, "%Y-%m-%d %H:%M:%S")
   | timechart span=1h avg(ml_attack_prob) BY ml_label
