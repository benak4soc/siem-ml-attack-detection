#!/bin/bash
PYTHON=/usr/bin/python3

/opt/splunk/bin/splunk search \
  'index=network_flows sourcetype=cicflowmeter_csv | head 1000 | fields src_ip, dst_ip, src_port, dst_port, protocol, timestamp, flow_duration, flow_byts_s, fwd_iat_tot, bwd_iat_tot, fwd_iat_max, flow_iat_max, idle_max, idle_mean, fwd_header_len' \
  -output csv \
  -auth splunk:splunk@123 2>/dev/null \
| $PYTHON /opt/splunk/etc/apps/network_attack_detect/bin/score_flow.py \
> /opt/splunk/etc/apps/network_attack_detect/lookups/scored_flows.csv
