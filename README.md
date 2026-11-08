# SIEM ML Attack Detection

A Machine Learning framework for SIEM alert filtering and severity scoring using the CIC-IDS2017 dataset, deployed on Splunk Enterprise 10.4.0.

## Overview

This project trains a Logistic Regression binary classifier to distinguish attack network flows from benign traffic, assigns a calibrated attack probability to each flow, and deploys the model within Splunk Enterprise on Fedora Linux.

**Key results:**
- AUC: 0.98 on held-out test set
- 97% suppression rate of benign flows
- 13× reduction in analyst alert volume vs rule-based baseline
- 30/30 attack flows detected with probability > 0.93

## Repository Structure
## Requirements

- Python 3.14+
- scikit-learn 1.9.0
- joblib, numpy, scapy
- Splunk Enterprise 10.4.0
- CICFlowMeter 0.4.2
- Fedora Linux

## Installation

```bash
# Install Python dependencies
pip3 install scikit-learn joblib numpy scapy --break-system-packages

# Install CICFlowMeter
pip3 install cicflowmeter --break-system-packages

# Deploy Splunk app
sudo cp splunk_app/* /opt/splunk/etc/apps/network_attack_detect/bin/
sudo cp splunk_app/inputs.conf /opt/splunk/etc/apps/network_attack_detect/default/
sudo cp splunk_app/props.conf /opt/splunk/etc/apps/network_attack_detect/default/
sudo /opt/splunk/bin/splunk restart
```

## Usage

```bash
# Run the full pipeline
cd scripts
sudo bash run_all.sh

# Then in Splunk Web UI (http://localhost:8000)
# | inputcsv scored_flows.csv
# | stats count BY ml_label
```

## Model Details

| Parameter | Value |
|---|---|
| Algorithm | Logistic Regression |
| Features | 10 (top variance from 83 CICFlowMeter features) |
| Key features | Flow Bytes/s (coef -5.49), Idle Max (coef +2.62) |
| Decision threshold | 0.5 (nominal), 0.75 (high-confidence alert) |
| Training samples | ~572,925 |
| AUC | 0.98 |

## Splunk Dashboard SPL Queries

```spl
-- Attack vs Benign count
| inputcsv scored_flows.csv | stats count BY ml_label

-- High confidence attacks
| inputcsv scored_flows.csv
| where ml_attack_prob >= 0.75
| table src_ip, dst_ip, dst_port, flow_byts_s, idle_max, ml_attack_prob
| sort - ml_attack_prob
```

## Author

## 1. Benak Patel Medugondanahalli Puradaswamy
## 2. Murat Can Yorgancioglu

## Methods of Artificial Intelligence — Academic Year 2025-2026,

## Supervisors: Prof. Jianmin Chen, Prof. Ioannis Krontiris

## References

- CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- scikit-learn: https://scikit-learn.org
- Splunk Enterprise: https://docs.splunk.com
