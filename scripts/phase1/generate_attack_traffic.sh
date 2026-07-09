#!/bin/bash
# ============================================================
# Phase 1 — Generate Synthetic Attack Traffic
# Creates SYN scan + DoS flood + UDP flood PCAP
# then converts to CICFlowMeter CSV
# ============================================================

echo "--- Phase 1: Generating synthetic attack PCAP ---"

cat > /tmp/gen_attack_pcap_v2.py << 'PYEOF'
from scapy.all import *
import random, time

packets = []
base_time = time.time()

# SYN port scan — hits every port 1-1024
print("  Generating SYN port scan packets (1-1024)...")
for port in range(1, 1024):
    pkt = (
        Ether() /
        IP(src="10.0.0.5", dst="192.168.1.1") /
        TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
    )
    pkt.time = base_time + port * 0.001
    packets.append(pkt)

# DoS flood bursts with long idle gaps (drives up idle_max — strongest attack feature)
print("  Generating DoS flood burst packets (10 bursts)...")
for burst in range(10):
    for i in range(50):
        pkt = (
            Ether() /
            IP(src="10.0.0.6", dst="192.168.1.1") /
            TCP(sport=random.randint(1024, 65535), dport=80, flags="S") /
            Raw(load=b"X" * 1400)
        )
        pkt.time = base_time + 1024*0.001 + (burst * 50) + (i * 0.001)
        packets.append(pkt)
    dummy = (
        Ether() /
        IP(src="10.0.0.6", dst="192.168.1.1") /
        TCP(sport=1234, dport=80, flags="S")
    )
    dummy.time = base_time + 1024*0.001 + (burst * 50) + 45
    packets.append(dummy)

# UDP flood
print("  Generating UDP flood packets (100)...")
for i in range(100):
    pkt = (
        Ether() /
        IP(src="10.0.0.7", dst="192.168.1.1") /
        UDP(sport=random.randint(1024, 65535), dport=53) /
        Raw(load=b"\x00" * random.randint(100, 500))
    )
    pkt.time = base_time + 2000 + i * 0.01
    packets.append(pkt)

wrpcap("/tmp/attack_v2.pcap", packets)
print(f"  Written {len(packets)} attack packets to /tmp/attack_v2.pcap")
PYEOF

echo "  Generating attack PCAP..."
python3 /tmp/gen_attack_pcap_v2.py

echo "  Converting PCAP to CICFlowMeter CSV..."
sudo /usr/local/sbin/cicflowmeter -f /tmp/attack_v2.pcap -c /tmp/attack_flows_v2.csv

echo "  Attack flows generated: $(wc -l < /tmp/attack_flows_v2.csv) rows"
echo "Phase 1 complete."
