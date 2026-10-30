from scapy.all import TCP, UDP, ICMP, IP
from utils import log_alert
from state import state

syn_counter = {}

def detect_suspicious(packet):
    # Detect TCP SYN flood / Port scans
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src = packet[IP].src if packet.haslayer(IP) else "Unknown"
        syn_counter[src] = syn_counter.get(src, 0) + 1

        if syn_counter[src] > 5:
            state.port_scan_alerts += 1
            log_alert(f"[MEDIUM] Port Scan / SYN Flood from {src} (Probe #{syn_counter[src]})")

    # Detect High-Port UDP anomalies (flags all active UDP traffic > 50000)
    if packet.haslayer(UDP):
        port = packet[UDP].dport
        if port > 50000:
            state.suspicious_alerts += 1
            src = packet[IP].src if packet.haslayer(IP) else "Unknown"
            log_alert(f"[LOW] Unusual High-Port UDP traffic to port {port} from {src}")

    # Detect ICMP Ping probes
    if packet.haslayer(ICMP):
        src = packet[IP].src if packet.haslayer(IP) else "Unknown"
        state.suspicious_alerts += 1
        log_alert(f"[LOW] ICMP Ping Packet Detected from {src}")