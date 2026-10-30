"""
Network IDS - Attack Traffic Simulator
Generates synthetic attack packets to demonstrate IDS detection capabilities
during presentations and evaluation testing.
"""

import time
import threading
from scapy.all import IP, TCP, UDP, ICMP, ARP
from sniffer import packet_handler
import mitm_detector
from utils import log_alert

def run_simulation(on_progress=None):
    """
    Simulates a sequence of cyber attacks with continuous activity
    to showcase real-time high-frequency detection on the GUI.
    """
    def worker():
        log_alert("[INFO] ========================================")
        log_alert("[INFO] >>> ATTACK SIMULATION INITIATED <<<")
        log_alert("[INFO] ========================================")
        time.sleep(0.4)

        # 1. ICMP Ping Sweep / Probe
        if on_progress: on_progress("Simulating ICMP Probe...")
        log_alert("[SIMULATION] Step 1: Attacker launching ICMP Ping Sweep...")
        for i in range(1, 6):
            pkt_icmp = IP(src=f"192.168.1.{40+i}", dst="192.168.1.1")/ICMP()
            packet_handler(pkt_icmp)
            time.sleep(0.08)
        time.sleep(0.5)

        # 2. Suspicious High-Port UDP Probes
        if on_progress: on_progress("Simulating Suspicious UDP Flood...")
        log_alert("[SIMULATION] Step 2: Attacker launching High-Port UDP Flood...")
        for port in [51234, 52345, 53456, 54567, 55678, 56789, 58000, 59999]:
            pkt_udp = IP(src="192.168.1.45", dst="192.168.1.10")/UDP(sport=12345, dport=port)
            packet_handler(pkt_udp)
            time.sleep(0.06)
        time.sleep(0.5)

        # 3. Aggressive TCP Port Scan / SYN Flood
        if on_progress: on_progress("Simulating TCP SYN Port Scan...")
        log_alert("[SIMULATION] Step 3: Attacker initiating Aggressive TCP SYN Port Scan (30 ports)...")
        attacker_ip = "192.168.1.99"
        for port in range(20, 51):
            syn_pkt = IP(src=attacker_ip, dst="192.168.1.10")/TCP(sport=50000+port, dport=port, flags="S")
            packet_handler(syn_pkt)
            time.sleep(0.03)
        time.sleep(0.5)

        # 4. ARP Spoofing Attacks (Multiple victims)
        if on_progress: on_progress("Simulating ARP Poisoning...")
        log_alert("[SIMULATION] Step 4: Attacker poisoning ARP Cache...")
        victims = [("192.168.1.150", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:11"),
                   ("192.168.1.151", "00:11:22:33:44:66", "aa:bb:cc:dd:ee:22")]
        for vip, legit_mac, fake_mac in victims:
            arp_legit = ARP(op=2, psrc=vip, hwsrc=legit_mac, pdst="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff")
            packet_handler(arp_legit)
            time.sleep(0.1)
            arp_fake = ARP(op=2, psrc=vip, hwsrc=fake_mac, pdst="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff")
            packet_handler(arp_fake)
            time.sleep(0.2)
        time.sleep(0.5)

        # 5. Man-in-the-Middle (MITM) Gateway Impersonation
        if on_progress: on_progress("Simulating MITM Gateway Spoof...")
        gw_ip = mitm_detector.gateway_ip or "192.168.1.1"
        log_alert(f"[SIMULATION] Step 5: Attacker impersonating Default Gateway ({gw_ip})...")

        if mitm_detector.gateway_mac is None:
            gw_legit = ARP(op=2, psrc=gw_ip, hwsrc="10:fe:ed:01:02:03")
            packet_handler(gw_legit)
            time.sleep(0.2)

        for rogue_mac in ["de:ad:be:ef:13:37", "de:ad:be:ef:ff:99"]:
            gw_spoof = ARP(op=2, psrc=gw_ip, hwsrc=rogue_mac)
            packet_handler(gw_spoof)
            time.sleep(0.3)

        log_alert("[INFO] ========================================")
        log_alert("[INFO] >>> SIMULATION COMPLETED: Attack vectors flagged! <<<")
        log_alert("[INFO] ========================================")
        if on_progress: on_progress("Simulation Finished")

    t = threading.Thread(target=worker, daemon=True)
    t.start()

if __name__ == "__main__":
    print("\n--- Running Network IDS Attack Simulator ---")
    run_simulation(on_progress=lambda msg: print(f"[*] {msg}"))
    time.sleep(6)
    print("\n[+] Done! Check logs/alerts.log for recorded events.")
