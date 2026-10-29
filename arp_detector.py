from scapy.all import ARP
from utils import log_alert
from state import state

ip_mac = {}

def detect_arp_spoof(packet):

    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]

    if arp.op != 2:
        return

    ip = arp.psrc
    mac = arp.hwsrc

    if ip in ip_mac and ip_mac[ip] != mac:
        state.arp_alerts += 1
        log_alert(f"[HIGH] ARP Spoof Attempt - {ip} mapped to {mac}")

    ip_mac[ip] = mac