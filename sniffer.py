from scapy.all import sniff, get_if_list, get_if_addr, TCP, UDP, ICMP, ARP
from arp_detector import detect_arp_spoof
from suspicious_traffic import detect_suspicious
from mitm_detector import analyze_for_mitm
from state import state
import platform

# Windows-only COM initialization
if platform.system() == "Windows":
    try:
        import pythoncom
    except ImportError:
        pythoncom = None
    try:
        import wmi
    except ImportError:
        wmi = None
else:
    pythoncom = None
    wmi = None


def packet_handler(packet):
    state.packet_count += 1
    # Lightweight protocol breakdown used by the web dashboard analytics.
    if packet.haslayer(TCP):
        state.protocol_counts["TCP"] += 1
    elif packet.haslayer(UDP):
        state.protocol_counts["UDP"] += 1
    elif packet.haslayer(ICMP):
        state.protocol_counts["ICMP"] += 1
    elif packet.haslayer(ARP):
        state.protocol_counts["ARP"] += 1
    else:
        state.protocol_counts["OTHER"] += 1

    detect_arp_spoof(packet)
    detect_suspicious(packet)
    analyze_for_mitm(packet)

    if state.gui:
        state.gui.update_stats(
            state.packet_count,
            state.arp_alerts,
            state.mitm_alerts,
            state.port_scan_alerts,
            state.suspicious_alerts
        )


def choose_interface(prompt_user=True):
    interfaces = get_if_list()
    if not interfaces:
        return None

    try:
        import mitm_detector
        gw_prefix = ".".join(mitm_detector.gateway_ip.split(".")[:2]) if mitm_detector.gateway_ip else ""
    except Exception:
        gw_prefix = ""

    # Detect the best active interface
    best_index = 0
    found_gw_match = False
    for i, iface in enumerate(interfaces):
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "No IP"
        # Match gateway subnet first (e.g. 10.199.x.x)
        if gw_prefix and ip.startswith(gw_prefix):
            best_index = i
            found_gw_match = True
            break
        elif not found_gw_match and ip not in ("No IP", "0.0.0.0") and not ip.startswith(("127.", "169.254.", "192.168.56.")):
            best_index = i

    if not prompt_user:
        return interfaces[best_index]

    print("\n--- Available Network Interfaces ---")
    for i, iface in enumerate(interfaces):
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "No IP"

        name = iface
        if "VMnet8" in iface:
            name = "VMware NAT"
        elif "VMnet1" in iface:
            name = "VMware HostOnly"
        elif "Wi-Fi" in iface or "WiFi" in iface:
            name = "WiFi"
        elif "Ethernet" in iface:
            name = "Ethernet"

        marker = "  <-- (Active/Recommended)" if i == best_index else ""
        print(f"[{i}] : {name} ({ip}){marker}")

    try:
        user_input = input(f"\nSelect interface number (press Enter for default [{best_index}]): ").strip()
        choice = int(user_input) if user_input else best_index
    except Exception:
        choice = best_index

    if 0 <= choice < len(interfaces):
        return interfaces[choice]
    return interfaces[best_index]


def start_sniffer(iface=None, prompt_user=True, stop_event=None):
    if pythoncom:
        pythoncom.CoInitialize()

    if iface is None:
        iface = choose_interface(prompt_user=prompt_user)

    print(f"\n[+] Sniffing started on: {iface}\n")

    try:
        if stop_event is None:
            sniff(iface=iface, prn=packet_handler, store=False)
        else:
            # A short timeout lets the web dashboard stop capture without
            # blocking indefinitely inside Scapy's sniff().
            while not stop_event.is_set():
                sniff(
                    iface=iface,
                    prn=packet_handler,
                    store=False,
                    timeout=1
                )
    except Exception as e:
        print(f"[-] Sniffing error: {e}")
        raise


if __name__ == "__main__":
    start_sniffer()