class GlobalState:
    def __init__(self):
        self.gui = None
        self.packet_count = 0
        self.arp_alerts = 0
        self.mitm_alerts = 0
        self.port_scan_alerts = 0
        self.suspicious_alerts = 0
        # Protocol counters for web traffic analytics.
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}

state = GlobalState()