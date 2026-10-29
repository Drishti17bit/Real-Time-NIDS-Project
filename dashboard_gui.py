import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import os
import platform

class SnifferGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Network Intrusion Detection System (IDS) - Real-Time Monitor")
        self.window.geometry("920x650")
        self.window.minsize(800, 500)
        self.window.configure(bg="#f1f5f9")

        # Top Header Banner
        header = tk.Frame(self.window, bg="#0f172a", height=75)
        header.pack(fill=tk.X, side=tk.TOP)

        title = tk.Label(
            header,
            text="🛡️ NETWORK INTRUSION DETECTION SYSTEM (IDS)",
            font=("Segoe UI", 16, "bold"),
            fg="#f8fafc",
            bg="#0f172a"
        )
        title.pack(anchor="w", padx=25, pady=(12, 2))

        subtitle = tk.Label(
            header,
            text="Real-time Packet Sniffing | ARP Spoof & MITM Detection | Port Scan & Anomaly Analysis",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0f172a"
        )
        subtitle.pack(anchor="w", padx=25, pady=(0, 10))

        # Status & Info Bar
        status_frame = tk.Frame(self.window, bg="#e2e8f0", height=30)
        status_frame.pack(fill=tk.X)

        self.status_text_var = tk.StringVar(value="🟢 Status: Monitoring Traffic...")
        tk.Label(
            status_frame,
            textvariable=self.status_text_var,
            font=("Segoe UI", 9, "bold"),
            fg="#0f766e",
            bg="#e2e8f0"
        ).pack(side=tk.LEFT, padx=25, pady=4)

        try:
            import mitm_detector
            gw = mitm_detector.gateway_ip
        except Exception:
            gw = "Detecting..."

        self.gateway_var = tk.StringVar(value=f"Target Gateway: {gw}")
        tk.Label(
            status_frame,
            textvariable=self.gateway_var,
            font=("Segoe UI", 9),
            fg="#475569",
            bg="#e2e8f0"
        ).pack(side=tk.RIGHT, padx=25, pady=4)

        # Metrics / Stat Cards
        cards_frame = tk.Frame(self.window, bg="#f1f5f9")
        cards_frame.pack(fill=tk.X, padx=25, pady=12)

        self.packet_count_var = tk.StringVar(value="0")
        self.arp_alerts_var = tk.StringVar(value="0")
        self.mitm_alerts_var = tk.StringVar(value="0")
        self.suspicious_var = tk.StringVar(value="0")

        self._create_card(cards_frame, "📦 PACKETS SNIFFED", self.packet_count_var, "#0284c7", 0)
        self._create_card(cards_frame, "⚠️ ARP SPOOF ALERTS", self.arp_alerts_var, "#ea580c", 1)
        self._create_card(cards_frame, "🚨 MITM ATTACKS", self.mitm_alerts_var, "#dc2626", 2)
        self._create_card(cards_frame, "🔍 SCAN / ANOMALIES", self.suspicious_var, "#ca8a04", 3)

        cards_frame.columnconfigure((0, 1, 2, 3), weight=1)

        # Action Buttons Toolbar
        btn_frame = tk.Frame(self.window, bg="#f1f5f9")
        btn_frame.pack(fill=tk.X, padx=25, pady=(0, 10))

        demo_btn = tk.Button(
            btn_frame,
            text="⚡ Run Attack Simulation (Demo)",
            font=("Segoe UI", 10, "bold"),
            bg="#dc2626",
            fg="white",
            activebackground="#b91c1c",
            activeforeground="white",
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
            command=self.trigger_demo
        )
        demo_btn.pack(side=tk.LEFT, padx=(0, 10))

        clear_btn = tk.Button(
            btn_frame,
            text="🧹 Clear Display",
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg="#334155",
            relief=tk.SOLID,
            bd=1,
            padx=10,
            pady=5,
            cursor="hand2",
            command=self.clear_logs
        )
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))

        open_log_btn = tk.Button(
            btn_frame,
            text="📁 Open Log File",
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg="#334155",
            relief=tk.SOLID,
            bd=1,
            padx=10,
            pady=5,
            cursor="hand2",
            command=self.open_log_file
        )
        open_log_btn.pack(side=tk.LEFT)

        # Live Log Console
        log_container = tk.Frame(self.window, bg="#ffffff", bd=1, relief=tk.SOLID)
        log_container.pack(fill=tk.BOTH, expand=True, padx=25, pady=(0, 20))

        console_header = tk.Frame(log_container, bg="#1e293b", height=28)
        console_header.pack(fill=tk.X)
        tk.Label(
            console_header,
            text="  Live Intrusion Alerts & Event Feed",
            font=("Consolas", 10, "bold"),
            fg="#94a3b8",
            bg="#1e293b"
        ).pack(side=tk.LEFT, pady=3)

        self.log_box = scrolledtext.ScrolledText(
            log_container,
            wrap=tk.WORD,
            bg="#0f172a",
            fg="#f8fafc",
            font=("Consolas", 10),
            padx=10,
            pady=10,
            bd=0
        )
        self.log_box.pack(fill=tk.BOTH, expand=True)

        # Configure color tags
        self.log_box.tag_config("CRITICAL", foreground="#f87171", font=("Consolas", 10, "bold"))
        self.log_box.tag_config("HIGH", foreground="#fb923c", font=("Consolas", 10, "bold"))
        self.log_box.tag_config("MEDIUM", foreground="#facc15", font=("Consolas", 10, "bold"))
        self.log_box.tag_config("LOW", foreground="#38bdf8")
        self.log_box.tag_config("INFO", foreground="#4ade80")
        self.log_box.tag_config("SIM", foreground="#c084fc", font=("Consolas", 10, "italic"))

        self.add_log("[INFO] Network Sniffer & IDS Initialized.")
        self.add_log("[INFO] Ready to monitor local network traffic or run attack simulation.")

    def _create_card(self, parent, label_text, var, color, col):
        card = tk.Frame(parent, bg="#ffffff", bd=1, relief=tk.SOLID, padx=12, pady=10)
        card.grid(row=0, column=col, padx=5, sticky="ew")

        tk.Label(
            card,
            text=label_text,
            font=("Segoe UI", 8, "bold"),
            fg="#64748b",
            bg="#ffffff"
        ).pack(anchor="w")

        tk.Label(
            card,
            textvariable=var,
            font=("Segoe UI", 20, "bold"),
            fg=color,
            bg="#ffffff"
        ).pack(anchor="w", pady=(4, 0))

    def update_stats(self, packets, arp_alerts, mitm_alerts, port_scan_alerts=0, suspicious_alerts=0):
        total_anomalies = port_scan_alerts + suspicious_alerts
        self.window.after(0, self._apply_stats, packets, arp_alerts, mitm_alerts, total_anomalies)

    def _apply_stats(self, packets, arp_alerts, mitm_alerts, total_anomalies):
        self.packet_count_var.set(str(packets))
        self.arp_alerts_var.set(str(arp_alerts))
        self.mitm_alerts_var.set(str(mitm_alerts))
        self.suspicious_var.set(str(total_anomalies))

    def add_log(self, text):
        self.window.after(0, self._apply_log, text)

    def _apply_log(self, text):
        tag = None
        if "[CRITICAL]" in text:
            tag = "CRITICAL"
        elif "[HIGH]" in text:
            tag = "HIGH"
        elif "[MEDIUM]" in text:
            tag = "MEDIUM"
        elif "[LOW]" in text:
            tag = "LOW"
        elif "[INFO]" in text:
            tag = "INFO"
        elif "[SIMULATION]" in text:
            tag = "SIM"

        if tag:
            self.log_box.insert(tk.END, text + "\n", tag)
        else:
            self.log_box.insert(tk.END, text + "\n")

        self.log_box.yview(tk.END)

    def trigger_demo(self):
        try:
            import simulate_attacks
            self.status_text_var.set("🚨 Status: Running Live Attack Simulation...")
            simulate_attacks.run_simulation(
                on_progress=lambda msg: self.status_text_var.set(f"🚨 Status: {msg}")
            )
        except Exception as e:
            messagebox.showerror("Simulation Error", str(e))

    def clear_logs(self):
        self.log_box.delete("1.0", tk.END)
        self.add_log("[INFO] Screen display cleared (Logs remain saved in logs/alerts.log).")

    def open_log_file(self):
        log_path = os.path.abspath("logs/alerts.log")
        if os.path.exists(log_path):
            if platform.system() == "Windows":
                os.startfile(log_path)
            else:
                subprocess.Popen(["xdg-open", log_path])
        else:
            messagebox.showinfo("Log File", "No alerts logged yet.")

    def run(self):
        self.window.mainloop()