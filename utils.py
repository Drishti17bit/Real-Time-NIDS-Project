import os
import datetime
from state import state

def log_alert(msg):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    full = f"{timestamp} {msg}"

    os.makedirs("logs", exist_ok=True)
    with open("logs/alerts.log", "a") as f:
        f.write(full + "\n")

    if state.gui:
        state.gui.add_log(full)