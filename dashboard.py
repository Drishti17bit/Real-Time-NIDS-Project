import os

def show_dashboard():
    print("\n-----------------------------------")
    print("   NETWORK SNIFFER + ANALYZER")
    print("-----------------------------------")

    # Show log count
    try:
        alerts = open("logs/alerts.log").read().strip().split("\n")
        print(f"Alerts Logged: {len(alerts)}")
    except:
        print("Alerts Logged: 0")

    print("-----------------------------------\n")