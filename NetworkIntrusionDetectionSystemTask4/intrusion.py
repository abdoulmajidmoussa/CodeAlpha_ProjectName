import os
os.environ["SCAPY_CACHE"] = "0"  # Fixes PermissionError on Windows

from scapy.all import sniff, IP, TCP
from datetime import datetime
from collections import defaultdict

# ------------------------------
# CONFIGURATION
# ------------------------------
PORT_SCAN_THRESHOLD = 10   # Number of distinct ports to trigger port scan alert
SYN_FLOOD_THRESHOLD = 100  # Number of SYN packets to trigger SYN flood alert
TIME_WINDOW         = 10   # Time window in seconds for detection
LOG_FILE            = "alerts.log"
IFACE               = "Wi-Fi"  # Network interface to monitor

# ------------------------------
# TRACKING STRUCTURES
# ------------------------------
ip_activity  = defaultdict(list)  # Tracks TCP ports per source IP
syn_activity = defaultdict(list)  # Tracks SYN packets per source IP

# ------------------------------
# ALERT & LOGGING
# ------------------------------
def log_alert(message):
    """Log an alert to the console and to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"{timestamp} - {message}"
    with open(LOG_FILE, "a") as f:
        f.write(formatted + "\n")
    print(f"[ALERT] {formatted}")

# ------------------------------
# DETECTION RULES
# ------------------------------
def detect_port_scan(packet):
    """
    Detect port scanning activity.
    Triggers if a single IP contacts more than PORT_SCAN_THRESHOLD
    distinct ports within TIME_WINDOW seconds.
    """
    if IP in packet and TCP in packet:
        src_ip       = packet[IP].src
        dst_port     = packet[TCP].dport
        current_time = datetime.now().timestamp()

        # Record the port access
        ip_activity[src_ip].append((dst_port, current_time))

        # Keep only entries within the time window
        ip_activity[src_ip] = [
            (p, t) for p, t in ip_activity[src_ip]
            if current_time - t <= TIME_WINDOW
        ]

        # Count distinct ports contacted
        distinct_ports = set(p for p, t in ip_activity[src_ip])

        if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
            log_alert(f"Port Scan detected from {src_ip} "
                      f"({len(distinct_ports)} ports in {TIME_WINDOW}s)")
            ip_activity[src_ip].clear()


def detect_syn_flood(packet):
    """
    Detect SYN flood attacks.
    Triggers if a single IP sends more than SYN_FLOOD_THRESHOLD
    SYN packets within TIME_WINDOW seconds.
    """
    if IP in packet and TCP in packet:
        # Check for SYN flag only (0x02), not SYN-ACK (0x12)
        if packet[TCP].flags == 0x02:
            src_ip       = packet[IP].src
            current_time = datetime.now().timestamp()

            # Record the SYN packet timestamp
            syn_activity[src_ip].append(current_time)

            # Keep only entries within the time window
            syn_activity[src_ip] = [
                t for t in syn_activity[src_ip]
                if current_time - t <= TIME_WINDOW
            ]

            if len(syn_activity[src_ip]) >= SYN_FLOOD_THRESHOLD:
                log_alert(f"SYN Flood detected from {src_ip} "
                          f"({len(syn_activity[src_ip])} SYN in {TIME_WINDOW}s)")
                syn_activity[src_ip].clear()

# ------------------------------
# PACKET HANDLER
# ------------------------------
def packet_handler(packet):
    """Main callback — dispatches each packet to all detection rules."""
    detect_port_scan(packet)
    detect_syn_flood(packet)

# ------------------------------
# ENTRY POINT
# ------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  Network Intrusion Detection System (IDS)")
    print("=" * 50)
    print(f"[*] Interface     : {IFACE}")
    print(f"[*] Port scan     : >{PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW}s")
    print(f"[*] SYN flood     : >{SYN_FLOOD_THRESHOLD} SYN in {TIME_WINDOW}s")
    print(f"[*] Log file      : {LOG_FILE}")
    print("[*] Press Ctrl+C to stop\n")

    try:
        sniff(prn=packet_handler, store=False, filter="tcp", iface=IFACE)
    except PermissionError:
        print("[-] Insufficient privileges. Please run as administrator.")
    except KeyboardInterrupt:
        print("\n[*] IDS stopped.")