# 🚨 CodeAlpha — Network Intrusion Detection System (IDS)

> **Task 4** of the CodeAlpha Cybersecurity Internship Program  


---

## 📌 Description

A lightweight **Python-based Network Intrusion Detection System (IDS)** built with Scapy. It monitors live TCP traffic and automatically detects two common attack patterns: **Port Scanning** and **SYN Flood attacks**. Alerts are logged to both the console and a log file in real time.

---

## ✨ Features

- 🔍 **Port Scan Detection** — triggers when a single IP contacts more than N distinct ports within a configurable time window
- 💥 **SYN Flood Detection** — triggers when a single IP sends more than N SYN packets within a configurable time window
- 📝 **Real-time logging** — all alerts saved to `alerts.log` with timestamps
- ⚙️ **Fully configurable** — thresholds and time windows defined in one place
- 🛡️ Graceful shutdown on `Ctrl+C`
- 🪟 Windows-compatible via Npcap

---

## 🛠️ Requirements

- Python 3.x
- [Scapy](https://scapy.net/)
- [Npcap](https://npcap.com/) *(Windows only — enable WinPcap compatibility mode)*
- Administrator / root privileges

Install dependencies:

```bash
pip install scapy
```

---

## 🚀 Usage

```bash
# Windows (run as Administrator)
python intrusion.py

# Linux/Mac (run as root)
sudo python3 intrusion.py
```

**Sample output:**

```
==================================================
  Network Intrusion Detection System (IDS)
==================================================
[*] Interface     : Wi-Fi
[*] Port scan     : >10 ports in 10s
[*] SYN flood     : >100 SYN in 10s
[*] Log file      : alerts.log
[*] Press Ctrl+C to stop

[ALERT] 2026-05-30 14:45:12 - Port Scan detected from 192.168.1.50 (15 ports in 10s)
[ALERT] 2026-05-30 14:45:18 - SYN Flood detected from 192.168.1.77 (134 SYN in 10s)
```

---

## ⚙️ Configuration

All detection parameters are defined at the top of `intrusion.py`:

```python
PORT_SCAN_THRESHOLD = 10    # Distinct ports to trigger port scan alert
SYN_FLOOD_THRESHOLD = 100   # SYN packets to trigger flood alert
TIME_WINDOW         = 10    # Detection window in seconds
IFACE               = "Wi-Fi"  # Network interface to monitor
LOG_FILE            = "alerts.log"
```

---

## 🔎 Detection Logic

### Port Scan Detection
```
For each TCP packet from source IP X:
  → Record (destination_port, timestamp)
  → Remove entries older than TIME_WINDOW seconds
  → If distinct ports contacted ≥ PORT_SCAN_THRESHOLD → ALERT
```

### SYN Flood Detection
```
For each TCP packet with SYN flag (0x02) from source IP X:
  → Record timestamp
  → Remove entries older than TIME_WINDOW seconds
  → If SYN count ≥ SYN_FLOOD_THRESHOLD → ALERT
```

---

## 📁 Project Structure

```
CodeAlpha_IntrusionDetectionSystem/
│
├── intrusion.py     # Main IDS script
├── alerts.log       # Generated alert log (auto-created)
└── README.md
```

---

## ⚠️ Disclaimer

This tool is developed **strictly for educational purposes** as part of a cybersecurity internship.  
Only deploy it on networks you own or have explicit authorization to monitor.  
Unauthorized network monitoring may be illegal in your jurisdiction.

---

## 👤 Author

**Moussa B. A.Majid**  
CodeAlpha Cybersecurity Internship — May/June 2026  

