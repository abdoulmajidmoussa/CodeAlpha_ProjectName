# 🔍 CodeAlpha — Basic Network Sniffer

> **Task 1** of the CodeAlpha Cybersecurity Internship Program  


---

## 📌 Description

A Python-based network packet sniffer built with **Scapy** that captures and analyzes live network traffic in real time. The tool inspects IP packets and displays key information such as source/destination IPs, protocols, ports, and payloads.

---

## ✨ Features

- 📡 Captures live IP traffic on a specified network interface
- 🔎 Identifies protocols: **TCP**, **UDP**, **ICMP**, and others
- 🚪 Displays source and destination **IP addresses** and **ports**
- 📦 Safely decodes and displays **raw payloads** (first 100 bytes)
- 📏 Shows **packet size** in bytes
- ⏱️ Timestamps each captured packet
- 🛡️ Graceful shutdown on `Ctrl+C`
- ⚠️ Error handling per packet — sniffer never crashes mid-capture

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
python sniffer.py

# Linux/Mac (run as root)
sudo python3 sniffer.py
```

**Sample output:**

```
[*] Starting Network Sniffer... (Ctrl+C to stop)

=============================================
[14:32:05]
  Src IP   : 192.168.1.11
  Dst IP   : 8.8.8.8
  Size     : 74 bytes
  Protocol : TCP  |  Ports: 54320 → 443
```

---

## ⚙️ Configuration

To change the monitored interface, edit line in `sniffer.py`:

```python
sniff(prn=packet_sniffer, store=False, filter="ip", iface="Wi-Fi")
```

| Parameter | Description |
|---|---|
| `iface` | Network interface name (`"Wi-Fi"`, `"eth0"`, etc.) |
| `filter` | BPF filter (`"ip"`, `"tcp"`, `"host 192.168.1.1"`, etc.) |

---

## 📁 Project Structure

```
CodeAlpha_NetworkSniffer/
│
├── sniffer.py       # Main sniffer script
└── README.md
```

---

## ⚠️ Disclaimer

This tool is developed **strictly for educational purposes** as part of a cybersecurity internship.  
Only use it on networks you own or have explicit permission to monitor.  
Unauthorized packet capturing may be illegal in your jurisdiction.

---

## 👤 Author

**Moussa B. A.Majid**  
CodeAlpha Cybersecurity Internship — May/June 2026  

