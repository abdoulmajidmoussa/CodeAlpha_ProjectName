from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from datetime import datetime
import sys


def packet_sniffer(packet):
    """Callback function to process and display captured packets."""
    try:
        if IP in packet:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"\n{'='*45}")
            print(f"[{timestamp}]")
            print(f"  Src IP   : {packet[IP].src}")
            print(f"  Dst IP   : {packet[IP].dst}")
            print(f"  Size     : {len(packet)} bytes")

            if TCP in packet:
                # Display TCP protocol info and ports
                print(f"  Protocol : TCP  |  Ports: {packet[TCP].sport} → {packet[TCP].dport}")
                if Raw in packet:
                    # Safely display raw payload (first 100 bytes)
                    payload = repr(packet[Raw].load[:100])
                    print(f"  Payload  : {payload}")

            elif UDP in packet:
                # Display UDP protocol info and ports
                print(f"  Protocol : UDP  |  Ports: {packet[UDP].sport} → {packet[UDP].dport}")

            elif ICMP in packet:
                # Display ICMP type
                print(f"  Protocol : ICMP | Type: {packet[ICMP].type}")

            else:
                # Unknown protocol — show raw protocol number
                print(f"  Protocol : Other (proto={packet[IP].proto})")

    except Exception as e:
        # Catch any unexpected error without stopping the sniffer
        print(f"  [!] Error processing packet: {e}")


if __name__ == "__main__":
    print("[*] Starting Network Sniffer... (Ctrl+C to stop)")
    try:
        # Capture all IP packets on the Wi-Fi interface
        sniff(prn=packet_sniffer, store=False, filter="ip", iface="Wi-Fi")
    except PermissionError:
        # Requires administrator/root privileges
        print("[-] Insufficient privileges. Please run as administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        print("\n[*] Sniffer stopped.")