# =====================================================
# PACKET SNIFFER IN PYTHON
# Coded by: Mr. Sabaz Ali Khan
# =====================================================
# Description:
#   A simple yet powerful real-time packet sniffer using Scapy.
#   Captures IP packets and prints Source/Destination IP, Protocol,
#   Ports (TCP/UDP), and ICMP type.
#
# Requirements:
#   1. Python 3.x
#   2. Run with Administrator / Root privileges (sudo on Linux/Mac)
#   3. Install Scapy: pip install scapy
#
# WARNING:
#   - Use ONLY on networks you own or have explicit permission to monitor.
#   - Packet sniffing without authorization may be illegal in your country.
#   - Tested on Linux, Windows (with Npcap), and macOS.
# =====================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime

def packet_handler(packet):
    """Callback function that processes each captured packet"""
    
    if IP in packet:
        ip_layer = packet[IP]
        
        # Basic timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"\n{'='*70}")
        print(f"[{timestamp}] PACKET CAPTURED")
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"TTL            : {ip_layer.ttl}")
        
        # Protocol detection
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol       : TCP")
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port : {tcp_layer.dport}")
            print(f"Flags          : {tcp_layer.flags}")
            
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol       : UDP")
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port : {udp_layer.dport}")
            
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"Protocol       : ICMP")
            print(f"Type           : {icmp_layer.type}")
            print(f"Code           : {icmp_layer.code}")
            
        else:
            print(f"Protocol       : Other (IP Protocol: {ip_layer.proto})")
        
        # Show payload preview (first 100 bytes)
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            print(f"Payload Preview: {payload[:100]}...")
        
        print(f"{'='*70}")

# ====================== START SNIFFING ======================
if __name__ == "__main__":
    print("🚀 Packet Sniffer Started by Mr. Sabaz Ali Khan")
    print("Press Ctrl+C to stop...\n")
    
    try:
        # You can change parameters here:
        #   - iface="eth0" or "Wi-Fi" (Windows) to specify interface
        #   - filter="tcp or udp or icmp" to filter traffic
        #   - count=0 means unlimited (stop with Ctrl+C)
        
        sniff(
            prn=packet_handler,          # function to call on each packet
            store=False,                 # don't store packets in memory
            filter="ip",                 # capture only IP packets
            count=0,                     # 0 = infinite
            # iface="eth0"               # uncomment and set your interface
        )
        
    except KeyboardInterrupt:
        print("\n\n👋 Sniffer stopped by user. Thank you!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("Tip: Run with sudo/root privileges!")