# ================================================
# LAN Traffic Monitor
# Coded by: Mr. Sabaz Ali Khan
# Cyber Security Expert | Ethical Hacker
# ================================================

from scapy.all import *
import time
from collections import defaultdict
import threading
import os

# Global dictionaries to store traffic stats
traffic_data = defaultdict(lambda: {'upload': 0, 'download': 0, 'mac': 'Unknown'})

def get_mac(ip):
    """Get MAC address of an IP"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_response = srp(broadcast / arp_request, timeout=2, verbose=False)[0]
    if arp_response:
        return arp_response[0][1].hwsrc
    return "Unknown"

def arp_scan():
    """Discover all devices on LAN"""
    print("[+] Scanning LAN for devices...")
    target_ip = "192.168.1.1/24"  # Change if your network is different (e.g., 192.168.0.1/24)
    
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether / arp, timeout=3, verbose=False)[0]
    
    devices = {}
    for sent, received in result:
        devices[received.psrc] = received.hwsrc
    
    print(f"[+] Found {len(devices)} devices on LAN\n")
    return devices

def packet_handler(packet):
    """Process each captured packet"""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        # Update traffic stats
        if src_ip in device_list:
            traffic_data[src_ip]['upload'] += length
            if not traffic_data[src_ip]['mac']:
                traffic_data[src_ip]['mac'] = device_list.get(src_ip, "Unknown")
        
        if dst_ip in device_list:
            traffic_data[dst_ip]['download'] += length
            if not traffic_data[dst_ip]['mac']:
                traffic_data[dst_ip]['mac'] = device_list.get(dst_ip, "Unknown")

def display_traffic():
    """Live display of traffic stats"""
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=" * 80)
        print("          LAN TRAFFIC MONITOR - Coded by Mr. Sabaz Ali Khan")
        print("=" * 80)
        print(f"{'IP Address':<18} {'MAC Address':<20} {'Upload (MB)':<15} {'Download (MB)':<15} {'Total (MB)':<15}")
        print("-" * 80)
        
        for ip, data in sorted(traffic_data.items(), key=lambda x: x[1]['upload'] + x[1]['download'], reverse=True):
            total = (data['upload'] + data['download']) / (1024 * 1024)
            upload = data['upload'] / (1024 * 1024)
            download = data['download'] / (1024 * 1024)
            print(f"{ip:<18} {data['mac']:<20} {upload:.2f} MB       {download:.2f} MB       {total:.2f} MB")
        
        print("\nPress Ctrl+C to stop...")
        time.sleep(2)

# ===================== MAIN =====================
if __name__ == "__main__":
    print("🔥 LAN Traffic Monitor by Mr. Sabaz Ali Khan 🔥\n")
    
    # Discover devices
    device_list = arp_scan()
    
    # Start display thread
    display_thread = threading.Thread(target=display_traffic, daemon=True)
    display_thread.start()
    
    # Start sniffing (change interface if needed: e.g., "Wi-Fi", "eth0")
    print("[+] Starting packet sniffing... (Press Ctrl+C to stop)")
    
    try:
        sniff(prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\n\n[+] Monitoring stopped by user.")
        print("Thank you for using Mr. Sabaz Ali Khan's LAN Traffic Monitor!")