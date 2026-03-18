# ========================================================
# NETWORK INTRUSION DETECTION SYSTEM (NIDS)
# Python Implementation using Scapy
# ========================================================
# Coded by: Mr. Sabaz Ali Khan
# Date: March 2026
# GitHub: https://github.com/whoami592
# Purpose: Educational & Ethical Use Only
# Special thanks to ethical hacking community
# ========================================================

import scapy.all as scapy
from collections import defaultdict
import time
import threading
import os
import sys

# ===================== CONFIGURATION =====================
THRESHOLD_SYN_FLOOD = 50      # SYN packets per IP in 5 seconds
THRESHOLD_PORT_SCAN = 30      # Different ports from same IP in 5 seconds
THRESHOLD_ICMP_FLOOD = 100    # ICMP packets per IP in 5 seconds
ALERT_LOG_FILE = "nids_alerts.log"

# Tracking dictionaries
syn_tracker = defaultdict(list)
port_tracker = defaultdict(lambda: defaultdict(list))
icmp_tracker = defaultdict(list)

# Lock for thread safety
lock = threading.Lock()

# ===================== ALERT FUNCTION =====================
def log_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    alert = f"[{timestamp}] ALERT: {message}\n"
    print(f"\033[91m{alert}\033[0m")  # Red color in terminal
    with open(ALERT_LOG_FILE, "a") as f:
        f.write(alert)

# ===================== PACKET ANALYZER =====================
def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # ================== SYN FLOOD DETECTION ==================
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":  # SYN flag only
            with lock:
                syn_tracker[src_ip].append(time.time())
                # Keep only last 5 seconds
                syn_tracker[src_ip] = [t for t in syn_tracker[src_ip] if time.time() - t < 5]
                
                if len(syn_tracker[src_ip]) > THRESHOLD_SYN_FLOOD:
                    log_alert(f"SYN Flood detected from {src_ip} → {dst_ip} "
                              f"({len(syn_tracker[src_ip])} SYN packets in 5s)")

        # ================== PORT SCAN DETECTION ==================
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == "S":
            dst_port = packet[scapy.TCP].dport
            with lock:
                port_tracker[src_ip][dst_ip].append((time.time(), dst_port))
                # Keep only last 5 seconds
                port_tracker[src_ip][dst_ip] = [p for p in port_tracker[src_ip][dst_ip] 
                                              if time.time() - p[0] < 5]
                
                unique_ports = len(set(p[1] for p in port_tracker[src_ip][dst_ip]))
                if unique_ports > THRESHOLD_PORT_SCAN:
                    log_alert(f"Port Scan detected from {src_ip} to {dst_ip} "
                              f"({unique_ports} unique ports in 5s)")

        # ================== ICMP FLOOD DETECTION ==================
        if packet.haslayer(scapy.ICMP):
            with lock:
                icmp_tracker[src_ip].append(time.time())
                icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if time.time() - t < 5]
                
                if len(icmp_tracker[src_ip]) > THRESHOLD_ICMP_FLOOD:
                    log_alert(f"ICMP Flood (Ping Flood) detected from {src_ip} "
                              f"({len(icmp_tracker[src_ip])} packets in 5s)")

# ===================== SNIFFER FUNCTION =====================
def start_nids(interface="eth0"):
    print(f"\033[92m[+] Starting NIDS by Mr. Sabaz Ali Khan on interface: {interface}\033[0m")
    print("[+] Monitoring for SYN Flood, Port Scan & ICMP Flood...")
    print("[+] Press Ctrl+C to stop\n")
    
    try:
        scapy.sniff(iface=interface,
                    prn=analyze_packet,
                    store=False)
    except KeyboardInterrupt:
        print("\n\033[93m[!] NIDS stopped by user\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error: {e}\033[0m")
        print("Tip: Run with sudo/root and check interface name (use 'ifconfig' or 'ip link')")

# ===================== MAIN =====================
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("\033[91m[!] Error: Please run this script with sudo/root privileges!\033[0m")
        print("Example: sudo python3 nids_sabaz_ali_khan.py")
        sys.exit(1)
    
    # List available interfaces
    print("Available interfaces:", scapy.get_if_list())
    
    # You can change interface here or pass as argument
    interface = "eth0"          # Change to your interface (e.g., wlan0, en0)
    # For wireless: interface = "wlan0"
    
    start_nids(interface)