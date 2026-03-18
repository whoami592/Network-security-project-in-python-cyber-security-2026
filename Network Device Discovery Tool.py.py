#!/usr/bin/env python3
# =============================================
#     NETWORK DEVICE DISCOVERY TOOL
# =============================================
# Coded By: MR SABAZ ALI KHAN
# Pakistani Ethical Hacker | Cyber Security Expert
# For Educational Purposes Only
# I am not responsible for any misuse of this tool
# =============================================

import sys
import time
from scapy.all import ARP, Ether, srp, conf

# Disable verbose logging
conf.verb = 0

def print_banner():
    print("""
    \033[1;32m
    =============================================
          NETWORK DEVICE DISCOVERY TOOL
    =============================================
          Coded By: MR SABAZ ALI KHAN
       Pakistani Ethical Hacker (2025)
    =============================================
    \033[0m
    """)

def discover_devices(target_ip_range):
    """
    Performs ARP Scan on the given IP range to discover active devices.
    """
    print(f"\033[1;34m[+] Scanning network: {target_ip_range}\033[0m")
    print("\033[1;33m[!] Please wait... This may take 5-10 seconds\033[0m\n")
    
    start_time = time.time()
    
    # Create ARP request packet
    arp_request = ARP(pdst=target_ip_range)
    
    # Create Ethernet broadcast frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Stack packets
    packet = broadcast / arp_request
    
    # Send and receive packets (srp = send + receive)
    answered = srp(packet, timeout=5, verbose=0)[0]
    
    devices = []
    for sent, received in answered:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc.upper()
        })
    
    scan_duration = time.time() - start_time
    return devices, scan_duration

def main():
    print_banner()
    
    # Check root privileges (required for raw sockets)
    if sys.platform.startswith('linux') and 'root' not in open('/proc/self/status').read():
        print("\033[1;31m[!] This script must be run as root (sudo) on Linux!\033[0m")
        print("    Try: sudo python3 network_discovery.py")
        sys.exit(1)
    
    # Get target range from user
    if len(sys.argv) == 2:
        target = sys.argv[1]
    else:
        target = input("\033[1;36mEnter target network range (e.g., 192.168.1.0/24): \033[0m").strip()
    
    if not target:
        print("\033[1;31m[-] No range provided. Exiting...\033[0m")
        sys.exit(1)
    
    try:
        devices, duration = discover_devices(target)
        
        if not devices:
            print("\033[1;31m[-] No devices found on the network!\033[0m")
            return
        
        print("\033[1;32m[+] Scan Complete! Devices Found:\033[0m")
        print("-" * 60)
        print(f"{'IP Address':<18} {'MAC Address':<20} {'Vendor (if known)':<15}")
        print("-" * 60)
        
        for device in devices:
            # Simple MAC vendor lookup (common vendors)
            mac = device['mac']
            vendor = "Unknown"
            if mac.startswith("00:1A:2B") or mac.startswith("00-1A-2B"):
                vendor = "Apple"
            elif mac.startswith("00:50:56") or mac.startswith("00-50-56"):
                vendor = "VMware"
            elif mac.startswith("00:0C:29"):
                vendor = "VMware"
            elif mac.startswith("B8:27:EB"):
                vendor = "Raspberry Pi"
            elif mac.startswith("DC:A6:32"):
                vendor = "Samsung"
            
            print(f"{device['ip']:<18} {device['mac']:<20} {vendor:<15}")
        
        print("-" * 60)
        print(f"\033[1;33mScan completed in {duration:.2f} seconds | Found {len(devices)} device(s)\033[0m")
        
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Scan interrupted by user.\033[0m")
    except Exception as e:
        print(f"\033[1;31m[!] Error: {e}\033[0m")
        print("    Make sure Scapy is installed and you have network access.")

if __name__ == "__main__":
    # Installation reminder
    try:
        main()
    except ImportError:
        print("\033[1;31m[!] Scapy is not installed!\033[0m")
        print("    Install with: pip3 install scapy")
        print("    Then run again with sudo.")