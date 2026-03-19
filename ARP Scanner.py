# ARP Network Scanner in Python
# Built for educational & ethical purposes only
# Requirements: 
#   → pip install scapy
#   → Run as Administrator / root (sudo python3 arp_scanner.py)
#   → Works best on Linux / macOS (Windows needs Npcap + admin rights)

from scapy.all import ARP, Ether, srp, get_if_hwaddr, get_if_addr, conf
import sys
import time
import argparse
from datetime import datetime

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Scanner - Discover devices on local network")
    parser.add_argument("-t", "--target", dest="target", 
                        help="Target IP / IP range (example: 192.168.1.1/24 or 192.168.1.50-100)",
                        required=True)
    parser.add_argument("-i", "--interface", dest="interface", 
                        help="Network interface (optional - auto-detected if not given)",
                        default=None)
    return parser.parse_args()


def scan(ip_range, iface=None):
    print(f"\n[+] Starting ARP scan on {ip_range} ...")
    print(f"    Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Create ARP request packet
    arp_request = ARP(pdst=ip_range)
    
    # Create Ethernet broadcast frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine into one packet
    arp_request_broadcast = broadcast / arp_request
    
    # Send packet and receive answers (srp = send/receive layer 2)
    # timeout=2 → wait max 2 seconds
    # verbose=False → less noisy output
    if iface:
        conf.iface = iface
    
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    # Prepare results
    clients = []
    for sent, received in answered_list:
        clients.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": get_mac_vendor(received.hwsrc)  # optional
        })
    
    return clients


def get_mac_vendor(mac):
    """Very simple MAC vendor lookup (you can extend it with API or local DB)"""
    mac_prefix = mac.upper()[:8].replace(":", "")
    common_vendors = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "00:25:00": "Apple",
        "3C:D9:2B": "Hewlett Packard",
        "F0:18:98": "Apple",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "TP-Link",
        "00:1A:2B": "Dell",
        # Add more if you want...
    }
    return common_vendors.get(mac_prefix, "Unknown")


def print_result(results):
    if not results:
        print("[-] No devices responded.")
        return
    
    print(" IP".ljust(18) + "MAC Address".ljust(20) + "Vendor")
    print("-" * 65)
    
    for client in sorted(results, key=lambda x: x["ip"]):
        print(f"{client['ip']:<18}{client['mac']:<20}{client['vendor']}")
    
    print(f"\n[+] Found {len(results)} active devices.")
    print(f"    Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


if __name__ == "__main__":
    options = get_arguments()
    
    try:
        # You can also hardcode for quick testing:
        # options.target = "192.168.1.0/24"
        
        discovered = scan(options.target, options.interface)
        print_result(discovered)
        
    except PermissionError:
        print("[-] Error: Please run this script with sudo / Administrator privileges!")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] Scan stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)
