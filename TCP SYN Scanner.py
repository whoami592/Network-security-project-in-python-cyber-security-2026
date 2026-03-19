# ========================================================
# TCP SYN Scanner (Stealth / Half-Open Port Scanner)
# Coded by Mr. Sabaz Ali Khan
# YouTube: MR Sabaz Ali Khan Hacking Series
# GitHub : whoami592
# ========================================================
# WARNING: 
# This tool is for EDUCATIONAL PURPOSES ONLY.
# Use ONLY on networks/devices you OWN or have explicit written permission to scan.
# Unauthorized scanning may be illegal in your country.
# Run as ROOT / Administrator (sudo python3 syn_scanner.py)
# ========================================================

from scapy.all import *
import argparse
import time
import threading
from datetime import datetime

# Colors for nice output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def syn_scan(target, port):
    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK received
                print(f"{GREEN}[+] Port {port} is OPEN on {target}{RESET}")
                # Send RST to close the half-open connection (stealth)
                send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
            elif response[TCP].flags == "RA":  # RST-ACK
                pass  # Closed
    except Exception:
        pass  # Silent fail for speed

def scan_range(target, start_port, end_port, threads=100):
    print(f"{YELLOW}[*] Starting TCP SYN Scan on {target} (Ports {start_port}-{end_port}){RESET}")
    print(f"{YELLOW}[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n")
    
    start_time = time.time()
    thread_list = []
    
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=syn_scan, args=(target, port))
        thread_list.append(t)
        t.start()
        
        # Limit concurrent threads
        if len(thread_list) >= threads:
            for thread in thread_list:
                thread.join()
            thread_list = []
    
    # Join remaining threads
    for thread in thread_list:
        thread.join()
    
    print(f"\n{GREEN}[+] Scan completed in {time.time() - start_time:.2f} seconds{RESET}")

def main():
    parser = argparse.ArgumentParser(description="TCP SYN Scanner by Mr. Sabaz Ali Khan")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (e.g. 1-1000 or 80,443,22)")
    parser.add_argument("--threads", type=int, default=200, help="Number of threads (default 200)")
    
    args = parser.parse_args()
    
    # Parse ports
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        port_range = range(start, end + 1)
    else:
        port_range = [int(p) for p in args.ports.split(",")]
    
    try:
        scan_range(args.target, min(port_range), max(port_range) if isinstance(port_range, range) else max(port_range), args.threads)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan stopped by user.{RESET}")

if __name__ == "__main__":
    print(f"""
    {GREEN}
     ███████╗██╗   ██╗███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
     ██╔════╝██║   ██║████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
     ███████╗██║   ██║██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
     ╚════██║██║   ██║██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
     ███████║╚██████╔╝██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    {RESET}
    TCP SYN Scanner - Coded by Mr. Sabaz Ali Khan
    """)
    main()
