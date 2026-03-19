# ========================================================
#       NETWORK LOG ANALYZER
# ========================================================
# This Script Coded By pakistani Ethical Hacker Mr Sabaz ali khan
# Purpose: Analyze network logs (firewall, syslog, access logs etc.)
#           Extract IPs, count frequencies, detect suspicious activity
#           Educational & Pentesting Purpose Only
# GitHub Style: Simple, Powerful, No Extra Dependencies
# ========================================================

import re
from collections import Counter
import argparse
import os
from datetime import datetime

# Regex to extract IPv4 addresses
IP_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

def parse_log_file(logfile_path):
    """Parse log file and extract IPs + basic stats"""
    if not os.path.exists(logfile_path):
        print(f"[-] Error: File '{logfile_path}' not found!")
        return None, None, None

    print(f"[+] Loading log file: {logfile_path}")
    ip_list = []
    deny_count = 0
    total_lines = 0

    with open(logfile_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            
            # Extract all IPs from this line
            ips = re.findall(IP_REGEX, line)
            ip_list.extend(ips)
            
            # Detect denied/blocked actions (common in firewall logs)
            if any(keyword in line.upper() for keyword in ['DENY', 'BLOCK', 'DROP', 'REJECT', 'FORBIDDEN', 'ERROR']):
                deny_count += 1

    return ip_list, total_lines, deny_count

def generate_report(ip_list, total_lines, deny_count, threshold=10):
    """Generate beautiful analysis report"""
    print("\n" + "="*60)
    print("          NETWORK LOG ANALYZER REPORT")
    print("          Coded By Mr Sabaz Ali Khan")
    print("="*60)
    print(f"Total Lines Analyzed     : {total_lines}")
    print(f"Total IPs Extracted      : {len(ip_list)}")
    print(f"Unique IPs               : {len(set(ip_list))}")
    print(f"Blocked/Denied Actions   : {deny_count}")
    print("-"*60)

    if not ip_list:
        print("[-] No IPs found in the log!")
        return

    # Count frequency of each IP
    ip_counter = Counter(ip_list)
    
    print("\n[+] TOP 10 MOST FREQUENT IPs (Possible Attackers):")
    print(f"{'Rank':<5} {'IP Address':<18} {'Count':<8} {'Status'}")
    print("-"*50)
    
    for rank, (ip, count) in enumerate(ip_counter.most_common(10), 1):
        status = "SUSPICIOUS" if count >= threshold else "Normal"
        print(f"{rank:<5} {ip:<18} {count:<8} {status}")

    # Suspicious IPs report
    suspicious = [ip for ip, count in ip_counter.items() if count >= threshold]
    if suspicious:
        print(f"\n[!] ALERT: {len(suspicious)} Suspicious IPs detected "
              f"(appeared >= {threshold} times)")
        for ip in suspicious[:5]:  # show only top 5
            print(f"    → {ip} ({ip_counter[ip]} times)")
    else:
        print("\n[+] No highly suspicious IPs detected.")

    print("\n[+] Analysis Complete! Stay Safe.")
    print("    Script Coded By Mr Sabaz Ali Khan - Ethical Hacker")

def main():
    parser = argparse.ArgumentParser(
        description="Network Log Analyzer - Coded By Mr Sabaz Ali Khan"
    )
    parser.add_argument("logfile", help="Path to your network log file")
    parser.add_argument("-t", "--threshold", type=int, default=10,
                        help="Threshold for suspicious IP (default: 10)")
    args = parser.parse_args()

    ip_list, total_lines, deny_count = parse_log_file(args.logfile)
    if ip_list is not None:
        generate_report(ip_list, total_lines, deny_count, args.threshold)

if __name__ == "__main__":
    print("Network Log Analyzer Started...")
    main()
