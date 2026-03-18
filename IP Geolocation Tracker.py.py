"""
===============================================================
IP GEOLOCATION TRACKER
===============================================================
Coded by: Mr. Sabaz Ali Khan
Language: Python 3
Date: March 2026

DESCRIPTION:
A powerful, lightweight IP Geolocation Tracker that fetches
real-time location data (Country, City, ISP, Coordinates, etc.)
using the free ip-api.com service (no API key required).

FEATURES:
• Track any IP address or your own public IP
• Clean, colored output
• Error handling
• Easy to use CLI
• Works on Windows, Linux & macOS

HOW TO RUN:
1. Save this file as: ip_geolocation_tracker.py
2. Install requests: pip install requests
3. Run: python ip_geolocation_tracker.py
   OR
   python ip_geolocation_tracker.py 8.8.8.8

Enjoy! 🔥
===============================================================
"""

import requests
import sys
import json
from datetime import datetime

# ANSI Colors for beautiful output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    print(f"""{Colors.HEADER}
╔══════════════════════════════════════════════════════════════╗
║              IP GEOLOCATION TRACKER v1.0                     ║
║                Coded by Mr. Sabaz Ali Khan                   ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}""")

def get_geolocation(ip=None):
    try:
        if ip:
            url = f"http://ip-api.com/json/{ip}"
            print(f"{Colors.BLUE}🔍 Tracking IP: {ip}{Colors.END}")
        else:
            url = "http://ip-api.com/json/"
            print(f"{Colors.BLUE}🔍 Detecting your public IP...{Colors.END}")

        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            print(f"{Colors.RED}❌ API Error: HTTP {response.status_code}{Colors.END}")
            return None

        data = response.json()

        if data.get("status") == "fail":
            print(f"{Colors.RED}❌ Failed: {data.get('message', 'Unknown error')}{Colors.END}")
            return None

        return data

    except requests.exceptions.Timeout:
        print(f"{Colors.RED}❌ Timeout: API took too long to respond.{Colors.END}")
    except requests.exceptions.ConnectionError:
        print(f"{Colors.RED}❌ Connection Error: Please check your internet.{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Unexpected Error: {str(e)}{Colors.END}")
    
    return None

def display_info(data):
    if not data:
        return

    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ SUCCESS! IP Geolocation Found{Colors.END}\n")
    print(f"{Colors.BOLD}📍 IP Address       :{Colors.END} {data.get('query', 'N/A')}")
    print(f"{Colors.BOLD}🌍 Country          :{Colors.END} {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
    print(f"{Colors.BOLD}🏙️  Region           :{Colors.END} {data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})")
    print(f"{Colors.BOLD}🏘️  City             :{Colors.END} {data.get('city', 'N/A')}")
    print(f"{Colors.BOLD}📮 ZIP Code         :{Colors.END} {data.get('zip', 'N/A')}")
    print(f"{Colors.BOLD}📡 ISP              :{Colors.END} {data.get('isp', 'N/A')}")
    print(f"{Colors.BOLD}🏢 Organization     :{Colors.END} {data.get('org', 'N/A')}")
    print(f"{Colors.BOLD}🌐 AS Number        :{Colors.END} {data.get('as', 'N/A')}")
    
    print(f"\n{Colors.YELLOW}{Colors.BOLD}📌 Coordinates      :{Colors.END}")
    print(f"   Latitude         : {data.get('lat', 'N/A')}")
    print(f"   Longitude        : {data.get('lon', 'N/A')}")
    print(f"   Google Maps Link : https://www.google.com/maps?q={data.get('lat', '')},{data.get('lon', '')}")
    
    print(f"\n{Colors.BLUE}{Colors.BOLD}⏰ Timezone         :{Colors.END} {data.get('timezone', 'N/A')}")
    print(f"{Colors.BOLD}🔄 Query Time       :{Colors.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

def main():
    print_banner()
    
    ip = None
    if len(sys.argv) > 1:
        ip = sys.argv[1].strip()
        if not ip.replace('.', '').isdigit() and not ':' in ip:  # basic validation
            print(f"{Colors.RED}❌ Invalid IP format!{Colors.END}")
            sys.exit(1)

    data = get_geolocation(ip)
    if data:
        display_info(data)
    else:
        print(f"\n{Colors.RED}⚠️  Tracking failed. Please try again later.{Colors.END}")

if __name__ == "__main__":
    main()