import subprocess
import requests
import json
import os
from zapv2 import ZAPv2
import nmap

# 🛠️ Configuration
ZAP_PROXY = "http://localhost:8080"
zap = ZAPv2(proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})
nm = nmap.PortScanner()

GOBUSTER_WORDLIST = "/usr/share/wordlists/dirb/common.txt"  # Ensure this exists
SUBLIST3R_PATH = "/home/kali/Desktop/Sublist3r/sublist3r.py"  # Update with correct path

# 🕵️‍♂️ Passive Scan - Security Headers Check
def passive_scan(target_url):
    print(f"\n🔍 Performing Passive Scan on {target_url}...")
    try:
        headers = requests.get(target_url).headers
        print("\n🛡️ Security Headers:")
        for header in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection"]:
            print(f"{header}: {headers.get(header, 'Not Set')}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error: {e}")

# 📂 Directory Enumeration
def dir_enum(target_url):
    print(f"\n📂 Running Directory Enumeration on {target_url}...")
    if not os.path.exists(GOBUSTER_WORDLIST):
        print("❌ Wordlist not found! Please install gobuster and check the path.")
        return
    try:
        subprocess.run(["gobuster", "dir", "-u", target_url, "-w", GOBUSTER_WORDLIST, "-t", "10"], check=True)
    except FileNotFoundError:
        print("❌ Gobuster not found! Install it using: sudo apt install gobuster")

# 🌐 Subdomain Enumeration
def subdomain_enum(domain):
    print(f"\n🌍 Running Subdomain Enumeration on {domain}...")
    if not os.path.exists(SUBLIST3R_PATH):
        print("❌ Sublist3r not found! Clone it using: git clone https://github.com/aboul3la/Sublist3r.git")
        return
    try:
        subprocess.run(["python3", SUBLIST3R_PATH, "-d", domain, "-o", "subdomains.txt"], check=True)
    except FileNotFoundError:
        print("❌ Python3 not found! Ensure Python is installed.")

# 🛡️ SQL Injection Scan
def sql_injection_scan(target_url):
    print(f"\n💉 Testing for SQL Injection on {target_url}...")
    try:
        subprocess.run(["sqlmap", "-u", target_url, "--batch", "--dbs"], check=True)
    except FileNotFoundError:
        print("❌ SQLMap not found! Install it using: sudo apt install sqlmap")

# 🔐 Brute Force Login Attempt
def brute_force_login(target_ip, username, password_list, service="ssh"):
    print(f"\n🔓 Performing Brute-Force Attack on {target_ip} ({service})...")
    if not os.path.exists(password_list):
        print("❌ Password list not found! Provide a valid list.")
        return
    try:
        subprocess.run(["hydra", "-l", username, "-P", password_list, target_ip, service], check=True)
    except FileNotFoundError:
        print("❌ Hydra not found! Install it using: sudo apt install hydra")

# 🔒 SSL Security Check
def ssl_security_scan(target_url):
    print(f"\n🔑 Checking SSL Security for {target_url}...")
    try:
        subprocess.run(["testssl.sh", target_url], check=True)
    except FileNotFoundError:
        print("❌ testssl.sh not found! Install it using: sudo apt install testssl.sh")

# 🔄 API Security Scan using ZAP
def api_scan(target_url):
    print(f"\n🛰️ Scanning API Endpoints for {target_url} using ZAP...")
    try:
        zap.urlopen(target_url)
        zap.spider.scan(target_url)
        while int(zap.spider.status()) < 100:
            print("⏳ Spidering API in progress...")
        print("\n✅ API Scan Complete!")
        print(json.dumps(zap.core.alerts(), indent=4))
    except Exception as e:
        print(f"❌ Error with ZAP scan: {e}")

# 🌐 Network Port Scan using Nmap
def network_scan(target_ip):
    print(f"\n🔎 Scanning Open Ports on {target_ip} using Nmap...")
    try:
        nm.scan(target_ip, "1-65535")
        for host in nm.all_hosts():
            print(f"📡 Host: {host} ({nm[host].hostname()})")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"  - {proto.upper()} Port {port}: {nm[host][proto][port]['state']}")
    except Exception as e:
        print(f"❌ Nmap Scan Error: {e}")

# 🚀 Main Execution
if __name__ == "__main__":
    target_web = "http://example.com"
    target_network = "192.168.1.1"
    target_domain = "example.com"
    password_list = "/usr/share/wordlists/rockyou.txt"  # Update with actual path

    passive_scan(target_web)
    dir_enum(target_web)
    subdomain_enum(target_domain)
    sql_injection_scan(target_web)
    brute_force_login(target_network, "admin", password_list)
    ssl_security_scan(target_web)
    api_scan(target_web)
    network_scan(target_network)
