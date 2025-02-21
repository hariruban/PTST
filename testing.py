import subprocess
from zapv2 import ZAPv2
import nmap
import requests
import json

# OWASP ZAP Configuration
ZAP_PROXY = "http://localhost:8080"
zap = ZAPv2(proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

# Nmap Scanner
nm = nmap.PortScanner()

# Passive Scan - Security Headers Check
def passive_scan(target_url):
    print(f"Performing passive scan on {target_url}...")
    headers = requests.get(target_url).headers
    print("\nSecurity Headers:")
    for header in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection"]:
        print(f"{header}: {headers.get(header, 'Not Set')}")

# Directory Enumeration using Gobuster
def dir_enum(target_url, wordlist="common.txt"):
    print(f"Performing directory enumeration on {target_url}...")
    subprocess.run(["gobuster", "dir", "-u", target_url, "-w", wordlist, "-t", "10"])

# Subdomain Enumeration using Sublist3r
def subdomain_enum(domain):
    print(f"Performing subdomain enumeration on {domain}...")
    subprocess.run(["sublist3r", "-d", domain, "-o", "subdomains.txt"])

# SQL Injection Testing using sqlmap
def sql_injection_scan(target_url):
    print(f"Testing {target_url} for SQL Injection...")
    subprocess.run(["sqlmap", "-u", target_url, "--batch", "--dbs"])

# Brute Force Login using Hydra
def brute_force_login(target_ip, username, password_list, service="ssh"):
    print(f"Performing brute-force attack on {target_ip}...")
    subprocess.run(["hydra", "-l", username, "-P", password_list, target_ip, service])

# SSL Security Check using testssl.sh
def ssl_security_scan(target_url):
    print(f"Checking SSL Security for {target_url}...")
    subprocess.run(["testssl.sh", target_url])

# API Endpoint Discovery using ZAP
def api_scan(target_url):
    print(f"Scanning API endpoints for {target_url}...")
    zap.urlopen(target_url)
    zap.spider.scan(target_url)
    while int(zap.spider.status()) < 100:
        print("Spidering API in progress...")
    print("API scan complete!")
    print(json.dumps(zap.core.alerts(), indent=4))

# Main Execution
if __name__ == "__main__":
    target_web = "http://example.com"
    target_network = "192.168.1.1"
    target_domain = "example.com"
    
    passive_scan(target_web)
    dir_enum(target_web)
    subdomain_enum(target_domain)
    sql_injection_scan(target_web)
    brute_force_login(target_network, "admin", "passwords.txt")
    ssl_security_scan(target_web)
    api_scan(target_web)
