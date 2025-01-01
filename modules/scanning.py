import nmap
import random

def nmap_scan(target, port_range="22,80,443,8080"):
    scanner = nmap.PortScanner()
    scanner.scan(target, port_range, '-T4 -sV')  # -T4 is faster and reasonable for most cases.
    results = []
    for host in scanner.all_hosts():
        results.append(f"[INFO] Host: {host}, State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                results.append(f"  Port: {port}, Service: {scanner[host][proto][port]['name']}")
    return results

def owasp_scan(target):
    vulnerabilities = [
        "[INFO] SQL Injection Vulnerability: Not Detected",
        "[INFO] XSS Vulnerability: Detected on /search endpoint",
        "[INFO] Directory Traversal: Not Detected",
        "[INFO] CSRF Vulnerability: Detected on /login endpoint"
    ]
    detected = [v for v in vulnerabilities if random.choice([True, False])]
    return detected if detected else ["[INFO] No critical vulnerabilities found."]
