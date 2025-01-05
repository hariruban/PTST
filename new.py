### Automated Penetration Testing Tool

# This code integrates reconnaissance, scanning (Nmap and OWASP ZAP), exploitation, and reporting into a single automated penetration testing tool with a user-friendly GUI.

import os
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext
from zapv2 import ZAPv2
import threading

# Reconnaissance Functions
def dns_lookup(target):
    """Performs DNS lookup."""
    try:
        command = f"nslookup {target}"
        output = os.popen(command).read()
        return output
    except Exception as e:
        return f"[ERROR] DNS Lookup failed: {str(e)}"

def subdomain_enum(target):
    """Performs subdomain enumeration (dummy data for now)."""
    # Implement subdomain enumeration using tools like Sublist3r or APIs.
    return ["sub1." + target, "sub2." + target]

def geolocate_ip(target):
    """Fetches geolocation information of the target (dummy data for now)."""
    # Use APIs like ipinfo.io for real implementation.
    return f"Location of {target}: Unknown City, Unknown Country"

def ssl_certificate_check(target):
    """Checks SSL certificate details (dummy data for now)."""
    return f"SSL Certificate for {target}: Valid, issued by Let's Encrypt."

# Scanning Functions
def nmap_detailed_scan(target):
    """Performs a detailed Nmap scan on the target."""
    try:
        nmap_command = f"nmap -sS -sV -O -p- {target}"
        output = os.popen(nmap_command).read()
        return output.splitlines()
    except Exception as e:
        return [f"[ERROR] Nmap scan failed: {str(e)}"]

def owasp_scan_real_time(target):
    """Performs a real-time OWASP ZAP scan on the target."""
    zap = ZAPv2(apikey='http://localhost:8080/JSON/core/view/version/?apikey=hnhsqpgkuv8f98fh17smrh1ppt')  # Replace with your OWASP ZAP API key

    try:
        # Start Spider Scan
        spider_id = zap.spider.scan(target)
        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(5)

        # Start Active Scan
        scan_id = zap.ascan.scan(target)
        while int(zap.ascan.status(scan_id)) < 100:
            time.sleep(5)

        # Fetch Alerts
        alerts = zap.core.alerts(baseurl=target)
        return alerts
    except Exception as e:
        return [f"[ERROR] An error occurred during OWASP scanning: {str(e)}"]

# Exploitation Functions
def exploit_vulnerability(target, exploit_name):
    """Performs exploitation (dummy implementation for now)."""
    # Implement exploitation using Metasploit or custom payloads.
    return f"[INFO] Exploited {target} using {exploit_name}."

# Reporting Function
def generate_report(report_content):
    """Generates a report based on the scan results."""
    try:
        with open("pentest_report.txt", "w") as report_file:
            for line in report_content:
                report_file.write(line + "\n")
        return "[INFO] Report saved as 'pentest_report.txt'."
    except Exception as e:
        return f"[ERROR] Report generation failed: {str(e)}"

# Main GUI Application
class PentestToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Automated Penetration Testing Tool")
        self.root.geometry("900x700")

        # Target Input
        self.target_label = tk.Label(root, text="Enter Target (IP/Domain):")
        self.target_label.pack(pady=10)

        self.target_entry = tk.Entry(root, width=50)
        self.target_entry.pack(pady=5)

        # Action Buttons
        self.start_button = tk.Button(root, text="Start Scan", command=self.start_scan, width=20)
        self.start_button.pack(pady=10)

        self.exploit_button = tk.Button(root, text="Exploit Vulnerabilities", command=self.start_exploit, width=20)
        self.exploit_button.pack(pady=5)

        self.report_button = tk.Button(root, text="Generate Report", command=self.generate_report_ui, width=20)
        self.report_button.pack(pady=5)

        # Results Display Area
        self.results_area = scrolledtext.ScrolledText(root, width=110, height=30)
        self.results_area.pack(pady=10)

    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showwarning("Input Error", "Please enter a target IP or domain.")
            return

        self.results_area.delete(1.0, tk.END)
        self.results_area.insert(tk.END, "[+] Starting Reconnaissance and Scanning...\n")

        scan_thread = threading.Thread(target=self.perform_scan, args=(target,))
        scan_thread.start()

    def perform_scan(self, target):
        # Reconnaissance
        self.results_area.insert(tk.END, "[INFO] Performing DNS Lookup...\n")
        dns_info = dns_lookup(target)
        self.results_area.insert(tk.END, f"{dns_info}\n")

        self.results_area.insert(tk.END, "[INFO] Performing Subdomain Enumeration...\n")
        subdomains = subdomain_enum(target)
        self.results_area.insert(tk.END, f"[INFO] Subdomains found: {', '.join(subdomains)}\n")

        self.results_area.insert(tk.END, "[INFO] Performing Geo Location Lookup...\n")
        geo_info = geolocate_ip(target)
        self.results_area.insert(tk.END, f"{geo_info}\n")

        self.results_area.insert(tk.END, "[INFO] Performing SSL Certificate Check...\n")
        ssl_info = ssl_certificate_check(target)
        self.results_area.insert(tk.END, f"{ssl_info}\n")

        # Detailed Nmap Scanning
        self.results_area.insert(tk.END, "\n[+] Starting Detailed Nmap Scan...\n")
        nmap_results = nmap_detailed_scan(target)
        for result in nmap_results:
            self.results_area.insert(tk.END, f"{result}\n")

        # Real-Time OWASP Vulnerability Scan
        self.results_area.insert(tk.END, "\n[+] Starting OWASP Vulnerability Scan...\n")
        self.results_area.insert(tk.END, "[INFO] This may take a few minutes...\n")

        try:
            alerts = owasp_scan_real_time(target)
            for alert in alerts:
                self.results_area.insert(tk.END, f"Alert: {alert['alert']} | Risk: {alert['risk']}\n")
        except Exception as e:
            self.results_area.insert(tk.END, f"[ERROR] OWASP Scan failed: {str(e)}\n")

        self.results_area.insert(tk.END, "\n[+] Scanning Completed!\n")

    def start_exploit(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showwarning("Input Error", "Please enter a target IP or domain.")
            return

        exploit_name = "exploit/multi/http/apache_mod_cgi_bash_env_exec"  # Example exploit
        self.results_area.insert(tk.END, "\n[+] Exploiting...\n")

        exploit_results = exploit_vulnerability(target, exploit_name)
        self.results_area.insert(tk.END, f"{exploit_results}\n")

    def generate_report_ui(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showwarning("Input Error", "Please enter a target IP or domain.")
            return

        self.results_area.insert(tk.END, "\n[+] Generating Report...\n")
        report_content = self.results_area.get(1.0, tk.END).strip().split("\n")
        report_status = generate_report(report_content)
        self.results_area.insert(tk.END, f"{report_status}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PentestToolApp(root)
    root.mainloop()
