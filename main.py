from modules.reconnaissance import dns_lookup, subdomain_enum, geolocate_ip
from modules.scanning import nmap_scan, owasp_scan
from modules.exploitation import exploit_vulnerability
from modules.reporting import generate_report

def main():
    print("Welcome to AutoPentest - Enhanced Pentesting Tool")
    target = input("Enter the target (IP/Domain): ")

    # Reconnaissance
    print("\n[+] Starting Reconnaissance...")
    dns_info = dns_lookup(target)
    print(dns_info)
    subdomains = subdomain_enum(target)
    print(f"[INFO] Subdomains: {', '.join(subdomains)}")
    geo_info = geolocate_ip(target)
    print(geo_info)

    # Scanning
    print("\n[+] Starting Scanning...")
    nmap_results = nmap_scan(target)
    for result in nmap_results:
        print(result)
    owasp_results = owasp_scan(target)
    for result in owasp_results:
        print(result)

    # Exploitation
    print("\n[+] Starting Exploitation...")
    exploit_name = input("Enter exploit to use (e.g., exploit/multi/http/apache_mod_cgi_bash_env_exec): ")
    exploit_results = exploit_vulnerability(target, exploit_name)
    print(exploit_results)

    # Reporting
    print("\n[+] Generating Report...")
    report_content = [dns_info] + [geo_info] + nmap_results + owasp_results + [exploit_results]
    report_status = generate_report(report_content)
    print(report_status)

if __name__ == "__main__":
    main()
