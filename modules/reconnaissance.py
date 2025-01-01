import socket
import requests

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"[INFO] Domain: {domain}, IP: {ip}"
    except Exception as e:
        return f"[ERROR] DNS lookup failed: {e}"

def subdomain_enum(domain, subdomains=None):
    if subdomains is None:
        subdomains = ["www", "mail", "ftp", "dev"]
    found = []
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            found.append(subdomain)
        except socket.gaierror:
            continue
    return found if found else ["No subdomains found."]

def geolocate_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            return f"[INFO] Location: {data.get('city')}, {data.get('region')}, {data.get('country')}"
        else:
            return "[ERROR] Failed to geolocate IP."
    except Exception as e:
        return f"[ERROR] Geolocation error: {e}"

def ssl_certificate_check(domain):
    import ssl
    import datetime
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                if expiry_date < datetime.datetime.now():
                    return f"[WARNING] SSL Certificate expired on {expiry_date}"
                return f"[INFO] SSL Certificate is valid until {expiry_date}"
    except Exception as e:
        return f"[ERROR] SSL Certificate check failed: {e}"
