import socket
import requests

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"[INFO] Domain: {domain}, IP: {ip}"
    except Exception as e:
        return f"[ERROR] DNS lookup failed: {e}"

def subdomain_enum(domain):
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
