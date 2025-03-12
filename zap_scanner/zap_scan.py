import requests
import time

ZAP_URL = "http://localhost:8080"
API_KEY = "4t7etjln63ta6c8rrthena0820"

def zap_scan(target):
    scan_url = f"{ZAP_URL}/JSON/ascan/action/scan/?apikey={API_KEY}&url={target}&recurse=true"
    response = requests.get(scan_url).json()
    scan_id = response.get("scan")

    if not scan_id:
        return {"error": "Scan failed"}

    while True:
        progress_url = f"{ZAP_URL}/JSON/ascan/view/status/?apikey={API_KEY}&scanId={scan_id}"
        progress = requests.get(progress_url).json().get("status")
        print(f"[*] Scan Progress: {progress}%")
        if progress == "100":
            break
        time.sleep(5)

    results_url = f"{ZAP_URL}/JSON/core/view/alerts/?apikey={API_KEY}"
    return requests.get(results_url).json()

