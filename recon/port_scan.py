import nmap
import concurrent.futures

def port_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-T4 -F")
    open_ports = [port for port in scanner[target]['tcp'] if scanner[target]['tcp'][port]['state'] == "open"]
    return {target: open_ports}

def run_port_scan(targets):
    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_target = {executor.submit(port_scan, target): target for target in targets}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            results[target] = future.result()
    return results

# Example Usage
# run_port_scan(["example.com", "test.com"])
