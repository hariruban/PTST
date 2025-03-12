import subprocess
import concurrent.futures

def subdomain_enum(target):
    print(f"[*] Enumerating subdomains for {target}...")

    cmd = f"subfinder -d {target} -silent"
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    subdomains = output.stdout.splitlines()

    print(f"[+] Found {len(subdomains)} subdomains.")
    return subdomains

def run_subdomain_enum(targets):
    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_target = {executor.submit(subdomain_enum, target): target for target in targets}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            results[target] = future.result()
    return results

# Example Usage
# run_subdomain_enum(["example.com", "test.com"])
