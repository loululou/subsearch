#!/usr/bin/env python3

import requests
import dns.resolver
import argparse
import concurrent.futures

# User-Agent header to prevent blocking
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
}

# Wordlist for brute-force method
WORDLIST = "subdomains.txt"

def is_resolvable(subdomain):
    try:
        dns.resolver.resolve(subdomain, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        return False

def brute_force_subdomains(domain):
    found_subdomains = []
    
    with open(WORDLIST, "r") as file:
        subdomains = [line.strip() + "." + domain for line in file]

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {executor.submit(is_resolvable, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(future_to_subdomain):
            sub = future_to_subdomain[future]
            if future.result():
                print(f"[FOUND] {sub}")
                found_subdomains.append(sub)

    return found_subdomains

def crtsh_enum(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for entry in json_data:
                subdomain = entry["name_value"]
                subdomains.add(subdomain.replace("\n", "").strip())
    except requests.RequestException:
        print("[ERROR] Failed to fetch data from crt.sh")
    
    return list(subdomains)

def hackertarget_enum(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()

    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            results = response.text.split("\n")
            for result in results:
                parts = result.split(",")
                if len(parts) > 0:
                    subdomains.add(parts[0])
    except requests.RequestException:
        print("[ERROR] Failed to fetch data from HackerTarget")
    
    return list(subdomains)

def alienvault_enum(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains = set()

    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for entry in json_data.get("passive_dns", []):
                subdomains.add(entry["hostname"])
    except requests.RequestException:
        print("[ERROR] Failed to fetch data from AlienVault")
    
    return list(subdomains)

def urlscan_enum(domain):
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    subdomains = set()

    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for result in json_data.get("results", []):
                page_domain = result.get("page", {}).get("domain", "")
                if page_domain:
                    subdomains.add(page_domain)
    except requests.RequestException:
        print("[ERROR] Failed to fetch data from urlscan.io")

    return list(subdomains)

def enumerate_subdomains(domain):
    all_subdomains = set()

    print("\n[+] Starting subdomain enumeration...\n")

    # 1. Brute-force method
    print("[*] Running brute-force subdomain enumeration...")
    all_subdomains.update(brute_force_subdomains(domain))

    # 2. CRT.sh (Certificate Transparency Logs)
    print("[*] Fetching subdomains from crt.sh...")
    all_subdomains.update(crtsh_enum(domain))

    # 3. HackerTarget API
    print("[*] Fetching subdomains from HackerTarget...")
    all_subdomains.update(hackertarget_enum(domain))

    # 4. AlienVault OTX API
    print("[*] Fetching subdomains from AlienVault...")
    all_subdomains.update(alienvault_enum(domain))

    # 5. Urlscan.io API 
    print("[*] Fetching subdomains from Urlscan.io...")
    all_subdomains.update(urlscan_enum(domain))

    print(f"\n[+] Found {len(all_subdomains)} unique subdomains!\n")

    for sub in sorted(all_subdomains):
        print(sub)

    return all_subdomains

def save_results(subdomains, output_file):
    with open(output_file, "w") as file:
        for sub in sorted(subdomains):
            file.write(sub + "\n")
    print(f"\n[+] Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python-based Subdomain Finder")
    parser.add_argument("domain", help="Target domain to find subdomains for")
    parser.add_argument("-o", "--output", help="Output file to save results", default="subdomains_found.txt")

    args = parser.parse_args()
    
    subdomains = enumerate_subdomains(args.domain)
    save_results(subdomains, args.output)
