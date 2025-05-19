#!/usr/bin/env python3
import asyncio
import socket
import subprocess
import whois
import requests
import json
import datetime
import os
import sys
import dns.resolver
from tqdm import tqdm

# Colors for output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

LOG_FILE = "devilscan_log.txt"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {msg}\n")

def banner():
    print(f"""{RED}
==============================================
          DevilScan Advanced v1.0
       By DarkDevil (Surya)
=============================================={RESET}""")

def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def yes_no_prompt(prompt):
    while True:
        ans = input(f"{prompt} (y/n): ").strip().lower()
        if ans in ('y','yes'):
            return True
        elif ans in ('n','no'):
            return False
        else:
            print("Please answer y or n")

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"{CYAN}[+] Resolved IP: {GREEN}{ip}{RESET}")
        log(f"Resolved IP for {domain}: {ip}")
        return ip
    except Exception as e:
        print(f"{RED}[-] Failed to resolve IP: {e}{RESET}")
        log(f"Failed to resolve IP for {domain}: {e}")
        sys.exit(1)

async def scan_port(ip, port, semaphore):
    async with semaphore:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

async def scan_ports(ip, ports):
    print(f"{YELLOW}[~] Scanning ports on {ip} ...{RESET}")
    semaphore = asyncio.Semaphore(500)
    tasks = [scan_port(ip, port, semaphore) for port in ports]
    open_ports = []
    for future in tqdm(asyncio.as_completed(tasks), total=len(tasks)):
        res = await future
        if res:
            open_ports.append(res)
    return sorted(open_ports)

def whois_lookup(domain):
    print(f"\n{CYAN}[*] Running WHOIS lookup...{RESET}")
    try:
        w = whois.whois(domain)
        for k,v in w.items():
            if v:
                print(f"{GREEN}{k}: {RESET}{v}")
        log(f"WHOIS lookup for {domain} done.")
    except Exception as e:
        print(f"{RED}[-] WHOIS lookup failed: {e}{RESET}")
        log(f"WHOIS lookup failed for {domain}: {e}")

def get_website_title(domain):
    try:
        url = f"http://{domain}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            start = r.text.find("<title>")
            end = r.text.find("</title>")
            if start != -1 and end != -1:
                title = r.text[start+7:end].strip()
                return title
        return "N/A"
    except:
        return "N/A"

def run_nmap(ip):
    print(f"\n{CYAN}[*] Running Nmap for service/version detection...{RESET}")
    try:
        result = subprocess.run(['nmap', '-sV', '-O', ip], capture_output=True, text=True, timeout=120)
        print(result.stdout)
        log(f"Nmap scan done for {ip}.")
    except Exception as e:
        print(f"{RED}[-] Nmap scan failed: {e}{RESET}")
        log(f"Nmap scan failed for {ip}: {e}")

def run_dirb(domain, wordlist):
    print(f"\n{CYAN}[*] Running dirb for directory brute forcing with wordlist: {wordlist}{RESET}")
    if not os.path.exists(wordlist):
        print(f"{RED}[-] Wordlist not found: {wordlist}{RESET}")
        log(f"Dirb wordlist not found: {wordlist}")
        return
    try:
        subprocess.run(['dirb', f'http://{domain}', wordlist], check=True)
        log(f"Dirb scan done on {domain} with {wordlist}")
    except Exception as e:
        print(f"{RED}[-] Dirb scan failed: {e}{RESET}")
        log(f"Dirb scan failed for {domain}: {e}")

def port_scan_range():
    print(f"{YELLOW}Enter port range to scan (default 1-1000):{RESET}")
    ports_input = input("Ports (e.g., 20-80 or 22,80,443): ").strip()
    if not ports_input:
        return list(range(1, 1001))
    elif '-' in ports_input:
        start, end = ports_input.split('-')
        return list(range(int(start), int(end)+1))
    else:
        ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
        return ports if ports else list(range(1, 1001))

def subdomain_enum(domain):
    print(f"\n{CYAN}[*] Enumerating subdomains using public API...{RESET}")
    api_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(api_url, timeout=15)
        if r.status_code != 200:
            print(f"{RED}[-] Failed to fetch subdomains (API error){RESET}")
            return []
        data = r.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sd in name.split("\n"):
                if sd.endswith(domain):
                    subdomains.add(sd.strip())
        if subdomains:
            print(f"{GREEN}[+] Found {len(subdomains)} subdomains:{RESET}")
            for sd in sorted(subdomains):
                print(f"  - {sd}")
            log(f"Subdomains found for {domain}: {len(subdomains)}")
        else:
            print(f"{YELLOW}No subdomains found.{RESET}")
        return list(subdomains)
    except Exception as e:
        print(f"{RED}[-] Subdomain enumeration failed: {e}{RESET}")
        log(f"Subdomain enumeration failed for {domain}: {e}")
        return []

async def main():
    banner()
    domain = input("Enter target domain or IP: ").strip()
    ip = resolve_ip(domain)
    title = get_website_title(domain)
    print(f"{CYAN}[+] Website Title: {GREEN}{title}{RESET}")

    ports = port_scan_range()

    open_ports = await scan_ports(ip, ports)
    if open_ports:
        print(f"\n{GREEN}[+] Open Ports: {', '.join(map(str, open_ports))}{RESET}")
    else:
        print(f"\n{RED}[-] No open ports found.{RESET}")

    if yes_no_prompt("Perform WHOIS lookup?"):
        whois_lookup(domain)

    if yes_no_prompt("Run subdomain enumeration?"):
        subdomain_enum(domain)

    if yes_no_prompt("Run detailed Nmap scan? (requires nmap installed)"):
        run_nmap(ip)

    if yes_no_prompt("Perform web directory brute force scan?"):
        wordlist = input("Enter path to wordlist (default /usr/share/wordlists/dirb/common.txt): ").strip()
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        run_dirb(domain, wordlist)

    print(f"\n{YELLOW}Scan completed at {now()}{RESET}")

if __name__ == "__main__":
    try:
        log(f"Starting scan on {datetime.datetime.now()}")
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{RED}Scan interrupted by user.{RESET}")
        log("Scan interrupted by user")
