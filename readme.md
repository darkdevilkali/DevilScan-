# DevilScan Advanced

DevilScan Advanced is a powerful and fast network and web reconnaissance tool written in Python.  
It includes asynchronous port scanning, WHOIS lookup, subdomain enumeration, web directory brute forcing, and Nmap integration.

## Features
- Async port scanning with progress bar  
- Domain IP resolution and website title fetching  
- WHOIS lookup  
- Subdomain enumeration via crt.sh API  
- Nmap scan integration  
- Web directory brute forcing using `dirb`  
- Customizable wordlist support  
- Logs activities to `devilscan_log.txt`  

## Requirements
- Python 3.7+  
- External tools: `nmap`, `dirb` (install via your package manager)  
- Python packages (install via pip):  
  - requests  
  - tqdm  
  - python-whois  
  - dnspython  

## Installation
```bash
pip install -r requirements.txt
sudo apt install nmap dirb
