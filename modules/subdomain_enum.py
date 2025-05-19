import requests

def passive_subdomain_enum(domain):
    subs = []
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            subs = list(set(entry['name_value'] for entry in data))
    except Exception:
        pass
    return subs

def brute_force_subdomain_enum(domain):
    subs = []
    common_subs = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'secure', 'server', 'ns1', 'ns2', 'admin']
    for sub in common_subs:
        full_sub = f"{sub}.{domain}"
        try:
            requests.get(f"http://{full_sub}", timeout=3)
            subs.append(full_sub)
        except:
            continue
    return subs
