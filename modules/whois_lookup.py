import whois

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"Error fetching WHOIS: {e}"
