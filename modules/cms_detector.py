import requests

def detect_cms(domain):
    detected = []
    url = f"http://{domain}"
    try:
        r = requests.get(url, timeout=5).text.lower()
        if 'wp-content' in r or 'wordpress' in r:
            detected.append('WordPress')
        if 'joomla' in r:
            detected.append('Joomla')
        if 'drupal' in r:
            detected.append('Drupal')
    except:
        pass
    return detected
