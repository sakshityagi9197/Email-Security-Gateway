# threat_detection/url_checker.py

import re
import requests

def extract_urls(text: str) -> list:
    return re.findall(r'https?://[^\s"\'>]+', text)

def check_url_reputation(url: str) -> dict:
    try:
        response = requests.get(url, timeout=5)
        return {"url": url, "status": response.status_code}
    except Exception as e:
        return {"url": url, "error": str(e)}
