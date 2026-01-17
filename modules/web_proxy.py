# modules/web_proxy.py
import requests
from bs4 import BeautifulSoup

def fetch_url(url, headers=None, timeout=10):
    """
    Belirtilen URL'den HTML içeriği çeker
    """
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return r.text
        return f"[!] HTTP {r.status_code} hatası: {url}"
    except Exception as e:
        return f"[!] URL çekme hatası: {e}"

def extract_text_from_html(html, max_len=3000):
    """
    HTML içinden düz metin çıkarır, uzunluğu sınırlar
    """
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator="\n")
    return text.strip()[:max_len]

def fetch_and_summarize(url, ai_func):
    """
    URL'den veri çek → temizle → AI ile özetle
    """
    html = fetch_url(url)
    if html.startswith("[!]"):
        return html
    text = extract_text_from_html(html)
    summary = ai_func(f"Bu sayfanın içeriğini özetle:\n\n{text}")
    return summary
