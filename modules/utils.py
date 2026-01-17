# modules/utils.py
import re
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

def clean_url(url: str) -> str:
    """URL içinden http/https kaldır, sadeleştir"""
    return url.strip().replace("http://", "").replace("https://", "").rstrip("/")

def extract_emails(text: str):
    """Metin içinden e-posta adreslerini çıkar"""
    return re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)

def extract_forms(html: str):
    """HTML içinden form ve parametreleri çıkar"""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        inputs = [i.get("name") for i in form.find_all("input") if i.get("name")]
        forms.append({"action": form.get("action"), "method": form.get("method"), "inputs": inputs})
    return forms

def download_wordlist(url: str, filename="wordlist.txt"):
    """Wordlist indir ve kaydet"""
    r = requests.get(url)
    with open(filename, "w") as f:
        f.write(r.text)
    return f"Wordlist indirildi: {filename}"

def progress_bar(iterable, desc="İşlem"):
    """İşlem sırasında progress bar göster"""
    return tqdm(iterable, desc=desc)
