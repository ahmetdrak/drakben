# modules/recon.py
# Drakben Recon Modülü - STATE-AWARE İleri Seviye Pasif Bilgi Toplama
# ZORUNLU: State kontrolü yapar, tested surface tekrar taramaz

import aiohttp
import asyncio
import requests
from bs4 import BeautifulSoup
import hashlib
import os

# State integration
try:
    from core.state import AgentState, ServiceInfo
    STATE_AVAILABLE = True
except ImportError:
    STATE_AVAILABLE = False

# Optional imports with fallback
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# AI özetleme için ai_bridge kullanılacak
from modules import ai_bridge


async def passive_recon(target, state: 'AgentState'):
    """
    STATE-AWARE passive recon
    
    ZORUNLU KONTROLLER:
    1. State varsa, tested surface kontrolü yap
    2. Aynı target tekrar taranmaz
    3. Sonuç state'e yazılır
    """
    print(f"[Recon] {target} için pasif bilgi toplanıyor...")
    
    # STATE KONTROLÜ
    if not STATE_AVAILABLE or not state:
        return {
            "target": target,
            "error": "State tracking is required for recon",
            "blocked": True
        }

    # Check if target already scanned in this session
    if state.target == target and state.open_services:
        print(f"[Recon] ⚠️  Target already scanned in this session, skipping duplicate")
        return {
            "target": target,
            "error": "Already scanned",
            "cached_services": len(state.open_services)
        }

    result = {
        "target": target,
        "title": None,
        "description": None,
        "headers": {},
        "favicon_hash": None,
        "forms": [],
        "scripts": [],
        "cms": None,
        "robots": None,
        "sitemap": None,
        "dns_records": {},
        "whois": {},
        "notes": []
    }

    try:
        # HTTP isteği
        async with aiohttp.ClientSession() as session:
            async with session.get(target, timeout=10) as resp:
                result["headers"] = dict(resp.headers)
                html = await resp.text()

        soup = BeautifulSoup(html, "html.parser")

        # Başlık ve meta description
        result["title"] = soup.title.string.strip() if soup.title else None
        meta_desc = soup.find("meta", attrs={"name": "description"})
        result["description"] = meta_desc["content"].strip() if meta_desc else None

        # Favicon hash
        favicon = soup.find("link", rel="icon")
        if favicon and favicon.get("href"):
            favicon_url = favicon["href"]
            if not favicon_url.startswith("http"):
                favicon_url = target.rstrip("/") + "/" + favicon_url.lstrip("/")
            fav_resp = requests.get(favicon_url, timeout=5)
            result["favicon_hash"] = hashlib.md5(fav_resp.content).hexdigest()

        # Form alanları
        for form in soup.find_all("form"):
            inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
            result["forms"].append({"action": form.get("action"), "inputs": inputs})

        # JS dosyaları
        result["scripts"] = [script.get("src") for script in soup.find_all("script") if script.get("src")]

        # CMS tespiti (basit)
        if "wp-content" in html or "WordPress" in html:
            result["cms"] = "WordPress"
        elif "Joomla" in html:
            result["cms"] = "Joomla"
        elif "Drupal" in html:
            result["cms"] = "Drupal"

        # robots.txt
        try:
            robots = requests.get(target.rstrip("/") + "/robots.txt", timeout=5)
            if robots.status_code == 200:
                result["robots"] = robots.text.splitlines()
        except:
            pass

        # sitemap.xml
        try:
            sitemap = requests.get(target.rstrip("/") + "/sitemap.xml", timeout=5)
            if sitemap.status_code == 200:
                result["sitemap"] = sitemap.text[:500]  # ilk 500 karakter
        except:
            pass

        # DNS kayıtları
        if DNS_AVAILABLE:
            try:
                result["dns_records"]["A"] = [str(r) for r in dns.resolver.resolve(target.replace("https://","").replace("http://",""), "A")]
            except:
                result["dns_records"]["A"] = []

            try:
                result["dns_records"]["MX"] = [str(r) for r in dns.resolver.resolve(target.replace("https://","").replace("http://",""), "MX")]
            except:
                result["dns_records"]["MX"] = []

            try:
                result["dns_records"]["TXT"] = [str(r) for r in dns.resolver.resolve(target.replace("https://","").replace("http://",""), "TXT")]
            except:
                result["dns_records"]["TXT"] = []
        else:
            result["dns_records"]["error"] = "dnspython not installed"

        # Whois bilgisi
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(target.replace("https://","").replace("http://",""))
                result["whois"] = {
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date),
                    "expiration_date": str(w.expiration_date),
                    "name_servers": w.name_servers
                }
            except Exception as e:
                result["whois"] = {"error": str(e)}
        else:
            result["whois"] = {"error": "python-whois not installed"}

        # AI özetleme
        ai_summary = await ai_bridge.analyze_recon_output(result)
        result["ai_summary"] = ai_summary

        return result

    except Exception as e:
        print(f"[Recon] Hata: {e}")
        result["error"] = str(e)
        return result
