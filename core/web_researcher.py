import os
import requests
import logging
import urllib.parse
import time
from typing import Any, Dict, List, Optional
from bs4 import BeautifulSoup

try:
    from rich.console import Console
    console: Optional[Console] = Console()
except ImportError:
    console = None

logger = logging.getLogger("drakben.researcher")

class WebResearcher:
    """
    Drakben's eyes on the internet.
    Uses direct HTML scraping fallback to ensure results even if libraries fail.
    """

    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        }

    def search_tool(self, query: str, max_results=5):
        """Searches specific targets using DDG HTML endpoint."""
        results: List[Dict[str, Any]] = []
        try:
            logger.info(f"Searching for: {query}")
            
            # Method 1: DuckDuckGo HTML (No JS required)
            url = "https://html.duckduckgo.com/html/"
            payload = {'q': query}
            
            resp = requests.post(url, data=payload, headers=self.headers, timeout=10)

            if resp.status_code != 200:
                logger.warning(f"DDG HTML failed ({resp.status_code}), trying Bing fallback.")
                return self._search_bing_fallback(query, max_results)

            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # DDG HTML selectors
            for link in soup.find_all('div', class_='result'):
                if len(results) >= max_results:
                    break
                    
                title_tag = link.find('a', class_='result__a')
                if not title_tag: continue
                
                href = title_tag.get('href')
                title = title_tag.get_text(strip=True)
                
                snippet_tag = link.find('a', class_='result__snippet')
                body = snippet_tag.get_text(strip=True) if snippet_tag else "No description."

                results.append({
                    "title": title,
                    "href": href,
                    "body": body
                })

            if not results:
                 # Last resort fallback if DDG structure changed or blocked
                 logger.warning("DDG parsed but no results found. Trying Bing.")
                 return self._search_bing_fallback(query, max_results)

            return results
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    def download_file(self, url: str, output_path: str):
        """Downloads a file securely."""
        try:
            logger.info(f"Downloading from {url} to {output_path}")
            with requests.get(url, headers=self.headers, stream=True, timeout=10) as r:
                r.raise_for_status()
                with open(output_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            return True
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    def extract_code_from_url(self, url: str):
        """Extracts code from URL."""
        try:
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            resp = requests.get(url, headers=self.headers, timeout=10)
            return resp.text
        except Exception as e:
            logger.error(f"Extract failed: {e}")
            return ""

    def _search_bing_fallback(self, query, max_results):
        """Bing scraping fallback"""
        results = []
        try:
            url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}"
            resp = requests.get(url, headers=self.headers, timeout=10)
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Bing selectors (li.b_algo)
            for item in soup.find_all('li', class_='b_algo'):
                if len(results) >= max_results:
                    break
                
                h2 = item.find('h2')
                if not h2: continue
                
                a_tag = h2.find('a')
                if not a_tag: continue
                
                title = a_tag.get_text(strip=True)
                href = a_tag.get('href')
                
                # Snippet
                snippet = "No description."
                p_tag = item.find('p')
                if p_tag:
                    snippet = p_tag.get_text(strip=True)
                
                results.append({
                    "title": title,
                    "href": href,
                    "body": snippet
                })
                
            return results
        except Exception as e:
            logger.error(f"Bing fallback failed: {e}")
            return []

    # ... (other methods like download_file keep same)

# Simple test
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    researcher = WebResearcher()
    
    q = "sqlmap github"
    if len(sys.argv) > 1:
        q = sys.argv[1]
    
    print(f"Searching for: {q}")
    res = researcher.search_tool(q)
    
    if not res:
        print("FAIL: No results returned.")
    else:
        for r in res:
            print(f"Found: {r['title']} - {r['href']}")
