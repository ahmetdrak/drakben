import logging
import sys
import urllib.parse
from typing import Any

import requests
from bs4 import BeautifulSoup

try:
    from modules.stealth_client import StealthSession
except ImportError:
    StealthSession = requests.Session

try:
    from rich.console import Console

    console = Console()
except ImportError:
    console = None
    Console = None

logger = logging.getLogger("drakben.researcher")


class WebResearcher:
    """Drakben's eyes on the internet.
    Uses Stealth Client to mimic Chrome 120 and bypass search engine anti-bot protection.
    """

    def __init__(self) -> None:
        # Initialize Persistent Stealth Session (Chrome 120 Fingerprint)
        self.session = StealthSession(impersonate="chrome120", randomize_behavior=True)

        # Note: Headers are mostly handled by curl_cffi, but we add some semantic ones
        self.session.headers.update(
            {
                "Referer": "https://www.google.com/",
                "Cache-Control": "max-age=0",
            },
        )

    def search_tool(self, query: str, max_results=5) -> Any:
        """Searches specific targets using DDG HTML endpoint."""
        results: list[dict[str, Any]] = []
        try:
            logger.info("Stealth Search for: %s", query)

            # Method 1: DuckDuckGo HTML (No JS required)
            url = "https://html.duckduckgo.com/html/"
            payload = {"q": query}

            # Use stealth session
            resp = self.session.post(url, data=payload, timeout=15)

            if resp.status_code != 200:
                logger.warning(
                    f"DDG HTML failed ({resp.status_code}), trying Bing fallback.",
                )
                return self._search_bing_fallback(query, max_results)

            soup = BeautifulSoup(resp.text, "html.parser")

            # DDG HTML selectors
            for link in soup.find_all("div", class_="result"):
                if len(results) >= max_results:
                    break

                title_tag = link.find("a", class_="result__a")
                if not title_tag:
                    continue

                href = title_tag.get("href")
                title = title_tag.get_text(strip=True)

                snippet_tag = link.find("a", class_="result__snippet")
                body = (
                    snippet_tag.get_text(strip=True)
                    if snippet_tag
                    else "No description."
                )

                results.append({"title": title, "href": href, "body": body})

            if not results:
                # Last resort fallback if DDG structure changed or blocked
                logger.warning("DDG parsed but no results found. Trying Bing.")
                return self._search_bing_fallback(query, max_results)

            return results

        except Exception as e:
            logger.exception("Search failed: %s", e)
            return []

    def download_file(self, url: str, output_path: str) -> bool | None:
        """Downloads a file using Stealth Session (Bypasses firewall blocks)."""
        try:
            logger.info("Stealth Downloading from {url} to %s", output_path)

            # Note: curl_cffi doesn't support stream=True in the same way requests does for file iteration
            # We download in memory then write for now (assuming files < 50MB)
            # For larger files, we might need requests fallback or chunked impl

            # Check if session supports streaming (requests)
            is_requests = isinstance(self.session, requests.Session)

            if is_requests:
                with self.session.get(url, stream=True, timeout=60) as r:
                    r.raise_for_status()
                    with open(output_path, "wb") as f:
                        f.writelines(r.iter_content(chunk_size=8192))
            else:
                # StealthSession (curl_cffi) doesn't stream well. Fallback to requests for large files.
                # Just use requests directly for downloads to be safe on memory

                with requests.get(
                    url,
                    stream=True,
                    timeout=60,
                    headers={"User-Agent": "Mozilla/5.0"},
                ) as r:
                    r.raise_for_status()
                    with open(output_path, "wb") as f:
                        f.writelines(r.iter_content(chunk_size=8192))

            return True
        except Exception as e:
            logger.exception("Download failed: %s", e)
            return False

    def extract_code_from_url(self, url: str) -> Any:
        """Extracts code from URL using Stealth Session."""
        try:
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace(
                    "/blob/",
                    "/",
                )

            resp = self.session.get(url, timeout=15)
            return resp.text
        except Exception as e:
            logger.exception("Extract failed: %s", e)
            return ""

    def _search_bing_fallback(self, query, max_results) -> Any:
        """Bing scraping fallback with Stealth Headers."""
        results = []
        try:
            url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}"
            resp = self.session.get(url, timeout=15)

            soup = BeautifulSoup(resp.text, "html.parser")

            # Bing selectors (li.b_algo)
            for item in soup.find_all("li", class_="b_algo"):
                if len(results) >= max_results:
                    break

                h2 = item.find("h2")
                if not h2:
                    continue

                a_tag = h2.find("a")
                if not a_tag:
                    continue

                title = a_tag.get_text(strip=True)
                href = a_tag.get("href")

                # Snippet
                snippet = "No description."
                p_tag = item.find("p")
                if p_tag:
                    snippet = p_tag.get_text(strip=True)

                results.append({"title": title, "href": href, "body": snippet})

            return results
        except Exception as e:
            logger.exception("Bing fallback failed: %s", e)
            return []


# Simple test
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    researcher = WebResearcher()

    q = "sqlmap github"
    if len(sys.argv) > 1:
        q = sys.argv[1]

    res = researcher.search_tool(q)

    if not res:
        pass
    else:
        for _r in res:
            pass
