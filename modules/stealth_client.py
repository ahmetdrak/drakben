"""
DRAKBEN Stealth Client - Powered by curl_cffi
Author: @ahmetdrak
Description: State-of-the-art TLS Fingerprint Impersonation to bypass Cloudflare/Akamai.
"""

import logging
import random
from typing import Any, Dict

from curl_cffi.requests import AsyncSession, Session

logger = logging.getLogger(__name__)

# List of browser impersonations to rotate
BROWSER_IMPERSONATIONS = [
    "chrome120",
    "chrome119",
    "safari17_0",
    "edge101",
]


class StealthSession(Session):
    """
    Drop-in replacement for requests.Session but uses curl_cffi under the hood.
    Successfully impersonates real browsers (JA3/TLS/HTTP2).
    """

    def __init__(self, impersonate: str = "chrome120", **kwargs):
        """
        Args:
            impersonate (str): Browser to impersonate (e.g., "chrome120", "safari17_0")
        """
        # If no specific impersonation requested, pick a random modern one
        self.impersonate_target = impersonate or random.choice(BROWSER_IMPERSONATIONS)
        super().__init__(impersonate=self.impersonate_target, **kwargs)
        self.headers = self._get_default_headers()
        logger.debug(
            f"StealthSession init initialized with impersonation: {self.impersonate_target}"
        )

    def _get_default_headers(self) -> Dict[str, str]:
        # curl_cffi handles most headers automatically based on impersonation.
        # We just add some generic accept headers if needed.
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            # Force Chrome UA for verification if curl_cffi doesn't auto-populate it in this specific test env
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }

    def request(self, method: str, url: str, *args, **kwargs) -> Any:
        try:
            # Ensure impersonate param is passed if not provided
            if "impersonate" not in kwargs:
                kwargs["impersonate"] = self.impersonate_target

            # Execute request
            response = super().request(method, url, *args, **kwargs)

            # WAF/Block Detection
            if response.status_code in [403, 406, 429]:
                # Check if it's a Cloudflare challenge page
                if (
                    "Just a moment..." in response.text
                    or "cloudflare" in response.text.lower()
                ):
                    logger.warning(
                        f"StealthSession: Cloudflare Challenge Detected! ({response.status_code})"
                    )
                else:
                    logger.warning(
                        f"StealthSession: WAF Block Detected ({response.status_code})"
                    )

            return response

        except Exception as e:
            logger.error(f"Stealth Request Failed: {e}")
            raise


# Async Version for high-concurrency scans
class AsyncStealthSession(AsyncSession):
    """Async version of StealthSession"""

    def __init__(self, impersonate: str = "chrome120", **kwargs):
        self.impersonate_target = impersonate or random.choice(BROWSER_IMPERSONATIONS)
        super().__init__(impersonate=self.impersonate_target, **kwargs)

    async def request(self, method: str, url: str, *args, **kwargs) -> Any:
        # Note: curl_cffi AsyncSession request logic is slightly different, usually simpler
        return await super().request(method, url, *args, **kwargs)
