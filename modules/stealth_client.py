"""DRAKBEN Stealth Client - Powered by curl_cffi
Author: @ahmetdrak
Description: State-of-the-art TLS Fingerprint Impersonation with Proxy Rotation and Human Behavior Simulation.
"""

import asyncio
import logging
import secrets
import time
from typing import Any

from curl_cffi.requests import AsyncSession, Session

logger = logging.getLogger(__name__)

# List of browser impersonations to rotate
BROWSER_IMPERSONATIONS = [
    "chrome120",
    "chrome119",
    "safari17_0",
    "edge101",
]

# Common Referers to boost trust score
REPUTABLE_REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://twitter.com/",
    "https://www.facebook.com/",
    "https://www.reddit.com/",
]


class ProxyManager:
    """Manages proxy rotation and health checks."""

    def __init__(self, proxies: list[str] | None = None) -> None:
        self.proxies = proxies or []
        self.bad_proxies: set[str] = set()

    def get_proxy(self) -> str | None:
        """Get a random working proxy."""
        available = [p for p in self.proxies if p not in self.bad_proxies]
        if not available:
            return None
        import secrets

        return secrets.choice(available)

    def mark_bad(self, proxy: str) -> None:
        """Mark proxy as failed/blocked."""
        if proxy:
            self.bad_proxies.add(proxy)
            logger.warning("Proxy marked as bad: %s", proxy)


class StealthSession(Session):
    """Advanced Session with Cloudflare Bypass capabilities.
    Features:
    - TLS Fingerprint Impersonation (JA3/JA4 compatible)
    - Proxy Rotation
    - Human Behavior Simulation (Jitter, Referer Spoofing).
    """

    def __init__(
        self,
        impersonate: str | None = None,
        proxies: list[str] | None = None,
        randomize_behavior: bool = True,
        **kwargs,
    ) -> None:
        """Args:
        impersonate (str): Browser to impersonate
        proxies (List[str]): List of proxy URLs (http/socks5)
        randomize_behavior (bool): Enable jitter and header randomization.

        """
        # Pick random browser if not specified
        self.impersonate_target = impersonate or secrets.choice(BROWSER_IMPERSONATIONS)
        self.proxy_manager = ProxyManager(proxies)
        self.randomize_behavior = randomize_behavior
        self.current_proxy = self.proxy_manager.get_proxy()
        self._last_url: str = ""

        # Init parent with proxy if available
        super().__init__(
            impersonate=self.impersonate_target,
            proxies={"http": self.current_proxy, "https": self.current_proxy}
            if self.current_proxy
            else None,
            **kwargs,
        )

        self.headers.update(self._get_default_headers())
        logger.debug(
            f"StealthSession initialized: {self.impersonate_target} | Proxy: {bool(self.current_proxy)}",
        )

    def _get_default_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            # Note: User-Agent is handled by curl_cffi impersonate, but we can override if needed
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
        }

        if self.randomize_behavior and "Referer" not in self.headers:
            # LOGIC FIX: Only set initial referer if not already present.
            # Jumper-style referer change on every request is suspicious.
            headers["Referer"] = secrets.choice(REPUTABLE_REFERERS)

        # Ensure User-Agent is present (curl_cffi sometimes sets it late)
        if "User-Agent" not in headers:
            ua_map = {
                "chrome120": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Windows",
                    "Chromium",
                ),
                "chrome119": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                    "Windows",
                    "Chromium",
                ),
                "safari17_0": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                    "macOS",
                    "Safari",
                ),
                "edge101": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47",
                    "Windows",
                    "Chromium",
                ),
            }
            ua_data = ua_map.get(
                self.impersonate_target,
                (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Windows",
                    "Chromium",
                ),
            )
            headers["User-Agent"] = ua_data[0]
            # LOGIC FIX: Global consistency for platform and brand
            headers["sec-ch-ua-platform"] = f'"{ua_data[1]}"'
            if ua_data[2] == "Chromium":
                headers["sec-ch-ua"] = (
                    '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
                )
            else:
                # Safari doesn't use sec-ch-ua headers typically
                headers.pop("sec-ch-ua", None)
                headers.pop("sec-ch-ua-mobile", None)
                headers.pop("sec-ch-ua-platform", None)

        return headers

    def rotate_identity(self) -> None:
        """Rotate browser fingerprint and proxy (Logic Fix: Update headers too)."""
        self.impersonate_target = secrets.choice(BROWSER_IMPERSONATIONS)
        self.current_proxy = self.proxy_manager.get_proxy()

        # Update headers for the new identity
        new_headers = self._get_default_headers()
        self.headers.update(new_headers)

        if self.current_proxy:
            self.proxies = {"http": self.current_proxy, "https": self.current_proxy}

    def request(self, method: str, url: str, *args, **kwargs) -> Any:
        # Human Jitter (Anti-Bot)
        if self.randomize_behavior:
            # random.uniform(0.5, 3.0) equivalent using secrets
            sleep_time = 0.5 + (secrets.randbelow(2500) / 1000.0)
            time.sleep(sleep_time)

        # LOGIC FIX: Maintain stateful Referer chain
        if not kwargs.get("headers"):
            kwargs["headers"] = {}

        if "Referer" not in kwargs["headers"] and hasattr(self, "_last_url"):
            # If same domain, use last URL as referer
            from urllib.parse import urlparse

            curr_domain = urlparse(url).netloc
            last_domain = urlparse(self._last_url).netloc
            if curr_domain == last_domain:
                kwargs["headers"]["Referer"] = self._last_url

        try:
            if "impersonate" not in kwargs:
                kwargs["impersonate"] = self.impersonate_target

            response = super().request(method, url, *args, **kwargs)

            # LOGIC FIX: Track URL for referer stability
            self._last_url = url

            # WAF/Block Detection Logic
            if response.status_code in [403, 406, 429, 503]:
                if any(
                    x in response.text.lower()
                    for x in ["cloudflare", "just a moment", "challenge"]
                ):
                    logger.warning(
                        f"Cloudflare Challenge Detected! ({response.status_code})",
                    )
                    self.proxy_manager.mark_bad(self.current_proxy)
                    self.rotate_identity()  # Auto-rotate on block
                elif response.status_code == 429:
                    logger.warning("Rate Limited! Cooling down...")
                    time.sleep(5)

            return response

        except Exception as e:
            logger.exception("Stealth Request Failed: %s", e)
            self.proxy_manager.mark_bad(self.current_proxy)
            raise


# Async Version for high-concurrency scans
class AsyncStealthSession(AsyncSession):
    """Async version of StealthSession with similar capabilities."""

    def __init__(
        self, impersonate: str | None = None, proxies: list[str] | None = None, **kwargs,
    ) -> None:
        self.impersonate_target = impersonate or secrets.choice(BROWSER_IMPERSONATIONS)
        self.proxies_list = proxies or []
        super().__init__(impersonate=self.impersonate_target, **kwargs)

    async def request(self, method: str, url: str, *args, **kwargs) -> Any:
        # Simple jitter for async
        await asyncio.sleep(0.1 + (secrets.randbelow(1400) / 1000.0))  # 0.1 - 1.5
        return await super().request(method, url, *args, **kwargs)
