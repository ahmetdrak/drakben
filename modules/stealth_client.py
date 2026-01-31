"""
DRAKBEN Stealth Client - Powered by curl_cffi
Author: @ahmetdrak
Description: State-of-the-art TLS Fingerprint Impersonation with Proxy Rotation and Human Behavior Simulation.
"""

import asyncio
import logging
import random
import time
from typing import Any, Dict, List, Optional

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
    """Manages proxy rotation and health checks"""

    def __init__(self, proxies: List[str] = None):
        self.proxies = proxies or []
        self.bad_proxies = set()

    def get_proxy(self) -> Optional[str]:
        """Get a random working proxy"""
        available = [p for p in self.proxies if p not in self.bad_proxies]
        if not available:
            return None
        return random.choice(available)

    def mark_bad(self, proxy: str):
        """Mark proxy as failed/blocked"""
        if proxy:
            self.bad_proxies.add(proxy)
            logger.warning(f"Proxy marked as bad: {proxy}")


class StealthSession(Session):
    """
    Advanced Session with Cloudflare Bypass capabilities.
    Features:
    - TLS Fingerprint Impersonation (JA3/JA4 compatible)
    - Proxy Rotation
    - Human Behavior Simulation (Jitter, Referer Spoofing)
    """

    def __init__(
        self,
        impersonate: str = None,
        proxies: List[str] = None,
        randomize_behavior: bool = True,
        **kwargs,
    ):
        """
        Args:
            impersonate (str): Browser to impersonate
            proxies (List[str]): List of proxy URLs (http/socks5)
            randomize_behavior (bool): Enable jitter and header randomization
        """
        # Pick random browser if not specified
        self.impersonate_target = impersonate or random.choice(BROWSER_IMPERSONATIONS)
        self.proxy_manager = ProxyManager(proxies)
        self.randomize_behavior = randomize_behavior
        self.current_proxy = self.proxy_manager.get_proxy()

        # Init parent with proxy if available
        super().__init__(
            impersonate=self.impersonate_target,
            proxies={"http": self.current_proxy, "https": self.current_proxy} if self.current_proxy else None,
            **kwargs,
        )

        self.headers = self._get_default_headers()
        logger.debug(f"StealthSession initialized: {self.impersonate_target} | Proxy: {bool(self.current_proxy)}")

    def _get_default_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            # Note: User-Agent is handled by curl_cffi impersonate, but we can override if needed
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
        }
        
        if self.randomize_behavior:
            headers["Referer"] = random.choice(REPUTABLE_REFERERS)
            
        return headers

    def rotate_identity(self):
        """Rotate browser fingerprint and proxy"""
        self.impersonate_target = random.choice(BROWSER_IMPERSONATIONS)
        self.current_proxy = self.proxy_manager.get_proxy()
        
        # Re-init curl interface properties
        # Note: curl_cffi session reuse with changing impersonate might be limited, 
        # normally we'd create a new session, but here we update what we can.
        if self.current_proxy:
            self.proxies = {"http": self.current_proxy, "https": self.current_proxy}

    def request(self, method: str, url: str, *args, **kwargs) -> Any:
        # Human Jitter (Anti-Bot)
        if self.randomize_behavior:
            sleep_time = random.uniform(0.5, 3.0)
            time.sleep(sleep_time)

        try:
            if "impersonate" not in kwargs:
                kwargs["impersonate"] = self.impersonate_target
                
            response = super().request(method, url, *args, **kwargs)

            # WAF/Block Detection Logic
            if response.status_code in [403, 406, 429, 503]:
                if any(x in response.text.lower() for x in ["cloudflare", "just a moment", "challenge"]):
                    logger.warning(f"Cloudflare Challenge Detected! ({response.status_code})")
                    self.proxy_manager.mark_bad(self.current_proxy)
                    self.rotate_identity() # Auto-rotate on block
                elif response.status_code == 429:
                    logger.warning("Rate Limited! Cooling down...")
                    time.sleep(5)

            return response

        except Exception as e:
            logger.error(f"Stealth Request Failed: {e}")
            self.proxy_manager.mark_bad(self.current_proxy)
            raise


# Async Version for high-concurrency scans
class AsyncStealthSession(AsyncSession):
    """Async version of StealthSession with similar capabilities"""

    def __init__(self, impersonate: str = None, proxies: List[str] = None, **kwargs):
        self.impersonate_target = impersonate or random.choice(BROWSER_IMPERSONATIONS)
        self.proxies_list = proxies or []
        super().__init__(impersonate=self.impersonate_target, **kwargs)

    async def request(self, method: str, url: str, *args, **kwargs) -> Any:
        # Simple jitter for async
        await asyncio.sleep(random.uniform(0.1, 1.5))
        return await super().request(method, url, *args, **kwargs)
