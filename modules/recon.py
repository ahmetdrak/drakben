# modules/recon.py
# DRAKBEN Recon Module - STATE-AWARE Advanced Passive Information Gathering
# REQUIRED: State control is enforced, tested surfaces are not re-scanned
# Enhanced: Logging, async consistency, retry mechanism

import asyncio
import hashlib
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

# Setup logger
logger = logging.getLogger(__name__)

# State integration
try:
    from core.state import AgentState

    STATE_AVAILABLE = True
except ImportError:
    STATE_AVAILABLE = False
    logger.warning("State module not available")

# Optional imports with fallback
try:
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.info("dnspython not installed - DNS lookups disabled")

try:
    import whois

    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.info("python-whois not installed - WHOIS lookups disabled")

# BeautifulSoup for HTML parsing
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("beautifulsoup4 not installed - HTML parsing limited")


class ReconError(Exception):
    """Custom exception for recon errors"""
    pass


class AsyncRetry:
    """Async retry decorator with exponential backoff"""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
    
    def __call__(self, func):
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(self.max_retries):
                try:
                    return await func(*args, **kwargs)
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    last_exception = e
                    if attempt < self.max_retries - 1:
                        delay = self.base_delay * (2 ** attempt)
                        logger.warning(f"Retry {attempt + 1}/{self.max_retries} after {delay}s: {e}")
                        await asyncio.sleep(delay)
            raise last_exception
        return wrapper


async def fetch_url(session: aiohttp.ClientSession, url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Fetch URL with proper error handling and logging.
    
    Args:
        session: aiohttp ClientSession
        url: URL to fetch
        timeout: Request timeout in seconds
        
    Returns:
        Dict with 'status', 'headers', 'text', 'error' keys
    """
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "text": await resp.text(),
                "error": None
            }
    except aiohttp.ClientError as e:
        logger.error(f"HTTP error fetching {url}: {e}")
        return {"status": 0, "headers": {}, "text": "", "error": str(e)}
    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching {url}")
        return {"status": 0, "headers": {}, "text": "", "error": "Timeout"}


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    return domain


async def passive_recon(target: str, state: Optional["AgentState"] = None) -> Dict[str, Any]:
    """
    STATE-AWARE passive recon with full async support.
    Refactored to reduce Cognitive Complexity.
    """
    logger.info(f"Starting passive recon for: {target}")

    # STATE CHECK
    if STATE_AVAILABLE and state is None:
        logger.warning("State tracking is recommended but not provided")

    # Check if target already scanned in this session
    if state and state.target == target and state.open_services:
        logger.info(f"Target {target} already scanned in this session, using cached data")
        return {
            "target": target,
            "cached": True,
            "cached_services": len(state.open_services),
        }

    result = _initialize_recon_result(target)

    # Ensure target has protocol
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"
        logger.debug(f"Added http:// prefix to target: {target}")

    try:
        connector = aiohttp.TCPConnector(ssl=False)  # Allow self-signed certs
        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. Main Page & HTML Analysis
            await _analyze_main_page(session, target, result)
            
            # 2. Additional HTTP Resources (Robots, Sitemap, Favicon)
            await _fetch_additional_resources(session, target, result)

        # 3. External Lookups (DNS, WHOIS)
        domain = extract_domain(target)
        if domain:
            await _perform_external_lookups(domain, result)
        
        # AI summary placeholder
        result["ai_summary"] = "AI analysis handled by Brain module"
        
        logger.info(f"Recon completed for {target}: {len(result['forms'])} forms, CMS: {result['cms']}")
        return result

    except Exception as e:
        logger.exception(f"Recon failed for {target}: {e}")
        result["error"] = str(e)
        return result

def _initialize_recon_result(target: str) -> Dict[str, Any]:
    return {
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
        "technologies": [],
        "notes": [],
        "error": None,
    }

async def _analyze_main_page(session: aiohttp.ClientSession, target: str, result: Dict[str, Any]):
    """Fetch and parse the main page content."""
    logger.debug(f"Fetching main page: {target}")
    main_response = await fetch_url(session, target)
    
    if main_response["error"]:
        result["error"] = main_response["error"]
        result["notes"].append(f"Main page fetch failed: {main_response['error']}")
        return

    result["headers"] = main_response["headers"]
    html = main_response["text"]
    
    if BS4_AVAILABLE and html:
        _parse_html_content(html, result)

def _parse_html_content(html: str, result: Dict[str, Any]):
    """Parse HTML content for metadata, forms, scripts, etc."""
    soup = BeautifulSoup(html, "html.parser")
    
    # Title and meta description
    if soup.title:
        result["title"] = soup.title.string.strip() if soup.title.string else None
        logger.debug(f"Found title: {result['title']}")
    
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.get("content"):
        result["description"] = meta_desc["content"].strip()
    
    # Forms
    for form in soup.find_all("form"):
        inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
        form_info = {"action": form.get("action"), "method": form.get("method", "GET"), "inputs": inputs}
        result["forms"].append(form_info)
    logger.debug(f"Found {len(result['forms'])} forms")
    
    # Scripts
    result["scripts"] = [script.get("src") for script in soup.find_all("script") if script.get("src")]
    
    # CMS & Tech Detection
    result["cms"] = detect_cms(html, result["headers"])
    if result["cms"]:
        logger.info(f"Detected CMS: {result['cms']}")
    
    result["technologies"] = detect_technologies(html, result["headers"])

async def _fetch_additional_resources(session: aiohttp.ClientSession, target: str, result: Dict[str, Any]):
    """Fetch robots.txt, sitemap.xml, and favicon."""
    base_url = target.rstrip("/")
    
    # Favicon - basic check (would need soup for correct link, but simplified here or passed from parse)
    # Re-parsing just for favicon link to keep simple or pass data? 
    # Let's keep it simple: Standard locations + what was found in HTML if we passed it.
    # To avoid complexity allow passing soup or just do robots/sitemap here.
    
    # Robots.txt
    robots_url = f"{base_url}/robots.txt"
    resp = await fetch_url(session, robots_url, timeout=5)
    if not resp["error"] and resp["status"] == 200:
        result["robots"] = resp["text"].splitlines()[:50]
        logger.debug("Found robots.txt")

    # Sitemap.xml
    sitemap_url = f"{base_url}/sitemap.xml"
    resp = await fetch_url(session, sitemap_url, timeout=5)
    if not resp["error"] and resp["status"] == 200:
        result["sitemap"] = resp["text"][:1000]
        logger.debug("Found sitemap.xml")

async def _perform_external_lookups(domain: str, result: Dict[str, Any]):
    """Perform DNS and WHOIS lookups."""
    # DNS Records
    if DNS_AVAILABLE:
        result["dns_records"] = await asyncio.get_event_loop().run_in_executor(
            None, get_dns_records, domain
        )
    else:
        result["dns_records"]["note"] = "DNS lookup not available"

    # WHOIS
    if WHOIS_AVAILABLE:
        result["whois"] = await asyncio.get_event_loop().run_in_executor(
            None, get_whois_info, domain
        )
    else:
        result["whois"]["note"] = "WHOIS lookup not available"


def detect_cms(html: str, headers: Dict[str, str]) -> Optional[str]:
    """
    Detect CMS from HTML content and headers.
    
    Args:
        html: HTML content
        headers: HTTP response headers
        
    Returns:
        CMS name or None
    """
    html_lower = html.lower()
    
    cms_signatures = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Joomla": ["joomla", "/components/com_", "/modules/mod_"],
        "Drupal": ["drupal", "sites/default/files", "sites/all"],
        "Magento": ["magento", "mage/cookies", "/skin/frontend/"],
        "Shopify": ["shopify", "cdn.shopify.com"],
        "Ghost": ["ghost", "ghost-admin"],
        "TYPO3": ["typo3", "typo3conf"],
        "PrestaShop": ["prestashop", "/modules/ps_"],
        "Wix": ["wix.com", "wixstatic.com"],
        "Squarespace": ["squarespace", "sqsp"],
    }
    
    for cms, signatures in cms_signatures.items():
        if any(sig in html_lower for sig in signatures):
            return cms
    
    # Check headers for CMS hints
    _ = headers.get("Server", "").lower()
    x_powered = headers.get("X-Powered-By", "").lower()
    
    if "wp" in x_powered or "wordpress" in x_powered:
        return "WordPress"
    if "drupal" in x_powered:
        return "Drupal"
    
    return None


def detect_technologies(html: str, headers: Dict[str, str]) -> List[str]:
    """
    Detect web technologies from HTML and headers.
    
    Args:
        html: HTML content
        headers: HTTP response headers
        
    Returns:
        List of detected technologies
    """
    technologies = []
    html_lower = html.lower()
    
    # JavaScript frameworks
    js_frameworks = {
        "React": ["react", "reactdom", "_reactroot"],
        "Vue.js": ["vue.js", "vue.min.js", "__vue__"],
        "Angular": ["ng-app", "ng-controller", "angular"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "Tailwind": ["tailwind"],
    }
    
    for tech, signatures in js_frameworks.items():
        if any(sig in html_lower for sig in signatures):
            technologies.append(tech)
    
    # Server technologies from headers
    server = headers.get("Server", "")
    if server:
        technologies.append(f"Server: {server}")
    
    x_powered = headers.get("X-Powered-By", "")
    if x_powered:
        technologies.append(f"Powered-By: {x_powered}")
    
    return technologies


def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Get DNS records for domain (sync function).
    
    Args:
        domain: Domain name
        
    Returns:
        Dict with DNS records
    """
    records = {}
    
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
    
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            records["error"] = "Domain does not exist"
            break
        except Exception as e:
            records[rtype] = []
            logger.debug(f"DNS {rtype} lookup failed for {domain}: {e}")
    
    return records


def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Get WHOIS information for domain (sync function).
    
    Args:
        domain: Domain name
        
    Returns:
        Dict with WHOIS info
    """
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "status": w.status if hasattr(w, 'status') else None,
        }
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return {"error": str(e)}


# Synchronous wrapper for compatibility
def passive_recon_sync(target: str, state: Optional["AgentState"] = None) -> Dict[str, Any]:
    """
    Synchronous wrapper for passive_recon.
    
    Args:
        target: Target URL
        state: AgentState instance
        
    Returns:
        Recon results
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(passive_recon(target, state))
