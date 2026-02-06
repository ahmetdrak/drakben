# modules/recon.py
# DRAKBEN Recon Module - STATE-AWARE Advanced Passive Information Gathering
# REQUIRED: State control is enforced, tested surfaces are not re-scanned
# Enhanced: Logging, async consistency, retry mechanism

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

import aiohttp

if TYPE_CHECKING:
    from core.agent.state import AgentState

# Setup logger
logger = logging.getLogger(__name__)

# State integration
try:
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
    """Custom exception for recon errors."""


class AsyncRetry:
    """Async retry decorator with exponential backoff."""

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0) -> None:
        self.max_retries = max_retries
        self.base_delay = base_delay

    def __call__(self, func) -> Any:

        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            for attempt in range(self.max_retries):
                try:
                    return await func(*args, **kwargs)
                except (TimeoutError, aiohttp.ClientError) as e:
                    last_exception = e
                    if attempt < self.max_retries - 1:
                        delay = self.base_delay * (2**attempt)
                        logger.warning(
                            f"Retry {attempt + 1}/{self.max_retries} after {delay}s: {e}",
                        )
                        await asyncio.sleep(delay)
            raise last_exception

        return wrapper


async def fetch_url(session: aiohttp.ClientSession, url: str) -> dict[str, Any]:
    """Fetch URL with proper error handling and logging.

    Args:
        session: aiohttp ClientSession
        url: URL to fetch

    Returns:
        Dict with 'status', 'headers', 'text', 'error' keys

    """
    timeout_seconds = 10  # Fixed timeout value
    try:
        async with asyncio.timeout(timeout_seconds):
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
            ) as resp:
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "text": await resp.text(),
                    "error": None,
                }
    except TimeoutError:
        logger.exception("Timeout fetching %s", url)
        return {"status": 0, "headers": {}, "text": "", "error": "Timeout"}
    except aiohttp.ClientError as e:
        logger.exception("HTTP error fetching %s: %s", url, e)
        return {"status": 0, "headers": {}, "text": "", "error": str(e)}


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain


async def passive_recon(
    target: str,
    state: Optional["AgentState"] = None,
) -> dict[str, Any]:
    """STATE-AWARE passive recon with full async support.
    Refactored to reduce Cognitive Complexity.
    """
    logger.info("Starting passive recon for: %s", target)

    # STATE CHECK
    if STATE_AVAILABLE and state is None:
        logger.warning("State tracking is recommended but not provided")

    # Check if target already scanned in this session
    if state and state.target == target and state.open_services:
        logger.info(
            f"Target {target} already scanned in this session, using cached data",
        )
        return {
            "target": target,
            "cached": True,
            "cached_services": len(state.open_services),
        }

    result = _initialize_recon_result(target)

    # Ensure target has protocol
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
        logger.debug("Added http:// prefix to target: %s", target)

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

        logger.info(
            f"Recon completed for {target}: {len(result['forms'])} forms, CMS: {result['cms']}",
        )
        return result

    except Exception as e:
        logger.exception("Recon failed for %s: %s", target, e)
        result["error"] = str(e)
        return result


def _initialize_recon_result(target: str) -> dict[str, Any]:
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


async def _analyze_main_page(
    session: aiohttp.ClientSession,
    target: str,
    result: dict[str, Any],
) -> None:
    """Fetch and parse the main page content."""
    logger.debug("Fetching main page: %s", target)
    main_response = await fetch_url(session, target)

    if main_response["error"]:
        result["error"] = main_response["error"]
        result["notes"].append(f"Main page fetch failed: {main_response['error']}")
        return

    result["headers"] = main_response["headers"]
    html = main_response["text"]

    if BS4_AVAILABLE and html:
        _parse_html_content(html, result)


def _parse_html_content(html: str, result: dict[str, Any]) -> None:
    """Parse HTML content for metadata, forms, scripts, etc."""
    soup = BeautifulSoup(html, "html.parser")

    # Title and meta description
    if soup.title:
        result["title"] = soup.title.string.strip() if soup.title.string else None
        logger.debug("Found title: %s", result["title"])

    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc:
        content = meta_desc.get("content")
        if isinstance(content, str):
            result["description"] = content.strip()

    # Forms
    for form in soup.find_all("form"):
        inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
        form_info = {
            "action": form.get("action"),
            "method": form.get("method", "GET"),
            "inputs": inputs,
        }
        result["forms"].append(form_info)
    logger.debug("Found %s forms", len(result["forms"]))

    # Scripts
    result["scripts"] = [
        script.get("src") for script in soup.find_all("script") if script.get("src")
    ]

    # CMS & Tech Detection
    result["cms"] = detect_cms(html, result["headers"])
    if result["cms"]:
        logger.info("Detected CMS: %s", result["cms"])

    result["technologies"] = detect_technologies(html, result["headers"])


async def _fetch_additional_resources(
    session: aiohttp.ClientSession,
    target: str,
    result: dict[str, Any],
) -> None:
    """Fetch robots.txt, sitemap.xml, and favicon."""
    base_url = target.rstrip("/")

    # Favicon - basic check (would need soup for correct link, but simplified here or passed from parse)
    # Re-parsing just for favicon link to keep simple or pass data?
    # Let's keep it simple: Standard locations + what was found in HTML if we passed it.
    # To avoid complexity allow passing soup or just do robots/sitemap here.

    # Robots.txt
    robots_url = f"{base_url}/robots.txt"
    resp = await fetch_url(session, robots_url)
    if not resp["error"] and resp["status"] == 200:
        result["robots"] = resp["text"].splitlines()[:50]
        logger.debug("Found robots.txt")

    # Sitemap.xml
    sitemap_url = f"{base_url}/sitemap.xml"
    resp = await fetch_url(session, sitemap_url)
    if not resp["error"] and resp["status"] == 200:
        result["sitemap"] = resp["text"][:1000]
        logger.debug("Found sitemap.xml")


async def _perform_external_lookups(domain: str, result: dict[str, Any]) -> None:
    """Perform DNS and WHOIS lookups."""
    # DNS Records
    if DNS_AVAILABLE:
        result["dns_records"] = await asyncio.get_event_loop().run_in_executor(
            None,
            get_dns_records,
            domain,
        )
    else:
        result["dns_records"]["note"] = "DNS lookup not available"

    # WHOIS
    if WHOIS_AVAILABLE:
        result["whois"] = await asyncio.get_event_loop().run_in_executor(
            None,
            get_whois_info,
            domain,
        )
    else:
        result["whois"]["note"] = "WHOIS lookup not available"


def detect_cms(html: str, headers: dict[str, str]) -> str | None:
    """Detect CMS from HTML content and headers.

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


def detect_technologies(html: str, headers: dict[str, str]) -> list[str]:
    """Detect web technologies from HTML and headers.

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


def get_dns_records(domain: str) -> dict[str, Any]:
    """Get DNS records for domain (sync function).

    Args:
        domain: Domain name

    Returns:
        Dict with DNS records

    """
    records: dict[str, Any] = {}

    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

    for rtype in record_types:
        try:
            # Paranoid: Use dedicated resolver to avoid local DNS/ISP logging
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["1.1.1.1", "8.8.8.8", "1.0.0.1"]
            resolver.timeout = 5.0
            resolver.lifetime = 10.0

            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            records["error"] = "Domain does not exist"
            break
        except Exception as e:
            records[rtype] = []
            logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, e)

    return records


def get_whois_info(domain: str) -> dict[str, Any]:
    """Get WHOIS information for domain (sync function).

    Args:
        domain: Domain name

    Returns:
        Dict with WHOIS info

    """
    try:
        w = whois.whois(domain)
        ns = w.name_servers
        if isinstance(ns, str):
            ns = [ns]

        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": ns if ns else [],
            "status": getattr(w, "status", None),
        }
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        return {"error": str(e)}


# Synchronous wrapper for compatibility
def passive_recon_sync(
    target: str,
    state: Optional["AgentState"] = None,
) -> dict[str, Any]:
    """Synchronous wrapper for passive_recon.

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


# =============================================================================
# Active Port Scanner (native — no nmap dependency)
# =============================================================================

async def scan_ports(
    host: str,
    ports: list[int] | None = None,
    connect_timeout: float = 1.5,
    concurrency: int = 200,
    state: Optional["AgentState"] = None,
) -> dict[str, Any]:
    """Native async TCP port scanner.

    Performs a TCP connect scan without relying on external tools like nmap.
    Uses a semaphore-controlled concurrency pool for speed.

    Args:
        host: Target hostname or IP address.
        ports: Ports to scan.  Defaults to common 1000 ports.
        connect_timeout: Per-port connection timeout in seconds.
        concurrency: Maximum simultaneous connection attempts.
        state: Optional AgentState for caching results.

    Returns:
        Dict with ``open_ports``, ``closed_count``, ``host``, ``duration``.
    """
    import socket
    import time as _time

    if ports is None:
        ports = _get_common_ports()

    # Resolve hostname once
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        logger.error("Cannot resolve host: %s", host)
        return {"host": host, "error": "DNS resolution failed", "open_ports": []}

    logger.info("Starting native port scan on %s (%s) — %d ports", host, ip, len(ports))
    start = _time.monotonic()

    sem = asyncio.Semaphore(concurrency)
    open_ports: list[dict[str, Any]] = []

    async def _probe(port: int) -> None:
        async with sem:
            try:
                async with asyncio.timeout(connect_timeout):
                    _, writer = await asyncio.open_connection(ip, port)
                writer.close()
                await writer.wait_closed()
                service = _guess_service(port)
                open_ports.append({"port": port, "state": "open", "service": service})
                logger.debug("Port %d open (%s)", port, service)
            except OSError:
                pass

    await asyncio.gather(*[_probe(p) for p in ports])
    open_ports.sort(key=lambda x: x["port"])

    duration = round(_time.monotonic() - start, 2)
    logger.info(
        "Port scan complete: %d open / %d scanned in %ss",
        len(open_ports), len(ports), duration,
    )

    # Update state if provided
    if state and STATE_AVAILABLE:
        for entry in open_ports:
            state.open_services[entry["port"]] = entry["service"]

    return {
        "host": host,
        "ip": ip,
        "open_ports": open_ports,
        "closed_count": len(ports) - len(open_ports),
        "scanned_count": len(ports),
        "duration": duration,
    }


def scan_ports_sync(
    host: str,
    ports: list[int] | None = None,
    connect_timeout: float = 1.5,
    concurrency: int = 200,
    state: Optional["AgentState"] = None,
) -> dict[str, Any]:
    """Synchronous wrapper for :func:`scan_ports`."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(
        scan_ports(host, ports, connect_timeout, concurrency, state),
    )


def _guess_service(port: int) -> str:
    """Map well-known ports to service names."""
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 135: "msrpc",
        139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
        445: "smb", 465: "smtps", 514: "syslog", 587: "submission",
        636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
        1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
        6379: "redis", 6443: "kubernetes", 8080: "http-proxy",
        8443: "https-alt", 8888: "http-alt", 9090: "prometheus",
        9200: "elasticsearch", 27017: "mongodb",
    }
    return services.get(port, "unknown")


def _get_common_ports() -> list[int]:
    """Return top 1000 commonly scanned TCP ports."""
    return [
        1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33,
        37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99,
        100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161,
        163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306,
        311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458,
        464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
        548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
        667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
        777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
        903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002,
        1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027,
        1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038,
        1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
        1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060,
        1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071,
        1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082,
        1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093,
        1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106,
        1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122,
        1131, 1138, 1148, 1152, 1169, 1234, 1241, 1352, 1433, 1434, 1443,
        1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580,
        1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718,
        1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812,
        1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971,
        1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
        2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033,
        2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048,
        2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119,
        2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196,
        2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383,
        2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602,
        2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725,
        2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998,
        3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031,
        3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269,
        3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367,
        3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527,
        3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800,
        3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880,
        3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000,
        4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129,
        4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550,
        4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004,
        5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100,
        5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269,
        5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544,
        5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730,
        5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862,
        5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915,
        5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988,
        5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007,
        6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346,
        6389, 6443, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646,
        6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792,
        6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025,
        7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512,
        7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937,
        7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021,
        8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086,
        8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193,
        8194, 8200, 8222, 8243, 8254, 8290, 8291, 8292, 8300, 8333, 8383,
        8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800,
        8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011,
        9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102,
        9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500,
        9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877,
        9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000,
        10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
        10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626,
        10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265,
        13456, 13722, 14000, 14238, 14441, 14442, 15000, 15002, 15003,
        15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080,
        16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101,
        19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031,
        20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734,
        25735, 26214, 27000, 27017, 27352, 27353, 27355, 27356, 27715,
        28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770,
        32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779,
        32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571,
        34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
        44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155,
        49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167,
        49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006,
        50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822,
        52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737,
        56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078,
        63331, 64623, 64680, 65000, 65129, 65389,
    ]
