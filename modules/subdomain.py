# modules/subdomain.py
# DRAKBEN Subdomain Enumeration Module
# Comprehensive subdomain discovery using multiple sources

import asyncio
import logging
import shutil
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import aiohttp

if TYPE_CHECKING:
    from core.state import AgentState

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    """Subdomain enumeration result"""

    subdomain: str
    source: str
    resolved: bool = False
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "source": self.source,
            "resolved": self.resolved,
            "ip_addresses": self.ip_addresses,
            "cname": self.cname,
        }


class SubdomainEnumerator:
    """
    Subdomain Enumerator using multiple sources.

    Sources:
    - crt.sh (Certificate Transparency)
    - VirusTotal (requires API key)
    - Subfinder (if installed)
    - Amass (if installed)
    - DNS brute force
    - Web archive
    """

    # Common subdomain wordlist
    COMMON_SUBDOMAINS = [
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "ns2",
        "webdisk",
        "pop3",
        "cpanel",
        "whm",
        "autodiscover",
        "autoconfig",
        "m",
        "imap",
        "test",
        "ns",
        "blog",
        "dev",
        "www2",
        "admin",
        "forum",
        "news",
        "vpn",
        "ns3",
        "mail2",
        "new",
        "mysql",
        "old",
        "lists",
        "support",
        "mobile",
        "mx",
        "static",
        "docs",
        "beta",
        "shop",
        "sql",
        "secure",
        "demo",
        "cp",
        "calendar",
        "wiki",
        "web",
        "media",
        "email",
        "images",
        "img",
        "www1",
        "intranet",
        "portal",
        "video",
        "sip",
        "dns2",
        "api",
        "cdn",
        "stats",
        "dns1",
        "ns4",
        "www3",
        "dns",
        "search",
        "staging",
        "server",
        "mx1",
        "chat",
        "wap",
        "my",
        "svn",
        "mail1",
        "sites",
        "proxy",
        "ads",
        "host",
        "crm",
        "cms",
        "backup",
        "mx2",
        "lyncdiscover",
        "info",
        "apps",
        "download",
        "remote",
        "db",
        "forums",
        "store",
        "relay",
        "files",
        "newsletter",
        "app",
        "live",
        "owa",
        "en",
        "start",
        "sms",
        "office",
        "exchange",
        "ipv4",
        "git",
        "stage",
        "uat",
        "prod",
        "production",
        "sandbox",
        "jenkins",
        "gitlab",
        "jira",
        "confluence",
        "nagios",
        "zabbix",
        "grafana",
        "prometheus",
        "kibana",
        "elastic",
    ]

    def __init__(
        self, virustotal_api_key: Optional[str] = None, use_external_tools: bool = True
    ):
        """
        Initialize Subdomain Enumerator.

        Args:
            virustotal_api_key: Optional VirusTotal API key
            use_external_tools: Whether to use external tools (subfinder, amass)
        """
        self.vt_api_key = virustotal_api_key
        self.use_external_tools = use_external_tools

        # Check available tools
        self.subfinder_available = shutil.which("subfinder") is not None
        self.amass_available = shutil.which("amass") is not None

        logger.info(
            f"Subdomain Enumerator initialized (subfinder: {self.subfinder_available}, amass: {self.amass_available})"
        )

    async def enumerate(
        self, domain: str, use_bruteforce: bool = False, resolve: bool = True
    ) -> List[SubdomainResult]:
        """
        Enumerate subdomains for a domain.

        Args:
            domain: Target domain
            use_bruteforce: Whether to use DNS brute force
            resolve: Whether to resolve subdomains

        Returns:
            List of SubdomainResult objects
        """
        domain = self._clean_domain(domain)
        logger.info(f"Starting subdomain enumeration for: {domain}")

        tasks = self._build_enumeration_tasks(domain, use_bruteforce)
        source_results = await self._gather_enumeration_results(tasks)
        results = await self._process_enumeration_results(source_results, resolve)

        return sorted(results, key=lambda x: x.subdomain)

    def _build_enumeration_tasks(self, domain: str, use_bruteforce: bool) -> List:
        """Build list of enumeration tasks"""
        tasks = [
            self._crtsh_enum(domain),
            self._web_archive_enum(domain),
        ]

        if self.vt_api_key:
            tasks.append(self._virustotal_enum(domain))

        if self.use_external_tools:
            if self.subfinder_available:
                tasks.append(self._subfinder_enum(domain))
            if self.amass_available:
                tasks.append(self._amass_enum(domain))

        if use_bruteforce:
            tasks.append(self._bruteforce_enum(domain))

        return tasks

    async def _gather_enumeration_results(self, tasks: List) -> List:
        """Gather results from all enumeration tasks"""
        timeout_seconds = 300  # Fixed timeout value
        try:
            async with asyncio.timeout(timeout_seconds):
                return await asyncio.gather(*tasks, return_exceptions=True)
        except TimeoutError:
            logger.warning("Subdomain enumeration timed out")
            return []

    async def _process_enumeration_results(
        self, source_results: List, resolve: bool
    ) -> List[SubdomainResult]:
        """Process and combine enumeration results"""
        subdomains: Set[str] = set()
        results: List[SubdomainResult] = []

        for result in source_results:
            if isinstance(result, list):
                results.extend(self._extract_unique_subdomains(result, subdomains))
            elif isinstance(result, Exception):
                logger.error(f"Source error: {result}")

        logger.info(f"Found {len(results)} unique subdomains")

        if resolve:
            results = await self._resolve_subdomains(results)
        return results

    def _extract_unique_subdomains(
        self, result_list: List[SubdomainResult], subdomains: Set[str]
    ) -> List[SubdomainResult]:
        """Extract unique subdomains from result list"""
        unique_results = []
        for r in result_list:
            if r.subdomain not in subdomains:
                subdomains.add(r.subdomain)
                unique_results.append(r)
        return unique_results

    def _clean_domain(self, domain: str) -> str:
        """Clean domain string"""
        domain = self._remove_protocol(domain)
        domain = self._remove_port(domain)
        domain = self._remove_www_prefix(domain)
        return domain.lower().strip()

    def _remove_protocol(self, domain: str) -> str:
        """Remove protocol from domain"""
        if "://" in domain:
            return urlparse(domain).netloc
        return domain

    def _remove_port(self, domain: str) -> str:
        """Remove port from domain"""
        if ":" in domain:
            return domain.split(":")[0]
        return domain

    def _remove_www_prefix(self, domain: str) -> str:
        """Remove www prefix from domain"""
        if domain.startswith("www."):
            return domain[4:]
        return domain

    async def _crtsh_enum(self, domain: str) -> List[SubdomainResult]:
        """Enumerate using crt.sh (Certificate Transparency)"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = self._parse_crtsh_data(data, domain)
                        logger.info(f"crt.sh found {len(results)} subdomains")
                        return results
            return []
        except Exception as e:
            logger.error(f"crt.sh error: {e}")
            return []

    def _parse_crtsh_data(self, data: List[Dict], domain: str) -> List[SubdomainResult]:
        """Parse crt.sh JSON data"""
        results = []
        seen = set()
        for entry in data:
            name = entry.get("name_value", "")
            subdomains = self._extract_subdomains_from_name(name, domain)
            for sub in subdomains:
                if sub not in seen:
                    seen.add(sub)
                    results.append(SubdomainResult(subdomain=sub, source="crt.sh"))
        return results

    def _extract_subdomains_from_name(self, name: str, domain: str) -> List[str]:
        """Extract subdomains from name string"""
        subdomains = []
        for sub in name.split("\n"):
            sub = sub.strip().lower()
            if sub.startswith("*."):
                sub = sub[2:]
            if sub.endswith(domain):
                subdomains.append(sub)
        return subdomains

    async def _virustotal_enum(self, domain: str) -> List[SubdomainResult]:
        """Enumerate using VirusTotal API"""
        if not self.vt_api_key:
            return []

        try:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"apikey": self.vt_api_key, "domain": domain}

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, params=params, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = self._parse_virustotal_data(data)
                        logger.info(f"VirusTotal found {len(results)} subdomains")
                        return results
            return []
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
            return []

    def _parse_virustotal_data(self, data: Dict) -> List[SubdomainResult]:
        """Parse VirusTotal API response"""
        results = []
        for sub in data.get("subdomains", []):
            results.append(SubdomainResult(subdomain=sub, source="virustotal"))
        return results

    async def _web_archive_enum(self, domain: str) -> List[SubdomainResult]:
        """Enumerate using Web Archive"""
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = self._parse_web_archive_data(data, domain)
                        logger.info(f"Web Archive found {len(results)} subdomains")
                        return results
            return []
        except Exception as e:
            logger.error(f"Web Archive error: {e}")
            return []

    def _parse_web_archive_data(
        self, data: List[List], domain: str
    ) -> List[SubdomainResult]:
        """Parse Web Archive JSON data"""
        results = []
        seen = set()
        for entry in data[1:]:  # Skip header
            host = self._extract_host_from_entry(entry, domain)
            if host and host not in seen:
                seen.add(host)
                results.append(SubdomainResult(subdomain=host, source="web_archive"))
        return results

    def _extract_host_from_entry(self, entry: List, domain: str) -> Optional[str]:
        """Extract host from web archive entry"""
        try:
            parsed = urlparse(entry[0])
            host = parsed.netloc.lower()
            if host.endswith(domain):
                return host
        except (ValueError, IndexError, AttributeError) as e:
            logger.debug(f"Error parsing web archive entry: {e}")
        return None

    async def _subfinder_enum(self, domain: str) -> List[SubdomainResult]:
        """Enumerate using subfinder"""
        if not self.subfinder_available:
            return []

        try:
            stdout = await self._run_subfinder_process(domain)
            results = self._parse_subfinder_output(stdout, domain)
            logger.info(f"Subfinder found {len(results)} subdomains")
            return results
        except asyncio.TimeoutError:
            logger.warning("Subfinder timed out")
            return []
        except Exception as e:
            logger.error(f"Subfinder error: {e}")
            return []

    async def _run_subfinder_process(self, domain: str) -> str:
        """Run subfinder process"""
        process = await asyncio.create_subprocess_exec(
            "subfinder",
            "-d",
            domain,
            "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=120)
        return stdout.decode()

    def _parse_subfinder_output(
        self, stdout: str, domain: str
    ) -> List[SubdomainResult]:
        """Parse subfinder output"""
        results = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line and line.endswith(domain):
                results.append(SubdomainResult(subdomain=line, source="subfinder"))
        return results

    async def _amass_enum(self, domain: str) -> List[SubdomainResult]:
        """Enumerate using amass"""
        results: List[SubdomainResult] = []
        timeout_seconds = 120  # Fixed timeout value

        if not self.amass_available:
            return results

        try:
            process = await asyncio.create_subprocess_exec(
                "amass",
                "enum",
                "-passive",
                "-d",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async with asyncio.timeout(timeout_seconds):
                stdout, _ = await process.communicate()

            for line in stdout.decode().strip().split("\n"):
                line = line.strip()
                if line and line.endswith(domain):
                    results.append(SubdomainResult(subdomain=line, source="amass"))

            logger.info(f"Amass found {len(results)} subdomains")

        except TimeoutError:
            logger.warning("Amass timed out")
        except Exception as e:
            logger.error(f"Amass error: {e}")

        return results

    async def _bruteforce_enum(self, domain: str) -> List[SubdomainResult]:
        """DNS brute force enumeration"""
        resolver = self._setup_dns_resolver()
        if not resolver:
            return []

        logger.info(f"Starting DNS brute force for {domain}")
        results = await self._process_bruteforce_batches(domain, resolver)
        logger.info(f"Brute force found {len(results)} subdomains")
        return results

    def _setup_dns_resolver(self):
        """Setup DNS resolver"""
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            return resolver
        except ImportError:
            logger.warning("dnspython not available for brute force")
            return None

    async def _process_bruteforce_batches(
        self, domain: str, resolver
    ) -> List[SubdomainResult]:
        """Process bruteforce in batches"""
        results = []
        batch_size = 50

        for i in range(0, len(self.COMMON_SUBDOMAINS), batch_size):
            batch = self.COMMON_SUBDOMAINS[i : i + batch_size]
            batch_results = await self._check_batch_subdomains(batch, domain, resolver)
            results.extend(batch_results)

        return results

    async def _check_batch_subdomains(
        self, batch: List[str], domain: str, resolver
    ) -> List[SubdomainResult]:
        """Check a batch of subdomains"""
        tasks = [self._check_single_subdomain(sub, domain, resolver) for sub in batch]
        batch_results = await asyncio.gather(*tasks)
        return [r for r in batch_results if r]

    async def _check_single_subdomain(
        self, sub: str, domain: str, resolver
    ) -> Optional[SubdomainResult]:
        """Check a single subdomain"""
        fqdn = f"{sub}.{domain}"
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, resolver.resolve, fqdn, "A")
            return SubdomainResult(subdomain=fqdn, source="bruteforce", resolved=True)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            logger.debug(f"Error in crt.sh query: {e}")
            return None

    async def _resolve_subdomains(
        self, results: List[SubdomainResult]
    ) -> List[SubdomainResult]:
        """Resolve subdomains to IP addresses"""
        resolver = self._setup_resolver()
        if not resolver:
            return results

        resolved_results = await self._resolve_in_batches(results, resolver)
        resolved_count = sum(1 for r in resolved_results if r.resolved)
        logger.info(f"Resolved {resolved_count}/{len(results)} subdomains")
        return resolved_results

    def _setup_resolver(self):
        """Setup DNS resolver"""
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            return resolver
        except ImportError:
            return None

    async def _resolve_in_batches(
        self, results: List[SubdomainResult], resolver
    ) -> List[SubdomainResult]:
        """Resolve subdomains in batches"""
        batch_size = 25
        resolved_results = []

        for i in range(0, len(results), batch_size):
            batch = results[i : i + batch_size]
            tasks = [self._resolve_single_subdomain(r, resolver) for r in batch]
            batch_results = await asyncio.gather(*tasks)
            resolved_results.extend(batch_results)

        return resolved_results

    async def _resolve_single_subdomain(
        self, result: SubdomainResult, resolver
    ) -> SubdomainResult:
        """Resolve a single subdomain"""
        if result.resolved:
            return result

        await self._resolve_a_record(result, resolver)
        await self._resolve_cname_record(result, resolver)
        return result

    async def _resolve_a_record(self, result: SubdomainResult, resolver) -> None:
        """Resolve A record for subdomain"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, resolver.resolve, result.subdomain, "A"
            )
            result.resolved = True
            result.ip_addresses = [str(r) for r in answers]
        except (OSError, ValueError) as e:
            logger.debug(f"DNS resolution error: {e}")
            result.resolved = False

    async def _resolve_cname_record(self, result: SubdomainResult, resolver) -> None:
        """Resolve CNAME record for subdomain"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None, resolver.resolve, result.subdomain, "CNAME"
            )
            result.cname = str(answers[0])
        except (OSError, IndexError) as e:
            logger.debug(f"CNAME lookup error: {e}")


async def enumerate_subdomains_for_state(
    state: "AgentState",
    enumerator: Optional[SubdomainEnumerator] = None,
    use_bruteforce: bool = False,
) -> List[SubdomainResult]:
    """
    Enumerate subdomains for state target.

    Args:
        state: AgentState instance
        enumerator: Optional SubdomainEnumerator instance
        use_bruteforce: Whether to use brute force

    Returns:
        List of SubdomainResult objects
    """
    if not state.target:
        logger.warning("No target set in state")
        return []

    enumerator = enumerator or SubdomainEnumerator()

    results = await enumerator.enumerate(
        domain=state.target, use_bruteforce=use_bruteforce, resolve=True
    )

    return results
