# modules/subdomain.py
# DRAKBEN Subdomain Enumeration Module
# Comprehensive subdomain discovery using multiple sources

import asyncio
import logging
import shutil
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    """Subdomain enumeration result."""

    subdomain: str
    source: str
    resolved: bool = False
    ip_addresses: list[str] = field(default_factory=list)
    cname: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "source": self.source,
            "resolved": self.resolved,
            "ip_addresses": self.ip_addresses,
            "cname": self.cname,
        }


class SubdomainEnumerator:
    """Subdomain Enumerator using multiple sources.

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
        self,
        virustotal_api_key: str | None = None,
        use_external_tools: bool = True,
    ) -> None:
        """Initialize Subdomain Enumerator.

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
            f"Subdomain Enumerator initialized (subfinder: {self.subfinder_available}, amass: {self.amass_available})",
        )

    async def enumerate(
        self,
        domain: str,
        use_bruteforce: bool = False,
        resolve: bool = True,
    ) -> list[SubdomainResult]:
        """Enumerate subdomains for a domain.

        Args:
            domain: Target domain
            use_bruteforce: Whether to use DNS brute force
            resolve: Whether to resolve subdomains

        Returns:
            List of SubdomainResult objects

        """
        domain = self._clean_domain(domain)
        logger.info("Starting subdomain enumeration for: %s", domain)

        tasks = self._build_enumeration_tasks(domain, use_bruteforce)
        source_results = await self._gather_enumeration_results(tasks)
        results = await self._process_enumeration_results(source_results, resolve)

        return sorted(results, key=lambda x: x.subdomain)

    def _build_enumeration_tasks(self, domain: str, use_bruteforce: bool) -> list:
        """Build list of enumeration tasks."""
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

    async def _gather_enumeration_results(self, tasks: list) -> list:
        """Gather results from all enumeration tasks."""
        timeout_seconds = 300  # Fixed timeout value
        try:
            async with asyncio.timeout(timeout_seconds):
                return await asyncio.gather(*tasks, return_exceptions=True)
        except TimeoutError:
            logger.warning("Subdomain enumeration timed out")
            return []

    async def _process_enumeration_results(
        self,
        source_results: list,
        resolve: bool,
    ) -> list[SubdomainResult]:
        """Process and combine enumeration results."""
        subdomains: set[str] = set()
        results: list[SubdomainResult] = []

        for result in source_results:
            if isinstance(result, list):
                results.extend(self._extract_unique_subdomains(result, subdomains))
            elif isinstance(result, Exception):
                logger.error("Source error: %s", result)

        logger.info("Found %s unique subdomains", len(results))

        if resolve:
            results = await self._resolve_subdomains(results)
        return results

    def _extract_unique_subdomains(
        self,
        result_list: list[SubdomainResult],
        subdomains: set[str],
    ) -> list[SubdomainResult]:
        """Extract unique subdomains from result list."""
        unique_results = []
        for r in result_list:
            if r.subdomain not in subdomains:
                subdomains.add(r.subdomain)
                unique_results.append(r)
        return unique_results

    def _clean_domain(self, domain: str) -> str:
        """Clean domain string."""
        domain = self._remove_protocol(domain)
        domain = self._remove_port(domain)
        domain = self._remove_www_prefix(domain)
        return domain.lower().strip()

    def _remove_protocol(self, domain: str) -> str:
        """Remove protocol from domain."""
        if "://" in domain:
            return urlparse(domain).netloc
        return domain

    def _remove_port(self, domain: str) -> str:
        """Remove port from domain."""
        if ":" in domain:
            return domain.split(":")[0]
        return domain

    def _remove_www_prefix(self, domain: str) -> str:
        """Remove www prefix from domain."""
        if domain.startswith("www."):
            return domain[4:]
        return domain

    async def _fetch_json_with_retry(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_retries: int = 3,
        base_delay: float = 1.0,
    ) -> Any:
        """Fetch JSON from *url* with exponential-backoff retry.

        Args:
            url: The URL to fetch.
            headers: Optional HTTP headers.
            max_retries: Maximum number of attempts.
            base_delay: Initial delay between retries in seconds.

        Returns:
            Parsed JSON data, or ``None`` on persistent failure.
        """
        client_timeout = aiohttp.ClientTimeout(total=30)
        for attempt in range(max_retries):
            try:
                async with (
                    aiohttp.ClientSession(timeout=client_timeout) as session,
                    session.get(url, headers=headers) as resp,
                ):
                    if resp.status == 200:
                        return await resp.json()
                    logger.warning(
                        "%s returned HTTP %d (attempt %d/%d)",
                        url,
                        resp.status,
                        attempt + 1,
                        max_retries,
                    )
            except (TimeoutError, aiohttp.ClientError) as exc:
                logger.warning(
                    "%s failed (attempt %d/%d): %s",
                    url,
                    attempt + 1,
                    max_retries,
                    exc,
                )
            if attempt < max_retries - 1:
                await asyncio.sleep(base_delay * (2**attempt))
        return None

    async def _crtsh_enum(self, domain: str) -> list[SubdomainResult]:
        """Enumerate using crt.sh (Certificate Transparency)."""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            data = await self._fetch_json_with_retry(url)
            if data is not None:
                results = self._parse_crtsh_data(data, domain)
                logger.info("crt.sh found %s subdomains", len(results))
                return results
            return []
        except Exception as e:
            logger.exception("crt.sh error: %s", e)
            return []

    def _parse_crtsh_data(self, data: list[dict], domain: str) -> list[SubdomainResult]:
        """Parse crt.sh JSON data."""
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

    def _extract_subdomains_from_name(self, name: str, domain: str) -> list[str]:
        """Extract subdomains from name string."""
        subdomains = []
        for sub in name.split("\n"):
            sub = sub.strip().lower()
            sub = sub.removeprefix("*.")
            if sub.endswith(domain):
                subdomains.append(sub)
        return subdomains

    async def _virustotal_enum(self, domain: str) -> list[SubdomainResult]:
        """Enumerate using VirusTotal API."""
        if not self.vt_api_key:
            return []

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": self.vt_api_key}
            data = await self._fetch_json_with_retry(url, headers=headers)
            if data is not None:
                results = self._parse_virustotal_data(data)
                logger.info("VirusTotal found %s subdomains", len(results))
                return results
            return []
        except Exception as e:
            logger.exception("VirusTotal error: %s", e)
            return []

    def _parse_virustotal_data(self, data: dict) -> list[SubdomainResult]:
        """Parse VirusTotal API v3 response."""
        results = []
        for entry in data.get("data", []):
            sub_id = entry.get("id", "")
            if sub_id:
                results.append(SubdomainResult(subdomain=sub_id, source="virustotal"))
        # Fallback for v2-style response
        for sub in data.get("subdomains", []):
            results.append(SubdomainResult(subdomain=sub, source="virustotal"))
        return results

    async def _web_archive_enum(self, domain: str) -> list[SubdomainResult]:
        """Enumerate using Web Archive."""
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            data = await self._fetch_json_with_retry(url)
            if data is not None:
                results = self._parse_web_archive_data(data, domain)
                logger.info("Web Archive found %s subdomains", len(results))
                return results
            return []
        except Exception as e:
            logger.exception("Web Archive error: %s", e)
            return []

    def _parse_web_archive_data(
        self,
        data: list[list],
        domain: str,
    ) -> list[SubdomainResult]:
        """Parse Web Archive JSON data."""
        results = []
        seen = set()
        # Skip header row if present; guard against empty data
        rows = data[1:] if len(data) > 1 else data
        for entry in rows:
            host = self._extract_host_from_entry(entry, domain)
            if host and host not in seen:
                seen.add(host)
                results.append(SubdomainResult(subdomain=host, source="web_archive"))
        return results

    def _extract_host_from_entry(self, entry: list, domain: str) -> str | None:
        """Extract host from web archive entry."""
        try:
            parsed = urlparse(entry[0])
            host = parsed.netloc.lower()
            if host.endswith(domain):
                return host
        except (ValueError, IndexError, AttributeError) as e:
            logger.debug("Error parsing web archive entry: %s", e)
        return None

    async def _subfinder_enum(self, domain: str) -> list[SubdomainResult]:
        """Enumerate using subfinder."""
        if not self.subfinder_available:
            return []

        try:
            stdout = await self._run_subfinder_process(domain)
            results = self._parse_subfinder_output(stdout, domain)
            logger.info("Subfinder found %s subdomains", len(results))
            return results
        except TimeoutError:
            logger.warning("Subfinder timed out")
            return []
        except Exception as e:
            logger.exception("Subfinder error: %s", e)
            return []

    async def _run_subfinder_process(self, domain: str) -> str:
        """Run subfinder process."""
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
        self,
        stdout: str,
        domain: str,
    ) -> list[SubdomainResult]:
        """Parse subfinder output."""
        results = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line and line.endswith(domain):
                results.append(SubdomainResult(subdomain=line, source="subfinder"))
        return results

    async def _amass_enum(self, domain: str) -> list[SubdomainResult]:
        """Enumerate using amass."""
        results: list[SubdomainResult] = []
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

            logger.info("Amass found %s subdomains", len(results))

        except TimeoutError:
            logger.warning("Amass timed out")
        except Exception as e:
            logger.exception("Amass error: %s", e)

        return results

    async def _bruteforce_enum(self, domain: str) -> list[SubdomainResult]:
        """DNS brute force enumeration."""
        resolver = self._setup_dns_resolver()
        if not resolver:
            return []

        logger.info("Starting DNS brute force for %s", domain)
        results = await self._process_bruteforce_batches(domain, resolver)
        logger.info("Brute force found %s subdomains", len(results))
        return results

    def _setup_dns_resolver(self) -> Any:
        """Setup DNS resolver."""
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
        self,
        domain: str,
        resolver,
    ) -> list[SubdomainResult]:
        """Process bruteforce in batches."""
        results = []
        batch_size = 50

        for i in range(0, len(self.COMMON_SUBDOMAINS), batch_size):
            batch = self.COMMON_SUBDOMAINS[i : i + batch_size]
            batch_results = await self._check_batch_subdomains(batch, domain, resolver)
            results.extend(batch_results)

        return results

    async def _check_batch_subdomains(
        self,
        batch: list[str],
        domain: str,
        resolver,
    ) -> list[SubdomainResult]:
        """Check a batch of subdomains."""
        tasks = [self._check_single_subdomain(sub, domain, resolver) for sub in batch]
        batch_results = await asyncio.gather(*tasks)
        return [r for r in batch_results if r]

    async def _check_single_subdomain(
        self,
        sub: str,
        domain: str,
        resolver,
    ) -> SubdomainResult | None:
        """Check a single subdomain."""
        fqdn = f"{sub}.{domain}"
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, resolver.resolve, fqdn, "A")
            return SubdomainResult(subdomain=fqdn, source="bruteforce", resolved=True)
        except Exception as e:
            logger.debug("DNS resolution failed for %s: %s", fqdn, e)
            return None

    async def _resolve_subdomains(
        self,
        results: list[SubdomainResult],
    ) -> list[SubdomainResult]:
        """Resolve subdomains to IP addresses."""
        resolver = self._setup_resolver()
        if not resolver:
            return results

        resolved_results = await self._resolve_in_batches(results, resolver)
        resolved_count = sum(1 for r in resolved_results if r.resolved)
        logger.info("Resolved %s/%s subdomains", resolved_count, len(results))
        return resolved_results

    def _setup_resolver(self) -> Any:
        """Setup DNS resolver."""
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            return resolver
        except ImportError:
            return None

    async def _resolve_in_batches(
        self,
        results: list[SubdomainResult],
        resolver,
    ) -> list[SubdomainResult]:
        """Resolve subdomains in batches."""
        batch_size = 25
        resolved_results = []

        for i in range(0, len(results), batch_size):
            batch = results[i : i + batch_size]
            tasks = [self._resolve_single_subdomain(r, resolver) for r in batch]
            batch_results = await asyncio.gather(*tasks)
            resolved_results.extend(batch_results)

        return resolved_results

    async def _resolve_single_subdomain(
        self,
        result: SubdomainResult,
        resolver,
    ) -> SubdomainResult:
        """Resolve a single subdomain."""
        if result.resolved:
            return result

        await self._resolve_a_record(result, resolver)
        await self._resolve_cname_record(result, resolver)
        return result

    async def _resolve_a_record(self, result: SubdomainResult, resolver) -> None:
        """Resolve A record for subdomain."""
        try:
            loop = asyncio.get_running_loop()
            answers = await loop.run_in_executor(
                None,
                resolver.resolve,
                result.subdomain,
                "A",
            )
            result.resolved = True
            result.ip_addresses = [str(r) for r in answers]
        except Exception as e:
            logger.debug("DNS resolution error: %s", e)
            result.resolved = False

    async def _resolve_cname_record(self, result: SubdomainResult, resolver) -> None:
        """Resolve CNAME record for subdomain."""
        try:
            loop = asyncio.get_running_loop()
            answers = await loop.run_in_executor(
                None,
                resolver.resolve,
                result.subdomain,
                "CNAME",
            )
            result.cname = str(answers[0])
        except Exception as e:
            logger.debug("CNAME lookup error: %s", e)
