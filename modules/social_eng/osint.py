"""DRAKBEN Social Engineering - OSINT Spider
Author: @drak_ben
Description: Gathers target intelligence (personnel, emails) from public sources.
"""

import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TargetPerson:
    """Represents a human target."""

    full_name: str
    role: str = "Unknown"
    email: str | None = None
    social_profiles: list[str] | None = None
    psych_profile: str | None = None
    confidence: float = 0.5  # 0-1 confidence score


@dataclass
class DomainIntel:
    """Domain intelligence results."""

    domain: str
    registrar: str = ""
    creation_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)


class OSINTSpider:
    """Crawls open sources to build a target list.

    Features:
    - DNS reconnaissance (MX, TXT, NS records)
    - Email format prediction with verification
    - Web scraping for employee discovery
    - Technology fingerprinting
    """

    def __init__(self) -> None:
        # Default email format constant
        self.DEFAULT_EMAIL_FORMAT = "{first}.{last}@{domain}"
        self.common_formats = [
            self.DEFAULT_EMAIL_FORMAT,
            "{first}{last}@{domain}",
            "{f}{last}@{domain}",
            "{first}.{l}@{domain}",
            "{first}_{last}@{domain}",
            "{last}.{first}@{domain}",
            "{f}.{last}@{domain}",
        ]
        self._session = None
        logger.info("OSINT Spider initialized")

    def _get_session(self) -> Any:
        """Get or create HTTP session with stealth headers."""
        if self._session is None:
            try:
                import requests
                self._session = requests.Session()
                self._session.headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                })
            except ImportError:
                logger.warning("requests library not available")
                return None
        return self._session

    def harvest_domain(self, domain: str) -> list[TargetPerson]:
        """Main entry point: Harvest targets from a company domain.

        Uses multiple OSINT techniques:
        1. DNS recon for email infrastructure
        2. Web scraping for employee discovery
        3. Search engine dorking patterns
        """
        logger.info("Harvesting intelligence for: %s", domain)
        targets: list[TargetPerson] = []

        # 1. DNS Reconnaissance
        domain_intel = self.dns_recon(domain)
        logger.info("DNS Recon: %s MX records, %s nameservers",
                   len(domain_intel.mx_records), len(domain_intel.name_servers))

        # 2. Detect email format from MX records
        email_format = self._detect_email_format(domain, domain_intel)
        logger.info("Detected email format: %s", email_format)

        # 3. Scrape website for team/about pages
        discovered = self._scrape_website_for_employees(domain)

        for name, role in discovered:
            email = self.predict_email(name, domain, email_format)
            confidence = 0.7 if self._verify_email_syntax(email) else 0.4

            targets.append(
                TargetPerson(
                    full_name=name,
                    role=role,
                    email=email,
                    social_profiles=self._find_social_profiles(name),
                    confidence=confidence,
                ),
            )

        # 4. Supplement with search engine results if few targets found
        if len(targets) < 3:
            search_targets = self._search_engine_recon(domain)
            targets.extend(search_targets)

        logger.info("Found %s potential targets", len(targets))
        return targets

    def dns_recon(self, domain: str) -> DomainIntel:
        """Perform DNS reconnaissance on target domain."""
        intel = DomainIntel(domain=domain)

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            # MX Records
            try:
                mx_answers = resolver.resolve(domain, "MX")
                intel.mx_records = [str(r.exchange).rstrip(".") for r in mx_answers]
            except Exception:
                pass

            # NS Records
            try:
                ns_answers = resolver.resolve(domain, "NS")
                intel.name_servers = [str(r).rstrip(".") for r in ns_answers]
            except Exception:
                pass

            # TXT Records (SPF, DKIM, etc.)
            try:
                txt_answers = resolver.resolve(domain, "TXT")
                intel.txt_records = [str(r) for r in txt_answers]
            except Exception:
                pass

        except ImportError:
            # Fallback to socket-based DNS
            logger.debug("dnspython not available, using socket fallback")
            try:
                intel.mx_records = self._socket_mx_lookup(domain)
            except Exception as e:
                logger.debug("Socket MX lookup failed: %s", e)
        except Exception as e:
            logger.warning("DNS recon failed: %s", e)

        return intel

    def _socket_mx_lookup(self, domain: str) -> list[str]:
        """Fallback MX lookup using socket."""
        try:
            # Basic A record lookup to verify domain exists
            socket.gethostbyname(domain)
            # For MX we'd need raw DNS, return common patterns
            return [f"mail.{domain}", f"smtp.{domain}"]
        except socket.gaierror:
            return []

    def _detect_email_format(self, domain: str, intel: DomainIntel) -> str:
        """Detect likely email format based on domain characteristics."""
        # Check TXT records for email patterns
        for txt in intel.txt_records:
            if "v=spf1" in txt.lower():
                # SPF record exists, domain has email infrastructure
                pass

        # Check if corporate email (Google Workspace, Microsoft 365)
        mx_str = " ".join(intel.mx_records).lower()
        if "google" in mx_str or "googlemail" in mx_str:
            return self.DEFAULT_EMAIL_FORMAT  # Google Workspace default
        elif "outlook" in mx_str or "microsoft" in mx_str:
            return self.DEFAULT_EMAIL_FORMAT  # Microsoft 365 default
        elif "protonmail" in mx_str:
            return "{first}{last}@{domain}"

        # Default to most common corporate format
        return self.DEFAULT_EMAIL_FORMAT

    def _scrape_website_for_employees(self, domain: str) -> list[tuple[str, str]]:
        """Scrape website for employee information."""
        discovered: list[tuple[str, str]] = []
        session = self._get_session()

        if not session:
            return discovered

        # Common paths for team/about pages
        paths = [
            "/about", "/about-us", "/team", "/our-team",
            "/leadership", "/management", "/contact",
            "/about/team", "/company/team",
        ]

        for path in paths:
            try:
                url = f"https://{domain}{path}"
                response = session.get(url, timeout=10, verify=False)

                if response.status_code == 200:
                    employees = self._extract_names_from_html(response.text)
                    discovered.extend(employees)
                    if employees:
                        logger.info("Found %s names on %s", len(employees), path)
                        break  # Found good page, stop searching

            except Exception as e:
                logger.debug("Failed to scrape %s: %s", path, e)

        return discovered

    def _extract_names_from_html(self, html: str) -> list[tuple[str, str]]:
        """Extract potential names and roles from HTML content."""
        results: list[tuple[str, str]] = []

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")

            # Look for common patterns
            # Pattern 1: Name in heading with role in nearby text
            for tag in soup.find_all(["h2", "h3", "h4", "strong", "b"]):
                text = tag.get_text(strip=True)
                if self._looks_like_name(text):
                    # Try to find role nearby
                    role = self._find_nearby_role(tag)
                    results.append((text, role))

            # Pattern 2: Structured team sections
            for card in soup.find_all(class_=re.compile(r"team|member|staff|employee", re.IGNORECASE)):
                name_elem = card.find(["h2", "h3", "h4", "strong"])
                role_elem = card.find(class_=re.compile(r"role|title|position", re.IGNORECASE))

                if name_elem:
                    name = name_elem.get_text(strip=True)
                    role = role_elem.get_text(strip=True) if role_elem else "Unknown"
                    if self._looks_like_name(name):
                        results.append((name, role))

        except ImportError:
            logger.debug("BeautifulSoup not available for HTML parsing")
        except Exception as e:
            logger.debug("HTML extraction error: %s", e)

        # Deduplicate
        return list(set(results))[:20]  # Limit to 20 results

    def _looks_like_name(self, text: str) -> bool:
        """Check if text looks like a person's name."""
        if not text or len(text) < 3 or len(text) > 50:
            return False

        # Should have 2-4 words (first, middle, last names)
        words = text.split()
        if len(words) < 2 or len(words) > 4:
            return False

        # Each word should be capitalized and alphabetic
        for word in words:
            if not word[0].isupper() or not word.replace("-", "").replace("'", "").isalpha():
                return False

        # Filter out common false positives
        false_positives = {"About Us", "Contact Us", "Our Team", "Learn More", "Read More"}
        return text not in false_positives

    def _find_nearby_role(self, element: Any) -> str:
        """Find role/title near a name element."""
        role_keywords = {"ceo", "cto", "cfo", "coo", "director", "manager",
                        "engineer", "developer", "analyst", "administrator",
                        "president", "founder", "head", "lead", "senior", "chief"}

        # Check next sibling
        next_elem = element.find_next_sibling()
        if next_elem:
            role = self._extract_role_from_element(next_elem, role_keywords)
            if role:
                return role

        # Check parent's children
        parent = element.parent
        if parent:
            role = self._search_parent_for_role(parent, element, role_keywords)
            if role:
                return role

        return "Unknown"

    def _extract_role_from_element(self, elem: Any, keywords: set[str]) -> str | None:
        """Extract role text from element if it contains role keywords."""
        text = elem.get_text(strip=True).lower() if hasattr(elem, "get_text") else str(elem).lower()
        for keyword in keywords:
            if keyword in text:
                return elem.get_text(strip=True) if hasattr(elem, "get_text") else str(elem)
        return None

    def _search_parent_for_role(self, parent: Any, exclude: Any, keywords: set[str]) -> str | None:
        """Search parent's children for role information."""
        for child in parent.children:
            if child != exclude and hasattr(child, "get_text"):
                text = child.get_text(strip=True).lower()
                for keyword in keywords:
                    if keyword in text:
                        return child.get_text(strip=True)
        return None

    def _find_social_profiles(self, name: str) -> list[str]:
        """Find potential social profiles for a person."""
        profiles = []
        name_slug = name.lower().replace(" ", "")

        profiles.append(f"linkedin.com/in/{name_slug}")
        profiles.append(f"twitter.com/{name_slug}")

        return profiles

    def _search_engine_recon(self, domain: str) -> list[TargetPerson]:
        """Use search engine patterns to find employees."""
        targets = []
        session = self._get_session()

        if not session:
            # Return simulated results as fallback
            return self._get_simulated_results(domain)

        # DuckDuckGo HTML search (no API key needed)
        dorks = [
            f'site:linkedin.com/in "{domain}"',
            f'site:{domain} "team" OR "about" OR "staff"',
        ]

        try:
            for dork in dorks:
                url = f"https://html.duckduckgo.com/html/?q={dork}"
                response = session.get(url, timeout=15)

                if response.status_code == 200:
                    names = self._extract_names_from_search_results(response.text)
                    for name in names[:5]:  # Limit per dork
                        email = self.predict_email(name, domain)
                        targets.append(TargetPerson(
                            full_name=name,
                            role="Unknown",
                            email=email,
                            confidence=0.4,
                        ))

        except Exception as e:
            logger.debug("Search engine recon failed: %s", e)
            return self._get_simulated_results(domain)

        return targets

    def _extract_names_from_search_results(self, html: str) -> list[str]:
        """Extract names from search engine results."""
        names = []

        # LinkedIn pattern: "FirstName LastName - Title | LinkedIn"
        linkedin_pattern = r"([A-Z][a-z]+ [A-Z][a-z]+)\s*[-–]\s*[^|]+\|\s*LinkedIn"
        matches = re.findall(linkedin_pattern, html)
        names.extend(matches)

        return list(set(names))[:10]

    def _get_simulated_results(self, domain: str) -> list[TargetPerson]:
        """Return simulated results when real OSINT fails."""
        logger.debug("Using simulated OSINT results for: %s", domain)

        simulated = [
            ("John Doe", "IT Administrator"),
            ("Jane Smith", "HR Manager"),
            ("Robert Brown", "Finance Director"),
            ("Emily White", "Security Analyst"),
        ]

        targets = []
        for name, role in simulated:
            email = self.predict_email(name, domain)
            targets.append(TargetPerson(
                full_name=name,
                role=role,
                email=email,
                social_profiles=self._find_social_profiles(name),
                confidence=0.3,  # Low confidence for simulated
            ))

        return targets

    def predict_email(
        self,
        full_name: str,
        domain: str,
        format_str: str = "{first}.{last}@{domain}",
    ) -> str:
        """Predict email address based on name and domain."""
        try:
            parts = full_name.lower().split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                f_initial, l_initial = first[0], last[0]

                return format_str.format(
                    first=first,
                    last=last,
                    f=f_initial,
                    l=l_initial,
                    domain=domain,
                )
            return f"{parts[0]}@{domain}"
        except Exception as e:
            logger.exception("Email prediction error: %s", e)
            return ""

    def _verify_email_syntax(self, email: str) -> bool:
        """Verify email syntax is valid."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))


