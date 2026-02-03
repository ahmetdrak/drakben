# modules/cve_database.py
# DRAKBEN CVE/NVD Database Integration
# Vulnerability matching with CVE database and CVSS scoring

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiohttp

if TYPE_CHECKING:
    from core.agent.state import AgentState

logger = logging.getLogger(__name__)


class CVSSSeverity(Enum):
    """CVSS severity levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CVEEntry:
    """CVE entry data structure."""

    cve_id: str
    description: str
    cvss_score: float
    cvss_vector: str
    severity: CVSSSeverity
    published_date: str
    last_modified: str
    references: list[str] = field(default_factory=list)
    cpe_matches: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity.value,
            "published_date": self.published_date,
            "last_modified": self.last_modified,
            "references": self.references,
            "cpe_matches": self.cpe_matches,
            "weaknesses": self.weaknesses,
        }


@dataclass
class VulnerabilityMatch:
    """Matched vulnerability with CVE."""

    detected_vuln: str
    cve_entry: CVEEntry | None
    confidence: float  # 0.0 - 1.0
    match_method: str  # "exact", "keyword", "cpe", "fuzzy"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected_vuln": self.detected_vuln,
            "cve": self.cve_entry.to_dict() if self.cve_entry else None,
            "confidence": self.confidence,
            "match_method": self.match_method,
        }


class AutoUpdater:
    """Real-Time CVE Feed Updater (Incremental).
    Checks NVD for updates every 12 hours without blocking main thread.
    """

    def __init__(self, db_instance: "CVEDatabase") -> None:
        self.db = db_instance
        self.running = False

    def start_background_update(self) -> None:
        """Starts the update loop in a separate thread."""
        import threading

        t = threading.Thread(target=self._update_loop, daemon=True)
        t.start()

    def _update_loop(self) -> None:
        """Infinite loop to keep DB fresh."""
        import time

        while True:
            try:
                self._perform_incremental_update()
                # Sleep 6 hours (NVD limits)
                time.sleep(6 * 3600)
            except Exception as e:
                logger.exception("Auto-Update failed: %s", e)
                time.sleep(3600)  # Retry in 1 hour

    def _perform_incremental_update(self) -> None:
        """Fetch only CVEs modified since last sync."""
        # Get last update timestamp from DB or default to 30 days ago
        last_sync = self.db.get_last_sync_time()
        if not last_sync:
            # First run: go back 90 days for recent threats
            start_date = (datetime.now() - timedelta(days=90)).isoformat()
        else:
            start_date = last_sync

        # NVD requires ISO8601 format: YYYY-MM-DDThh:mm:ss.s
        # Adjust format if needed
        if "." not in start_date:
            start_date += ".000"
        if not start_date.endswith("Z"):
            start_date += "Z"

        # Current time
        end_date = datetime.now().isoformat()
        if "." not in end_date:
            end_date += ".000"
        if not end_date.endswith("Z"):
            end_date += "Z"

        logger.info("Checking for CVE updates from %s to %s", start_date, end_date)

        # Note: In a threaded context, we can't use async aiohttp easily if the loop is separate.
        # We use 'requests' for the background thread to confirm simplicity.
        try:
            import urllib.parse
            import urllib.request

            headers = {"User-Agent": "Drakben-Agent/2.0"}
            if self.db.api_key:
                headers["apiKey"] = self.db.api_key

            url = f"{self.db.NVD_API_BASE}?lastModStartDate={start_date}&lastModEndDate={end_date}"
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=60) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    vulns = data.get("vulnerabilities", [])
                    logger.info("Found %s new/modified CVEs", len(vulns))

                    for item in vulns:
                        entry = self.db._parse_nvd_response(item)
                        if entry:
                            self.db._save_to_cache(entry)

                    # Update sync time
                    self.db.update_last_sync_time()
                else:
                    logger.warning("Update failed: HTTP %s", resp.status)

        except Exception as e:
            logger.exception("Incremental update error: %s", e)


class CVEDatabase:
    """CVE/NVD Database Manager with offline caching.

    Features:
    - NVD API 2.0 integration
    - SQLite offline cache
    - CVSS scoring
    - Keyword-based matching
    - CPE matching
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_EXPIRY_DAYS = 7

    def __init__(
        self, db_path: str = "nvd_cache.db", api_key: str | None = None,
    ) -> None:
        """Initialize CVE Database.

        Args:
            db_path: Path to SQLite cache database
            api_key: Optional NVD API key for higher rate limits

        """
        self.db_path = Path(db_path)
        self.api_key = api_key
        self._init_database()

        # 2026 Auto-Update Mechanism
        self.auto_updater = AutoUpdater(self)
        self.auto_updater.start_background_update()

        logger.info("CVE Database initialized: %s (Real-Time Updates Active)", db_path)

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cve_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS keyword_index (
                    keyword TEXT,
                    cve_id TEXT,
                    PRIMARY KEY (keyword, cve_id),
                    FOREIGN KEY (cve_id) REFERENCES cve_cache(cve_id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cpe_index (
                    cpe TEXT,
                    cve_id TEXT,
                    PRIMARY KEY (cpe, cve_id),
                    FOREIGN KEY (cve_id) REFERENCES cve_cache(cve_id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_keyword ON keyword_index(keyword)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cpe ON cpe_index(cpe)
            """)

            # Metadata table for sync state
            conn.execute("""
                CREATE TABLE IF NOT EXISTS meta_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.commit()

    def get_last_sync_time(self) -> str | None:
        """Get the timestamp of the last successful update."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT value FROM meta_info WHERE key='last_sync'",
                ).fetchone()
                return row[0] if row else None
        except Exception:
            return None

    def update_last_sync_time(self) -> None:
        """Set last sync time to now."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                now = datetime.now().isoformat()
                conn.execute(
                    "INSERT OR REPLACE INTO meta_info (key, value) VALUES ('last_sync', ?)",
                    (now,),
                )
                conn.commit()
        except Exception as e:
            logger.debug("Failed to update sync time: %s", e)

    def _get_severity(self, cvss_score: float) -> CVSSSeverity:
        """Get severity level from CVSS score."""
        if cvss_score == 0:
            return CVSSSeverity.NONE
        if cvss_score < 4.0:
            return CVSSSeverity.LOW
        if cvss_score < 7.0:
            return CVSSSeverity.MEDIUM
        if cvss_score < 9.0:
            return CVSSSeverity.HIGH
        return CVSSSeverity.CRITICAL

    def _parse_nvd_response(self, item: dict[str, Any]) -> CVEEntry | None:
        """Parse NVD API response item to CVEEntry."""
        try:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            description = self._extract_cve_description(cve_data)
            cvss_score, cvss_vector = self._extract_cvss_metrics(cve_data)
            references = self._extract_cve_references(cve_data)
            cpe_matches = self._extract_cpe_matches(cve_data)
            weaknesses = self._extract_cwe_weaknesses(cve_data)

            return CVEEntry(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=self._get_severity(cvss_score),
                published_date=cve_data.get("published", ""),
                last_modified=cve_data.get("lastModified", ""),
                references=references[:10],
                cpe_matches=cpe_matches[:20],
                weaknesses=weaknesses[:5],
            )
        except Exception as e:
            logger.exception("Error parsing NVD response: %s", e)
            return None

    def _extract_cve_description(self, cve_data: dict) -> str:
        """Extract CVE description (prefer English)."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    def _extract_cvss_metrics(self, cve_data: dict) -> tuple[float, str]:
        """Extract CVSS score and vector (prefer v3.1, then v3.0, then v2.0)."""
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            return self._get_cvss_from_metric(metrics["cvssMetricV31"][0])
        if "cvssMetricV30" in metrics:
            return self._get_cvss_from_metric(metrics["cvssMetricV30"][0])
        if "cvssMetricV2" in metrics:
            return self._get_cvss_from_metric(metrics["cvssMetricV2"][0])
        return 0.0, ""

    def _get_cvss_from_metric(self, metric: dict) -> tuple[float, str]:
        """Extract CVSS score and vector from metric."""
        cvss_data = metric.get("cvssData", {})
        return cvss_data.get("baseScore", 0.0), cvss_data.get("vectorString", "")

    def _extract_cve_references(self, cve_data: dict) -> list[str]:
        """Extract CVE references."""
        return [ref.get("url", "") for ref in cve_data.get("references", [])]

    def _extract_cpe_matches(self, cve_data: dict) -> list[str]:
        """Extract CPE matches from configurations."""
        cpe_matches = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", False):
                        cpe_matches.append(match.get("criteria", ""))
        return cpe_matches

    def _extract_cwe_weaknesses(self, cve_data: dict) -> list[str]:
        """Extract CWE weaknesses."""
        weaknesses = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))
        return weaknesses

    async def fetch_cve(self, cve_id: str) -> CVEEntry | None:
        """Fetch a specific CVE from NVD API or cache.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")

        Returns:
            CVEEntry or None if not found

        """
        # Check cache first
        cached = self._get_from_cache(cve_id)
        if cached:
            logger.debug("Cache hit for %s", cve_id)
            return cached

        # Fetch from API
        logger.info("Fetching %s from NVD API", cve_id)
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with aiohttp.ClientSession() as session:
                url = f"{self.NVD_API_BASE}?cveId={cve_id}"
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        if vulnerabilities:
                            entry = self._parse_nvd_response(vulnerabilities[0])
                            if entry:
                                self._save_to_cache(entry)
                                return entry
                    elif resp.status == 404:
                        logger.warning("CVE not found: %s", cve_id)
                    else:
                        logger.error("NVD API error: %s", resp.status)
        except TimeoutError:
            logger.exception("Timeout fetching %s", cve_id)
        except Exception as e:
            logger.exception("Error fetching %s: %s", cve_id, e)

        return None

    async def search_cves(
        self,
        keyword: str,
        max_results: int = 20,
        min_cvss: float = 0.0,
    ) -> list[CVEEntry]:
        """Search CVEs by keyword.

        Args:
            keyword: Search keyword
            max_results: Maximum results to return
            min_cvss: Minimum CVSS score filter

        Returns:
            List of matching CVEEntry objects

        """
        results = self._search_cached_cves(keyword, min_cvss)
        if len(results) >= max_results:
            return results[:max_results]

        api_results = await self._fetch_cves_from_api(keyword, max_results, min_cvss)
        return self._merge_cve_results(results, api_results, max_results)

    def _search_cached_cves(self, keyword: str, min_cvss: float) -> list[CVEEntry]:
        """Search CVEs in local cache."""
        results = []
        cached_results = self._search_cache(keyword)
        for entry in cached_results:
            if entry.cvss_score >= min_cvss:
                results.append(entry)
        return results

    async def _fetch_cves_from_api(
        self,
        keyword: str,
        max_results: int,
        min_cvss: float,
    ) -> list[CVEEntry]:
        """Fetch CVEs from NVD API."""
        logger.info("Searching NVD for: %s", keyword)
        results = []
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with aiohttp.ClientSession() as session:
                url = f"{self.NVD_API_BASE}?keywordSearch={keyword}&resultsPerPage={max_results}"
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = self._process_api_results(data, min_cvss)
        except Exception as e:
            logger.exception("Error searching CVEs: %s", e)

        return results

    def _process_api_results(self, data: dict, min_cvss: float) -> list[CVEEntry]:
        """Process API response and filter by CVSS."""
        results = []
        for item in data.get("vulnerabilities", []):
            entry = self._parse_nvd_response(item)
            if entry and entry.cvss_score >= min_cvss:
                self._save_to_cache(entry)
                results.append(entry)
        return results

    def _merge_cve_results(
        self,
        cached: list[CVEEntry],
        api: list[CVEEntry],
        max_results: int,
    ) -> list[CVEEntry]:
        """Merge cached and API results, removing duplicates."""
        seen_ids = {entry.cve_id for entry in cached}
        for entry in api:
            if entry.cve_id not in seen_ids:
                cached.append(entry)
                seen_ids.add(entry.cve_id)
        return cached[:max_results]

    async def search_by_cpe(self, cpe: str, max_results: int = 20) -> list[CVEEntry]:
        """Search CVEs by CPE (Common Platform Enumeration).

        Args:
            cpe: CPE string (e.g., "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
            max_results: Maximum results

        Returns:
            List of CVEEntry objects

        """
        results = []

        # Check local cache
        cached = self._search_cache_by_cpe(cpe)
        results.extend(cached)

        if len(results) >= max_results:
            return results[:max_results]

        # Fetch from API
        logger.info("Searching NVD by CPE: %s", cpe)
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with aiohttp.ClientSession() as session:
                url = f"{self.NVD_API_BASE}?cpeName={cpe}&resultsPerPage={max_results}"
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("vulnerabilities", []):
                            entry = self._parse_nvd_response(item)
                            if entry:
                                self._save_to_cache(entry)
                                if entry not in results:
                                    results.append(entry)
        except Exception as e:
            logger.exception("Error searching by CPE: %s", e)

        return results[:max_results]

    def _get_from_cache(self, cve_id: str) -> CVEEntry | None:
        """Get CVE from local cache."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT data, cached_at FROM cve_cache WHERE cve_id = ?",
                    (cve_id,),
                )
                row = cursor.fetchone()
                if row:
                    data, cached_at = row
                    # Check if cache is still valid
                    cached_time = datetime.fromisoformat(cached_at)
                    if datetime.now() - cached_time < timedelta(
                        days=self.CACHE_EXPIRY_DAYS,
                    ):
                        entry_data = json.loads(data)
                        return CVEEntry(
                            cve_id=entry_data["cve_id"],
                            description=entry_data["description"],
                            cvss_score=entry_data["cvss_score"],
                            cvss_vector=entry_data["cvss_vector"],
                            severity=CVSSSeverity(entry_data["severity"]),
                            published_date=entry_data["published_date"],
                            last_modified=entry_data["last_modified"],
                            references=entry_data.get("references", []),
                            cpe_matches=entry_data.get("cpe_matches", []),
                            weaknesses=entry_data.get("weaknesses", []),
                        )
        except Exception as e:
            logger.exception("Cache read error: %s", e)
        return None

    def _save_to_cache(self, entry: CVEEntry) -> None:
        """Save CVE to local cache."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Save main entry
                conn.execute(
                    "INSERT OR REPLACE INTO cve_cache (cve_id, data) VALUES (?, ?)",
                    (entry.cve_id, json.dumps(entry.to_dict())),
                )

                # Index keywords from description
                keywords = self._extract_keywords(entry.description)
                for keyword in keywords:
                    conn.execute(
                        "INSERT OR IGNORE INTO keyword_index (keyword, cve_id) VALUES (?, ?)",
                        (keyword.lower(), entry.cve_id),
                    )

                # Index CPE matches
                for cpe in entry.cpe_matches:
                    conn.execute(
                        "INSERT OR IGNORE INTO cpe_index (cpe, cve_id) VALUES (?, ?)",
                        (cpe, entry.cve_id),
                    )

                conn.commit()
        except Exception as e:
            logger.exception("Cache write error: %s", e)

    def _search_cache(self, keyword: str) -> list[CVEEntry]:
        """Search cache by keyword."""
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    SELECT DISTINCT c.data FROM cve_cache c
                    JOIN keyword_index k ON c.cve_id = k.cve_id
                    WHERE k.keyword LIKE ?
                    LIMIT 50
                    """,
                    (f"%{keyword.lower()}%",),
                )
                for row in cursor:
                    entry_data = json.loads(row[0])
                    results.append(
                        CVEEntry(
                            cve_id=entry_data["cve_id"],
                            description=entry_data["description"],
                            cvss_score=entry_data["cvss_score"],
                            cvss_vector=entry_data["cvss_vector"],
                            severity=CVSSSeverity(entry_data["severity"]),
                            published_date=entry_data["published_date"],
                            last_modified=entry_data["last_modified"],
                            references=entry_data.get("references", []),
                            cpe_matches=entry_data.get("cpe_matches", []),
                            weaknesses=entry_data.get("weaknesses", []),
                        ),
                    )
        except Exception as e:
            logger.exception("Cache search error: %s", e)
        return results

    def _search_cache_by_cpe(self, cpe: str) -> list[CVEEntry]:
        """Search cache by CPE."""
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    SELECT DISTINCT c.data FROM cve_cache c
                    JOIN cpe_index cp ON c.cve_id = cp.cve_id
                    WHERE cp.cpe LIKE ?
                    LIMIT 50
                    """,
                    (f"%{cpe}%",),
                )
                for row in cursor:
                    entry_data = json.loads(row[0])
                    results.append(
                        CVEEntry(
                            cve_id=entry_data["cve_id"],
                            description=entry_data["description"],
                            cvss_score=entry_data["cvss_score"],
                            cvss_vector=entry_data["cvss_vector"],
                            severity=CVSSSeverity(entry_data["severity"]),
                            published_date=entry_data["published_date"],
                            last_modified=entry_data["last_modified"],
                            references=entry_data.get("references", []),
                            cpe_matches=entry_data.get("cpe_matches", []),
                            weaknesses=entry_data.get("weaknesses", []),
                        ),
                    )
        except Exception as e:
            logger.exception("CPE search error: %s", e)
        return results

    def _extract_keywords(self, text: str) -> list[str]:
        """Extract indexable keywords from text."""
        import re

        # Extract words 4+ characters, alphanumeric
        words = re.findall(r"\b[a-zA-Z0-9]{4,}\b", text.lower())
        # Filter common words
        stopwords = {
            "that",
            "this",
            "with",
            "from",
            "have",
            "been",
            "were",
            "which",
            "when",
            "there",
            "their",
        }
        return [w for w in set(words) if w not in stopwords][:30]

    def get_cache_stats(self) -> dict[str, int]:
        """Get cache statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cve_count = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
                keyword_count = conn.execute(
                    "SELECT COUNT(DISTINCT keyword) FROM keyword_index",
                ).fetchone()[0]
                cpe_count = conn.execute(
                    "SELECT COUNT(DISTINCT cpe) FROM cpe_index",
                ).fetchone()[0]
                return {
                    "cve_entries": cve_count,
                    "indexed_keywords": keyword_count,
                    "indexed_cpes": cpe_count,
                }
        except Exception as e:
            logger.exception("Stats error: %s", e)
            return {"cve_entries": 0, "indexed_keywords": 0, "indexed_cpes": 0}

    def clear_cache(self) -> None:
        """Clear all cached data."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM keyword_index")
                conn.execute("DELETE FROM cpe_index")
                conn.execute("DELETE FROM cve_cache")
                conn.commit()
            logger.info("Cache cleared")
        except Exception as e:
            logger.exception("Clear cache error: %s", e)


class VulnerabilityMatcher:
    """Match detected vulnerabilities with CVE database.

    Uses multiple matching strategies:
    - Exact CVE ID match
    - Keyword-based matching
    - CPE-based matching
    - Fuzzy matching
    """

    # Common vulnerability patterns to CVE keywords
    VULN_PATTERNS = {
        "sql injection": ["sql injection", "sqli", "sql"],
        "xss": ["cross-site scripting", "xss"],
        "xxe": ["xml external entity", "xxe"],
        "ssrf": ["server-side request forgery", "ssrf"],
        "lfi": ["local file inclusion", "lfi", "path traversal"],
        "rfi": ["remote file inclusion", "rfi"],
        "rce": ["remote code execution", "rce", "command injection"],
        "csrf": ["cross-site request forgery", "csrf"],
        "idor": ["insecure direct object reference", "idor"],
        "ssti": ["server-side template injection", "ssti"],
        "deserialization": ["deserialization", "unserialize"],
        "authentication bypass": ["authentication bypass", "auth bypass"],
        "privilege escalation": ["privilege escalation", "privesc"],
        "buffer overflow": ["buffer overflow", "bof"],
        "directory traversal": ["directory traversal", "path traversal"],
    }

    def __init__(self, cve_db: CVEDatabase) -> None:
        """Initialize matcher.

        Args:
            cve_db: CVEDatabase instance

        """
        self.cve_db = cve_db
        logger.info("VulnerabilityMatcher initialized")

    async def match_vulnerability(
        self,
        vuln_type: str,
        product: str | None = None,
        version: str | None = None,
    ) -> list[VulnerabilityMatch]:
        """Match a detected vulnerability with CVEs.

        Args:
            vuln_type: Type of vulnerability (e.g., "sql injection")
            product: Affected product name
            version: Affected version

        Returns:
            List of VulnerabilityMatch objects sorted by confidence

        """
        vuln_lower = vuln_type.lower()

        # Strategy 1: Check if it's already a CVE ID
        exact_match = await self._try_exact_cve_match(vuln_type, vuln_lower)
        if exact_match:
            return exact_match

        matches = []
        matches.extend(await self._try_cpe_match(vuln_type, product, version))
        matches.extend(await self._try_keyword_match(vuln_type, vuln_lower))

        return self._deduplicate_and_sort_matches(matches)

    async def _try_exact_cve_match(
        self,
        vuln_type: str,
        vuln_lower: str,
    ) -> list[VulnerabilityMatch] | None:
        """Try to match as exact CVE ID."""
        if not vuln_lower.startswith("cve-"):
            return None

        entry = await self.cve_db.fetch_cve(vuln_type.upper())
        if entry:
            return [
                VulnerabilityMatch(
                    detected_vuln=vuln_type,
                    cve_entry=entry,
                    confidence=1.0,
                    match_method="exact",
                ),
            ]
        return None

    async def _try_cpe_match(
        self,
        vuln_type: str,
        product: str | None,
        version: str | None,
    ) -> list[VulnerabilityMatch]:
        """Try CPE-based matching."""
        matches: list[VulnerabilityMatch] = []
        if not product:
            return matches

        cpe_string = self._build_cpe(product, version)
        if not cpe_string:
            return matches

        cpe_results = await self.cve_db.search_by_cpe(cpe_string, max_results=10)
        for entry in cpe_results:
            matches.append(
                VulnerabilityMatch(
                    detected_vuln=vuln_type,
                    cve_entry=entry,
                    confidence=0.85,
                    match_method="cpe",
                ),
            )
        return matches

    async def _try_keyword_match(
        self,
        vuln_type: str,
        vuln_lower: str,
    ) -> list[VulnerabilityMatch]:
        """Try keyword-based matching."""
        matches = []
        keywords = self._get_search_keywords(vuln_lower)
        for keyword in keywords:
            search_results = await self.cve_db.search_cves(keyword, max_results=5)
            for entry in search_results:
                confidence = self._calculate_confidence(vuln_lower, entry.description)
                if confidence > 0.5:
                    matches.append(
                        VulnerabilityMatch(
                            detected_vuln=vuln_type,
                            cve_entry=entry,
                            confidence=confidence,
                            match_method="keyword",
                        ),
                    )
        return matches

    def _deduplicate_and_sort_matches(
        self,
        matches: list[VulnerabilityMatch],
    ) -> list[VulnerabilityMatch]:
        """Remove duplicates and sort by confidence."""
        seen_cves = set()
        unique_matches = []
        for match in sorted(matches, key=lambda x: x.confidence, reverse=True):
            if match.cve_entry and match.cve_entry.cve_id not in seen_cves:
                seen_cves.add(match.cve_entry.cve_id)
                unique_matches.append(match)
        return unique_matches[:10]  # Top 10 matches

    def _get_search_keywords(self, vuln_type: str) -> list[str]:
        """Get search keywords for vulnerability type."""
        keywords = [vuln_type]

        for pattern, alternatives in self.VULN_PATTERNS.items():
            if pattern in vuln_type or vuln_type in pattern:
                keywords.extend(alternatives)
                break

        return list(set(keywords))

    def _build_cpe(self, product: str, version: str | None) -> str | None:
        """Build CPE string from product/version."""
        if not product:
            return None

        product_clean = product.lower().replace(" ", "_")
        if version:
            version_clean = version.replace(" ", "_")
            return f"cpe:2.3:a:*:{product_clean}:{version_clean}:*:*:*:*:*:*:*"
        return f"cpe:2.3:a:*:{product_clean}:*:*:*:*:*:*:*:*"

    def _calculate_confidence(self, vuln_type: str, description: str) -> float:
        """Calculate match confidence based on description."""
        vuln_words = set(vuln_type.lower().split())
        desc_words = set(description.lower().split())

        if not vuln_words:
            return 0.0

        # Calculate Jaccard similarity
        intersection = len(vuln_words & desc_words)
        union = len(vuln_words)

        base_confidence = intersection / union if union > 0 else 0.0

        # Boost for exact phrase match
        if vuln_type.lower() in description.lower():
            base_confidence = min(1.0, base_confidence + 0.3)

        return round(base_confidence, 2)


# Convenience functions for state integration
async def match_state_vulnerabilities(
    state: "AgentState",
    cve_db: CVEDatabase | None = None,
) -> list[VulnerabilityMatch]:
    """Match all vulnerabilities in AgentState with CVE database.

    Args:
        state: AgentState instance
        cve_db: Optional CVEDatabase instance

    Returns:
        List of VulnerabilityMatch objects

    """
    if cve_db is None:
        cve_db = CVEDatabase()

    matcher = VulnerabilityMatcher(cve_db)
    all_matches = []

    for vuln in state.vulnerabilities:
        matches = await matcher.match_vulnerability(
            vuln_type=vuln.vuln_id,
            product=getattr(vuln, "product", None),
            version=getattr(vuln, "version", None),
        )
        all_matches.extend(matches)

    return all_matches


def get_severity_color(severity: CVSSSeverity) -> str:
    """Get color for severity level (for rich console)."""
    colors = {
        CVSSSeverity.NONE: "dim",
        CVSSSeverity.LOW: "green",
        CVSSSeverity.MEDIUM: "yellow",
        CVSSSeverity.HIGH: "orange1",
        CVSSSeverity.CRITICAL: "red bold",
    }
    return colors.get(severity, "white")


def format_cvss_score(score: float) -> str:
    """Format CVSS score with severity indicator."""
    if score == 0:
        return "0.0 (None)"
    if score < 4.0:
        return f"{score:.1f} (Low)"
    if score < 7.0:
        return f"{score:.1f} (Medium)"
    if score < 9.0:
        return f"{score:.1f} (High)"
    return f"{score:.1f} (Critical)"
