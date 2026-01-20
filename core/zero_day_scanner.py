# core/zero_day_scanner.py
# DRAKBEN Zero Day Scanner - Enterprise Grade CVE/Exploit Detection
# Author: @drak_ben

import asyncio
import aiohttp
import json
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import sqlite3
from pathlib import Path


class Severity(Enum):
    """CVE severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExploitAvailability(Enum):
    """Exploit availability status"""
    PUBLIC = "public"
    PRIVATE = "private"
    POC = "poc"
    UNKNOWN = "unknown"


@dataclass
class CVEEntry:
    """CVE vulnerability entry"""
    cve_id: str
    description: str
    severity: Severity
    cvss_score: float
    cvss_vector: str = ""
    published_date: str = ""
    modified_date: str = ""
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: ExploitAvailability = ExploitAvailability.UNKNOWN
    exploit_urls: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "published_date": self.published_date,
            "modified_date": self.modified_date,
            "affected_products": self.affected_products,
            "references": self.references,
            "exploit_available": self.exploit_available.value,
            "exploit_urls": self.exploit_urls,
            "cwe_ids": self.cwe_ids
        }


@dataclass
class ScanTarget:
    """Scan target information"""
    host: str
    port: int = 0
    service: str = ""
    version: str = ""
    os: str = ""
    banner: str = ""
    cpe: str = ""  # Common Platform Enumeration


@dataclass
class ScanResult:
    """Zero day scan result"""
    target: ScanTarget
    vulnerabilities: List[CVEEntry] = field(default_factory=list)
    scan_time: str = ""
    scanner_version: str = "2.0.0"
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    exploitable_count: int = 0
    
    def to_dict(self) -> Dict:
        return {
            "target": asdict(self.target),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_time": self.scan_time,
            "scanner_version": self.scanner_version,
            "total_cves": self.total_cves,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "exploitable_count": self.exploitable_count
        }


class CVEDatabase:
    """Local CVE database for offline scanning"""
    
    def __init__(self, db_path: str = "data/cve_database.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Connect to database"""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
    
    def _create_tables(self):
        """Create database tables"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                published_date TEXT,
                modified_date TEXT,
                affected_products TEXT,
                reference_urls TEXT,
                exploit_available TEXT,
                exploit_urls TEXT,
                cwe_ids TEXT,
                last_updated TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                exploit_db_id TEXT,
                title TEXT,
                type TEXT,
                platform TEXT,
                author TEXT,
                url TEXT,
                verified INTEGER DEFAULT 0,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_severity ON cves(severity)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cves(cvss_score)
        """)
        
        self.conn.commit()
    
    def add_cve(self, cve: CVEEntry):
        """Add or update CVE in database"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO cves 
            (cve_id, description, severity, cvss_score, cvss_vector, 
             published_date, modified_date, affected_products, reference_urls,
             exploit_available, exploit_urls, cwe_ids, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve.cve_id,
            cve.description,
            cve.severity.value,
            cve.cvss_score,
            cve.cvss_vector,
            cve.published_date,
            cve.modified_date,
            json.dumps(cve.affected_products),
            json.dumps(cve.references),
            cve.exploit_available.value,
            json.dumps(cve.exploit_urls),
            json.dumps(cve.cwe_ids),
            datetime.now().isoformat()
        ))
        
        self.conn.commit()
    
    def search_by_product(self, product: str, version: str = "") -> List[CVEEntry]:
        """Search CVEs by product name and version"""
        cursor = self.conn.cursor()
        
        search_term = f"%{product}%"
        if version:
            search_term = f"%{product}%{version}%"
        
        cursor.execute("""
            SELECT * FROM cves 
            WHERE affected_products LIKE ? 
            ORDER BY cvss_score DESC
        """, (search_term,))
        
        results = []
        for row in cursor.fetchall():
            results.append(self._row_to_cve(row))
        
        return results
    
    def search_by_cpe(self, cpe: str) -> List[CVEEntry]:
        """Search CVEs by CPE string"""
        cursor = self.conn.cursor()
        
        # Parse CPE and create search pattern
        cpe_pattern = f"%{cpe.replace(':', '%')}%"
        
        cursor.execute("""
            SELECT * FROM cves 
            WHERE affected_products LIKE ? 
            ORDER BY cvss_score DESC
        """, (cpe_pattern,))
        
        results = []
        for row in cursor.fetchall():
            results.append(self._row_to_cve(row))
        
        return results
    
    def get_critical_cves(self, limit: int = 100) -> List[CVEEntry]:
        """Get critical CVEs"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT * FROM cves 
            WHERE severity = 'critical' OR cvss_score >= 9.0
            ORDER BY cvss_score DESC
            LIMIT ?
        """, (limit,))
        
        return [self._row_to_cve(row) for row in cursor.fetchall()]
    
    def get_exploitable_cves(self) -> List[CVEEntry]:
        """Get CVEs with known exploits"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT * FROM cves 
            WHERE exploit_available IN ('public', 'poc')
            ORDER BY cvss_score DESC
        """)
        
        return [self._row_to_cve(row) for row in cursor.fetchall()]
    
    def _row_to_cve(self, row) -> CVEEntry:
        """Convert database row to CVEEntry"""
        return CVEEntry(
            cve_id=row["cve_id"],
            description=row["description"],
            severity=Severity(row["severity"]),
            cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"] or "",
            published_date=row["published_date"] or "",
            modified_date=row["modified_date"] or "",
            affected_products=json.loads(row["affected_products"] or "[]"),
            references=json.loads(row["reference_urls"] or "[]"),
            exploit_available=ExploitAvailability(row["exploit_available"]),
            exploit_urls=json.loads(row["exploit_urls"] or "[]"),
            cwe_ids=json.loads(row["cwe_ids"] or "[]")
        )
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


class NVDClient:
    """NIST National Vulnerability Database API Client"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.rate_limit_delay = 6.0 if not api_key else 0.6  # seconds between requests
        self.last_request_time = 0
    
    async def search_cves(self, keyword: str = None, cpe: str = None, 
                          cvss_min: float = None, days_back: int = 30,
                          results_per_page: int = 50) -> List[CVEEntry]:
        """Search CVEs from NVD API"""
        await self._rate_limit()
        
        params = {
            "resultsPerPage": results_per_page
        }
        
        if keyword:
            params["keywordSearch"] = keyword
        
        if cpe:
            params["cpeName"] = cpe
        
        if cvss_min:
            params["cvssV3Severity"] = self._cvss_to_severity(cvss_min)
        
        if days_back:
            pub_start = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
            params["pubStartDate"] = pub_start
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.BASE_URL, params=params, headers=headers, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_nvd_response(data)
                    else:
                        return []
        except Exception as e:
            print(f"[NVD API Error] {e}")
            return []
    
    async def get_cve_details(self, cve_id: str) -> Optional[CVEEntry]:
        """Get specific CVE details"""
        await self._rate_limit()
        
        params = {"cveId": cve_id}
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.BASE_URL, params=params, headers=headers, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        cves = self._parse_nvd_response(data)
                        return cves[0] if cves else None
        except Exception as e:
            print(f"[NVD API Error] {e}")
            return None
    
    async def _rate_limit(self):
        """Apply rate limiting"""
        import time
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity string"""
        if cvss >= 9.0:
            return "CRITICAL"
        elif cvss >= 7.0:
            return "HIGH"
        elif cvss >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _parse_nvd_response(self, data: Dict) -> List[CVEEntry]:
        """Parse NVD API response"""
        cves = []
        
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            
            # Get CVSS score
            cvss_score = 0.0
            cvss_vector = ""
            
            metrics = cve_data.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Get affected products (CPE)
            affected_products = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        affected_products.append(cpe_match.get("criteria", ""))
            
            # Get references
            references = []
            for ref in cve_data.get("references", []):
                references.append(ref.get("url", ""))
            
            # Get CWE IDs
            cwe_ids = []
            weaknesses = cve_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_ids.append(desc.get("value", ""))
            
            # Determine severity
            severity = self._score_to_severity(cvss_score)
            
            cve = CVEEntry(
                cve_id=cve_data.get("id", ""),
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=cve_data.get("published", ""),
                modified_date=cve_data.get("lastModified", ""),
                affected_products=affected_products,
                references=references,
                cwe_ids=cwe_ids
            )
            
            cves.append(cve)
        
        return cves
    
    def _score_to_severity(self, score: float) -> Severity:
        """Convert CVSS score to Severity enum"""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0:
            return Severity.LOW
        return Severity.INFO


class ExploitDBClient:
    """Exploit-DB search client"""
    
    SEARCH_URL = "https://www.exploit-db.com/search"
    
    async def search_exploits(self, cve_id: str = None, keyword: str = None) -> List[Dict]:
        """Search exploits from Exploit-DB"""
        exploits = []
        
        # Build search query
        query = cve_id or keyword
        if not query:
            return exploits
        
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "X-Requested-With": "XMLHttpRequest"
            }
            
            params = {
                "draw": "1",
                "columns[0][data]": "date_published",
                "columns[1][data]": "download",
                "columns[2][data]": "application_md5",
                "columns[3][data]": "verified",
                "columns[4][data]": "description",
                "order[0][column]": "0",
                "order[0][dir]": "desc",
                "search[value]": query,
                "search[regex]": "false",
                "start": "0",
                "length": "50"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.SEARCH_URL, params=params, headers=headers, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("data", []):
                            exploit = {
                                "id": item.get("id"),
                                "title": item.get("description", {}).get("title", "") if isinstance(item.get("description"), dict) else "",
                                "date": item.get("date_published", ""),
                                "type": item.get("type", {}).get("name", "") if isinstance(item.get("type"), dict) else "",
                                "platform": item.get("platform", {}).get("platform", "") if isinstance(item.get("platform"), dict) else "",
                                "author": item.get("author", {}).get("name", "") if isinstance(item.get("author"), dict) else "",
                                "verified": item.get("verified", 0) == 1,
                                "url": f"https://www.exploit-db.com/exploits/{item.get('id', '')}"
                            }
                            exploits.append(exploit)
        except Exception as e:
            print(f"[Exploit-DB Error] {e}")
        
        return exploits


class VulnersClient:
    """Vulners.com API client"""
    
    BASE_URL = "https://vulners.com/api/v3"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
    
    async def search_by_cpe(self, cpe: str) -> List[Dict]:
        """Search vulnerabilities by CPE"""
        if not self.api_key:
            return []
        
        try:
            url = f"{self.BASE_URL}/burp/software/"
            
            payload = {
                "software": cpe,
                "version": "",
                "type": "cpe",
                "apiKey": self.api_key
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", {}).get("search", [])
        except Exception as e:
            print(f"[Vulners Error] {e}")
        
        return []
    
    async def get_exploit_info(self, exploit_id: str) -> Optional[Dict]:
        """Get exploit information"""
        if not self.api_key:
            return None
        
        try:
            url = f"{self.BASE_URL}/document/id/"
            
            payload = {
                "id": exploit_id,
                "apiKey": self.api_key
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", {})
        except Exception as e:
            print(f"[Vulners Error] {e}")
        
        return None


class ZeroDayScanner:
    """
    Enterprise-grade Zero Day Scanner
    Integrates multiple vulnerability databases and exploit sources
    """
    
    VERSION = "2.0.0"
    
    def __init__(self, nvd_api_key: str = None, vulners_api_key: str = None):
        self.nvd_client = NVDClient(api_key=nvd_api_key)
        self.exploitdb_client = ExploitDBClient()
        self.vulners_client = VulnersClient(api_key=vulners_api_key)
        self.local_db = CVEDatabase()
        
        # Known vulnerable versions database
        self.known_vulnerable = self._load_known_vulnerable()
    
    def _load_known_vulnerable(self) -> Dict[str, List[Dict]]:
        """Load known vulnerable software versions"""
        return {
            # Apache
            "apache": [
                {"version_regex": r"2\.4\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49)",
                 "cves": ["CVE-2021-44790", "CVE-2021-44224", "CVE-2021-41773", "CVE-2021-42013"]},
            ],
            # Nginx
            "nginx": [
                {"version_regex": r"1\.(18|19|20)\.\d+",
                 "cves": ["CVE-2021-23017"]},
            ],
            # OpenSSH
            "openssh": [
                {"version_regex": r"[78]\.\d+",
                 "cves": ["CVE-2023-38408", "CVE-2021-41617", "CVE-2020-15778"]},
            ],
            # MySQL
            "mysql": [
                {"version_regex": r"5\.7\.\d+|8\.0\.\d+",
                 "cves": ["CVE-2021-22926", "CVE-2021-22895"]},
            ],
            # WordPress
            "wordpress": [
                {"version_regex": r"[456]\.\d+(\.\d+)?",
                 "cves": ["CVE-2022-21661", "CVE-2022-21662", "CVE-2022-21663"]},
            ],
            # PHP
            "php": [
                {"version_regex": r"7\.[34]\.\d+|8\.[012]\.\d+",
                 "cves": ["CVE-2022-31625", "CVE-2022-31626", "CVE-2021-21708"]},
            ],
            # Log4j
            "log4j": [
                {"version_regex": r"2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)(\.\d+)?",
                 "cves": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"]},
            ],
            # Spring Framework
            "spring": [
                {"version_regex": r"5\.[23]\.\d+",
                 "cves": ["CVE-2022-22965", "CVE-2022-22963"]},
            ],
            # Tomcat
            "tomcat": [
                {"version_regex": r"[89]\.\d+\.\d+|10\.\d+\.\d+",
                 "cves": ["CVE-2022-42252", "CVE-2022-34305"]},
            ],
            # Redis
            "redis": [
                {"version_regex": r"[567]\.\d+\.\d+",
                 "cves": ["CVE-2022-24736", "CVE-2022-24735"]},
            ],
            # Elasticsearch
            "elasticsearch": [
                {"version_regex": r"[78]\.\d+\.\d+",
                 "cves": ["CVE-2021-22144", "CVE-2021-22145"]},
            ],
            # Jenkins
            "jenkins": [
                {"version_regex": r"2\.\d+\.\d+",
                 "cves": ["CVE-2022-27198", "CVE-2022-27199"]},
            ],
        }
    
    async def scan_target(self, target: ScanTarget, deep_scan: bool = True) -> ScanResult:
        """
        Scan a target for known vulnerabilities
        
        Args:
            target: Target information (host, service, version)
            deep_scan: Whether to query online databases
        
        Returns:
            ScanResult with found vulnerabilities
        """
        result = ScanResult(
            target=target,
            scan_time=datetime.now().isoformat()
        )
        
        vulnerabilities = []
        
        # 1. Check local known vulnerable database
        local_vulns = self._check_known_vulnerable(target)
        vulnerabilities.extend(local_vulns)
        
        # 2. Check local CVE database
        if target.service or target.version:
            db_vulns = self.local_db.search_by_product(
                target.service or target.banner,
                target.version
            )
            vulnerabilities.extend(db_vulns)
        
        # 3. Check by CPE if available
        if target.cpe:
            cpe_vulns = self.local_db.search_by_cpe(target.cpe)
            vulnerabilities.extend(cpe_vulns)
        
        # 4. Deep scan - query online databases
        if deep_scan:
            online_vulns = await self._deep_scan(target)
            vulnerabilities.extend(online_vulns)
        
        # 5. Check for exploits
        vulnerabilities = await self._enrich_with_exploits(vulnerabilities)
        
        # Remove duplicates
        seen_cves = set()
        unique_vulns = []
        for v in vulnerabilities:
            if v.cve_id not in seen_cves:
                seen_cves.add(v.cve_id)
                unique_vulns.append(v)
        
        # Sort by CVSS score
        unique_vulns.sort(key=lambda x: x.cvss_score, reverse=True)
        
        # Update result
        result.vulnerabilities = unique_vulns
        result.total_cves = len(unique_vulns)
        result.critical_count = sum(1 for v in unique_vulns if v.severity == Severity.CRITICAL)
        result.high_count = sum(1 for v in unique_vulns if v.severity == Severity.HIGH)
        result.exploitable_count = sum(1 for v in unique_vulns if v.exploit_available in [ExploitAvailability.PUBLIC, ExploitAvailability.POC])
        
        return result
    
    def _check_known_vulnerable(self, target: ScanTarget) -> List[CVEEntry]:
        """Check against known vulnerable versions"""
        vulnerabilities = []
        
        service_lower = (target.service or target.banner or "").lower()
        version = target.version or ""
        
        for software, vulns in self.known_vulnerable.items():
            if software in service_lower:
                for vuln in vulns:
                    pattern = vuln.get("version_regex", "")
                    if pattern and re.search(pattern, version):
                        for cve_id in vuln.get("cves", []):
                            cve = CVEEntry(
                                cve_id=cve_id,
                                description=f"Known vulnerable version of {software}: {version}",
                                severity=Severity.HIGH,
                                cvss_score=8.0,
                                affected_products=[f"{software} {version}"]
                            )
                            vulnerabilities.append(cve)
        
        return vulnerabilities
    
    async def _deep_scan(self, target: ScanTarget) -> List[CVEEntry]:
        """Query online databases for vulnerabilities"""
        vulnerabilities = []
        
        # Build search keyword
        keyword = target.service or target.banner
        if target.version:
            keyword = f"{keyword} {target.version}"
        
        if not keyword:
            return vulnerabilities
        
        # Query NVD
        try:
            nvd_vulns = await self.nvd_client.search_cves(
                keyword=keyword,
                cvss_min=4.0,
                days_back=365
            )
            vulnerabilities.extend(nvd_vulns)
            
            # Store in local database
            for cve in nvd_vulns:
                self.local_db.add_cve(cve)
        except Exception as e:
            print(f"[Deep Scan] NVD query failed: {e}")
        
        # Query by CPE if available
        if target.cpe:
            try:
                cpe_vulns = await self.nvd_client.search_cves(cpe=target.cpe)
                vulnerabilities.extend(cpe_vulns)
            except Exception as e:
                print(f"[Deep Scan] CPE query failed: {e}")
        
        return vulnerabilities
    
    async def _enrich_with_exploits(self, vulnerabilities: List[CVEEntry]) -> List[CVEEntry]:
        """Enrich CVEs with exploit information"""
        for cve in vulnerabilities:
            if cve.exploit_available == ExploitAvailability.UNKNOWN:
                try:
                    exploits = await self.exploitdb_client.search_exploits(cve_id=cve.cve_id)
                    if exploits:
                        cve.exploit_available = ExploitAvailability.PUBLIC
                        cve.exploit_urls = [e.get("url", "") for e in exploits[:5]]
                except Exception:
                    pass
        
        return vulnerabilities
    
    async def scan_nmap_output(self, nmap_output: str) -> List[ScanResult]:
        """
        Parse nmap output and scan all discovered services
        
        Args:
            nmap_output: Raw nmap scan output
        
        Returns:
            List of ScanResults for each service
        """
        results = []
        
        # Parse nmap output
        targets = self._parse_nmap_output(nmap_output)
        
        # Scan each target
        for target in targets:
            result = await self.scan_target(target)
            results.append(result)
        
        return results
    
    def _parse_nmap_output(self, output: str) -> List[ScanTarget]:
        """Parse nmap output to extract targets"""
        targets = []
        
        current_host = ""
        
        for line in output.split("\n"):
            line = line.strip()
            
            # Get host
            host_match = re.search(r"Nmap scan report for (\S+)", line)
            if host_match:
                current_host = host_match.group(1)
                continue
            
            # Get port/service info
            port_match = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.+))?", line)
            if port_match and current_host:
                port = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                version = port_match.group(5) or ""
                
                if state == "open":
                    target = ScanTarget(
                        host=current_host,
                        port=port,
                        service=service,
                        version=version,
                        banner=f"{service} {version}".strip()
                    )
                    targets.append(target)
        
        return targets
    
    async def quick_scan(self, service: str, version: str = "") -> List[CVEEntry]:
        """
        Quick scan for a specific service/version combination
        
        Args:
            service: Service name (e.g., "apache", "nginx")
            version: Version string
        
        Returns:
            List of CVEEntry vulnerabilities
        """
        target = ScanTarget(
            host="",
            service=service,
            version=version,
            banner=f"{service} {version}".strip()
        )
        
        result = await self.scan_target(target, deep_scan=True)
        return result.vulnerabilities
    
    def get_critical_summary(self, results: List[ScanResult]) -> Dict:
        """Get summary of critical findings"""
        summary = {
            "total_hosts": len(results),
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "exploitable_vulnerabilities": 0,
            "top_cves": [],
            "affected_services": {}
        }
        
        all_vulns = []
        
        for result in results:
            summary["total_vulnerabilities"] += result.total_cves
            summary["critical_vulnerabilities"] += result.critical_count
            summary["high_vulnerabilities"] += result.high_count
            summary["exploitable_vulnerabilities"] += result.exploitable_count
            
            service = result.target.service or "unknown"
            if service not in summary["affected_services"]:
                summary["affected_services"][service] = 0
            summary["affected_services"][service] += result.total_cves
            
            all_vulns.extend(result.vulnerabilities)
        
        # Get top CVEs
        all_vulns.sort(key=lambda x: x.cvss_score, reverse=True)
        summary["top_cves"] = [v.to_dict() for v in all_vulns[:10]]
        
        return summary
    
    def close(self):
        """Close scanner and release resources"""
        self.local_db.close()


# Global scanner instance
_scanner: Optional[ZeroDayScanner] = None


def get_scanner(nvd_api_key: str = None, vulners_api_key: str = None) -> ZeroDayScanner:
    """Get or create global scanner instance"""
    global _scanner
    if _scanner is None:
        _scanner = ZeroDayScanner(nvd_api_key=nvd_api_key, vulners_api_key=vulners_api_key)
    return _scanner


# Convenience functions
async def scan_service(service: str, version: str = "") -> List[CVEEntry]:
    """Quick scan a service"""
    scanner = get_scanner()
    return await scanner.quick_scan(service, version)


async def scan_nmap_results(nmap_output: str) -> List[ScanResult]:
    """Scan from nmap output"""
    scanner = get_scanner()
    return await scanner.scan_nmap_output(nmap_output)
