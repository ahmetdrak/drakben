"""
DRAKBEN Autonomous Solver
Author: @drak_ben
Description: 5 modules for error analysis, auto-healing, and intelligent retry
"""

import re
import time
import subprocess
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum


class ErrorCategory(Enum):
    """Categories of errors"""
    MISSING_TOOL = "missing_tool"
    PERMISSION = "permission"
    NETWORK = "network"
    TIMEOUT = "timeout"
    SYNTAX = "syntax"
    DEPENDENCY = "dependency"
    UNKNOWN = "unknown"


@dataclass
class ErrorInfo:
    """Detailed error information"""
    category: ErrorCategory
    message: str
    command: str
    suggestions: List[str]
    auto_fixable: bool
    severity: str  # low, medium, high, critical


@dataclass
class HealingAction:
    """Action to heal an error"""
    action_type: str  # install, retry, escalate, modify
    command: str
    description: str
    risk_level: str  # safe, moderate, risky


# ====================
# MODULE 1: ErrorAnalyzer
# ====================
class ErrorAnalyzer:
    """Analyzes errors and categorizes them intelligently"""
    
    def __init__(self):
        self.error_patterns = {
            ErrorCategory.MISSING_TOOL: [
                r"command not found",
                r"not recognized as an internal or external command",
                r"No such file or directory",
                r"is not installed"
            ],
            ErrorCategory.PERMISSION: [
                r"permission denied",
                r"access denied",
                r"operation not permitted",
                r"you must be root",
                r"requires administrator"
            ],
            ErrorCategory.NETWORK: [
                r"no route to host",
                r"network unreachable",
                r"connection refused",
                r"connection timed out",
                r"failed to resolve"
            ],
            ErrorCategory.TIMEOUT: [
                r"timeout",
                r"timed out",
                r"deadline exceeded"
            ],
            ErrorCategory.SYNTAX: [
                r"syntax error",
                r"invalid syntax",
                r"parse error",
                r"unexpected token"
            ],
            ErrorCategory.DEPENDENCY: [
                r"module not found",
                r"cannot import",
                r"no module named",
                r"missing dependency"
            ]
        }
    
    def analyze_error(self, stderr: str, command: str) -> ErrorInfo:
        """Analyze error and provide detailed information"""
        if not stderr:
            return ErrorInfo(
                category=ErrorCategory.UNKNOWN,
                message="Unknown error",
                command=command,
                suggestions=[],
                auto_fixable=False,
                severity="low"
            )
        
        # Detect category
        category = self._detect_category(stderr)
        
        # Extract clean message
        message = self._extract_message(stderr)
        
        # Generate suggestions
        suggestions = self._generate_suggestions(category, message, command)
        
        # Determine if auto-fixable
        auto_fixable = category in [
            ErrorCategory.MISSING_TOOL,
            ErrorCategory.DEPENDENCY,
            ErrorCategory.TIMEOUT
        ]
        
        # Assess severity
        severity = self._assess_severity(category)
        
        return ErrorInfo(
            category=category,
            message=message,
            command=command,
            suggestions=suggestions,
            auto_fixable=auto_fixable,
            severity=severity
        )
    
    def _detect_category(self, stderr: str) -> ErrorCategory:
        """Detect error category from stderr"""
        stderr_lower = stderr.lower()
        
        for category, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, stderr_lower):
                    return category
        
        return ErrorCategory.UNKNOWN
    
    def _extract_message(self, stderr: str) -> str:
        """Extract clean error message"""
        lines = stderr.strip().split('\n')
        
        # Find first meaningful line
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('Warning'):
                return line
        
        return stderr[:200]  # Fallback: first 200 chars
    
    def _generate_suggestions(self, category: ErrorCategory, message: str, command: str) -> List[str]:
        """Generate helpful suggestions"""
        suggestions = []
        
        if category == ErrorCategory.MISSING_TOOL:
            tool = self._extract_tool_name(command)
            if tool:
                suggestions.append(f"Install {tool}: sudo apt install {tool} -y")
                suggestions.append(f"Or try: which {tool}")
        
        elif category == ErrorCategory.PERMISSION:
            suggestions.append("Try with sudo: sudo " + command)
            suggestions.append("Check file permissions: ls -la")
            suggestions.append("Check if running as root: whoami")
        
        elif category == ErrorCategory.NETWORK:
            suggestions.append("Check network connectivity: ping 8.8.8.8")
            suggestions.append("Check target is reachable: ping <target>")
            suggestions.append("Try with different timeout")
        
        elif category == ErrorCategory.TIMEOUT:
            suggestions.append("Increase timeout value")
            suggestions.append("Check if target is responsive")
            suggestions.append("Try with faster scan options")
        
        elif category == ErrorCategory.DEPENDENCY:
            module = self._extract_module_name(message)
            if module:
                suggestions.append(f"Install module: pip install {module}")
        
        return suggestions
    
    def _extract_tool_name(self, command: str) -> Optional[str]:
        """Extract tool name from command"""
        parts = command.strip().split()
        if parts:
            tool = parts[0]
            # Remove sudo if present
            if tool == "sudo" and len(parts) > 1:
                tool = parts[1]
            return tool
        return None
    
    def _extract_module_name(self, message: str) -> Optional[str]:
        """Extract Python module name from error"""
        match = re.search(r"no module named ['\"]?(\w+)['\"]?", message, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
    
    def _assess_severity(self, category: ErrorCategory) -> str:
        """Assess error severity"""
        severity_map = {
            ErrorCategory.MISSING_TOOL: "medium",
            ErrorCategory.PERMISSION: "high",
            ErrorCategory.NETWORK: "medium",
            ErrorCategory.TIMEOUT: "low",
            ErrorCategory.SYNTAX: "high",
            ErrorCategory.DEPENDENCY: "medium",
            ErrorCategory.UNKNOWN: "low"
        }
        return severity_map.get(category, "low")


# ====================
# MODULE 2: AutoHealer
# ====================
class AutoHealer:
    """Automatically heals common errors"""
    
    def __init__(self, system_info: Dict):
        self.system_info = system_info
        self.healing_history: List[HealingAction] = []
    
    def heal(self, error_info: ErrorInfo) -> Optional[HealingAction]:
        """Attempt to heal error automatically"""
        
        if not error_info.auto_fixable:
            return None
        
        healing_action = None
        
        if error_info.category == ErrorCategory.MISSING_TOOL:
            healing_action = self._heal_missing_tool(error_info)
        
        elif error_info.category == ErrorCategory.DEPENDENCY:
            healing_action = self._heal_missing_dependency(error_info)
        
        elif error_info.category == ErrorCategory.TIMEOUT:
            healing_action = self._heal_timeout(error_info)
        
        if healing_action:
            self.healing_history.append(healing_action)
        
        return healing_action
    
    def _heal_missing_tool(self, error_info: ErrorInfo) -> Optional[HealingAction]:
        """Heal missing tool error"""
        # Extract tool name
        match = re.search(r"(\w+).*command not found", error_info.message, re.IGNORECASE)
        if not match:
            # Try from command
            parts = error_info.command.strip().split()
            if parts:
                tool = parts[0]
                if tool == "sudo" and len(parts) > 1:
                    tool = parts[1]
                match = (tool,)
        
        if match:
            tool = match[0] if isinstance(match, tuple) else match.group(1)
            
            # Generate install command
            if self.system_info.get("os") == "Windows":
                # Windows: suggest manual installation
                return HealingAction(
                    action_type="install",
                    command=f"# Install {tool} manually on Windows",
                    description=f"Please install {tool} manually",
                    risk_level="safe"
                )
            else:
                # Linux: use apt/yum
                install_cmd = f"sudo apt install {tool} -y || sudo yum install {tool} -y"
                return HealingAction(
                    action_type="install",
                    command=install_cmd,
                    description=f"Install missing tool: {tool}",
                    risk_level="safe"
                )
        
        return None
    
    def _heal_missing_dependency(self, error_info: ErrorInfo) -> Optional[HealingAction]:
        """Heal missing Python dependency"""
        match = re.search(r"no module named ['\"]?(\w+)['\"]?", error_info.message, re.IGNORECASE)
        if match:
            module = match.group(1)
            return HealingAction(
                action_type="install",
                command=f"pip install {module}",
                description=f"Install missing Python module: {module}",
                risk_level="safe"
            )
        return None
    
    def _heal_timeout(self, error_info: ErrorInfo) -> Optional[HealingAction]:
        """Heal timeout error by modifying command"""
        # Increase timeout or use faster options
        modified_cmd = error_info.command
        
        if "nmap" in modified_cmd:
            if "-T4" in modified_cmd:
                modified_cmd = modified_cmd.replace("-T4", "-T5")
            else:
                modified_cmd += " -T5"
        
        if modified_cmd != error_info.command:
            return HealingAction(
                action_type="modify",
                command=modified_cmd,
                description="Retry with faster timing options",
                risk_level="safe"
            )
        
        return None
    
    def execute_healing(self, action: HealingAction, executor_func: Callable) -> bool:
        """Execute healing action"""
        try:
            result = executor_func(action.command)
            return result.get("success", False)
        except Exception:
            return False


# ====================
# MODULE 3: DependencyResolver
# ====================
class DependencyResolver:
    """Resolves and installs missing dependencies"""
    
    def __init__(self):
        self.tool_packages = {
            # Tool -> Package mapping
            "nmap": "nmap",
            "sqlmap": "sqlmap",
            "nikto": "nikto",
            "gobuster": "gobuster",
            "hydra": "hydra",
            "john": "john",
            "hashcat": "hashcat",
            "aircrack-ng": "aircrack-ng",
            "msfconsole": "metasploit-framework",
            "msfvenom": "metasploit-framework",
            "netcat": "netcat-traditional",
            "nc": "netcat-traditional",
            "curl": "curl",
            "wget": "wget",
            "git": "git"
        }
    
    def resolve_tool(self, tool_name: str) -> Optional[str]:
        """Get package name for tool"""
        return self.tool_packages.get(tool_name)
    
    def generate_install_command(self, tool_name: str, os_type: str = "Linux") -> Optional[str]:
        """Generate installation command"""
        package = self.resolve_tool(tool_name)
        if not package:
            package = tool_name  # Try tool name as package name
        
        if os_type == "Linux":
            return f"sudo apt install {package} -y || sudo yum install {package} -y"
        elif os_type == "Darwin":  # macOS
            return f"brew install {package}"
        else:
            return None  # Windows requires manual
    
    def check_and_install(self, tool_name: str, os_type: str, executor_func: Callable) -> bool:
        """Check if tool exists, install if missing"""
        # Check if already installed
        check_cmd = f"which {tool_name}"
        result = executor_func(check_cmd)
        
        if result.get("success"):
            return True  # Already installed
        
        # Try to install
        install_cmd = self.generate_install_command(tool_name, os_type)
        if install_cmd:
            install_result = executor_func(install_cmd)
            return install_result.get("success", False)
        
        return False
    
    def resolve_all_dependencies(self, required_tools: List[str], os_type: str) -> Dict:
        """Generate install plan for all dependencies"""
        plan = {
            "tools": required_tools,
            "commands": [],
            "resolvable": []
        }
        
        for tool in required_tools:
            cmd = self.generate_install_command(tool, os_type)
            if cmd:
                plan["commands"].append(cmd)
                plan["resolvable"].append(tool)
        
        return plan


# ====================
# MODULE 4: RetryStrategy
# ====================
class RetryStrategy:
    """Intelligent retry with exponential backoff"""
    
    def __init__(self):
        self.max_retries = 3
        self.base_delay = 1.0
        self.backoff_multiplier = 2.0
        self.retry_history: Dict[str, int] = {}
    
    def should_retry(self, command: str, error_info: ErrorInfo, attempt: int) -> bool:
        """Determine if command should be retried"""
        if attempt >= self.max_retries:
            return False
        
        # Don't retry syntax errors
        if error_info.category == ErrorCategory.SYNTAX:
            return False
        
        # Retry network and timeout errors
        if error_info.category in [ErrorCategory.NETWORK, ErrorCategory.TIMEOUT]:
            return True
        
        # Retry if healing was attempted
        if error_info.auto_fixable:
            return True
        
        return False
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay before retry"""
        return self.base_delay * (self.backoff_multiplier ** attempt)
    
    def execute_with_retry(
        self,
        command: str,
        executor_func: Callable,
        analyzer_func: Callable,
        healer_func: Optional[Callable] = None
    ) -> Dict:
        """Execute command with intelligent retry"""
        
        for attempt in range(self.max_retries):
            # Execute
            result = executor_func(command)
            
            if result.get("success"):
                return {
                    "success": True,
                    "result": result,
                    "attempts": attempt + 1
                }
            
            # Analyze error
            error_info = analyzer_func(result.get("stderr", ""), command)
            
            # Check if should retry
            if not self.should_retry(command, error_info, attempt):
                return {
                    "success": False,
                    "result": result,
                    "error_info": error_info,
                    "attempts": attempt + 1
                }
            
            # Try healing
            if healer_func and error_info.auto_fixable:
                healing_action = healer_func(error_info)
                if healing_action:
                    # Execute healing
                    heal_result = executor_func(healing_action.command)
                    if not heal_result.get("success"):
                        # Healing failed, might still retry
                        pass
            
            # Wait before retry
            if attempt < self.max_retries - 1:
                delay = self.get_delay(attempt)
                time.sleep(delay)
        
        return {
            "success": False,
            "result": result,
            "error_info": error_info,
            "attempts": self.max_retries
        }


# ====================
# MODULE 5: FallbackEngine
# ====================
class FallbackEngine:
    """Provides alternative approaches when primary fails"""
    
    def __init__(self):
        self.fallback_map = {
            # Tool -> Alternative tools
            "nmap": ["masscan", "rustscan", "nc"],
            "sqlmap": ["manual SQL injection"],
            "gobuster": ["dirb", "ffuf", "wfuzz"],
            "nikto": ["manual web scan", "curl"],
            "hydra": ["medusa", "ncrack"]
        }
        
        self.command_alternatives = {
            # Command patterns -> Alternative commands
            "nmap -sV": "nmap -sT",  # Version scan -> TCP connect
            "nmap -A": "nmap -sV -sC",  # Aggressive -> Version + Scripts
            "gobuster dir": "dirb",
        }
    
    def get_fallback_tools(self, tool: str) -> List[str]:
        """Get alternative tools"""
        return self.fallback_map.get(tool, [])
    
    def get_fallback_command(self, original_command: str) -> Optional[str]:
        """Generate fallback command"""
        
        # Check command alternatives
        for pattern, alternative in self.command_alternatives.items():
            if pattern in original_command:
                return original_command.replace(pattern, alternative)
        
        # Tool-specific fallbacks
        if "nmap" in original_command:
            # Fallback to simpler scan
            if "-A" in original_command:
                return original_command.replace("-A", "-sV")
            elif "-sV" in original_command:
                return original_command.replace("-sV", "-sT")
        
        return None
    
    def suggest_manual_approach(self, tool: str, target: str) -> str:
        """Suggest manual approach when tools fail"""
        suggestions = {
            "nmap": f"Manual approach: Try nc -zv {target} 1-1000 for port scanning",
            "sqlmap": f"Manual approach: Test SQL injection manually with curl",
            "gobuster": f"Manual approach: Try common directories manually: /admin, /login, /wp-admin",
        }
        return suggestions.get(tool, "No manual approach available")


# ====================
# UNIFIED FACADE
# ====================
class AutonomousSolver:
    """Main facade combining all 5 solver modules"""
    
    def __init__(self, system_info: Dict):
        self.analyzer = ErrorAnalyzer()
        self.healer = AutoHealer(system_info)
        self.resolver = DependencyResolver()
        self.retry = RetryStrategy()
        self.fallback = FallbackEngine()
        self.system_info = system_info
    
    def solve(self, command: str, error_output: str, executor_func: Callable) -> Dict:
        """Autonomous problem solving"""
        
        # 1. Analyze error
        error_info = self.analyzer.analyze_error(error_output, command)
        
        # 2. Try healing
        healing_action = self.healer.heal(error_info)
        
        solution = {
            "error_info": error_info,
            "healing_action": healing_action,
            "solved": False,
            "fallback_command": None
        }
        
        # 3. Execute healing if available
        if healing_action:
            healed = self.healer.execute_healing(healing_action, executor_func)
            if healed:
                solution["solved"] = True
                return solution
        
        # 4. Try fallback command
        fallback_cmd = self.fallback.get_fallback_command(command)
        if fallback_cmd:
            solution["fallback_command"] = fallback_cmd
        
        return solution
    
    def solve_with_retry(self, command: str, executor_func: Callable) -> Dict:
        """Solve with intelligent retry"""
        return self.retry.execute_with_retry(
            command=command,
            executor_func=executor_func,
            analyzer_func=lambda stderr, cmd: self.analyzer.analyze_error(stderr, cmd),
            healer_func=lambda error_info: self.healer.heal(error_info)
        )
    
    def get_solver_summary(self) -> Dict:
        """Get summary of solver activities"""
        return {
            "total_healings": len(self.healer.healing_history),
            "healing_actions": [
                {
                    "type": action.action_type,
                    "description": action.description,
                    "risk": action.risk_level
                }
                for action in self.healer.healing_history
            ]
        }
