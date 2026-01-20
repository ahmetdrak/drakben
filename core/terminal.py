# core/terminal.py
# Safe Terminal Command Executor with Approval System

import subprocess
import os
import datetime
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass


@dataclass
class CommandResult:
    """Command execution result"""
    command: str
    success: bool
    output: str
    error: str
    exit_code: int
    execution_time: float


class TerminalExecutor:
    """Execute terminal commands with approval system"""
    
    def __init__(self, log_dir: str = "logs", auto_approve: bool = False):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.auto_approve = auto_approve
        self.approved_once = False
        self.command_history = []
        
        # Dangerous command patterns (require approval)
        self.dangerous_patterns = [
            "rm -rf", "dd if=", "mkfs", ":(){ :|:& };:",  # Destructive
            "chmod 777", "chmod -R 777",  # Permission changes
            "> /dev/", "format", "fdisk",  # Disk operations
        ]
    
    def needs_approval(self, command: str) -> bool:
        """Check if command needs user approval"""
        # First command always needs approval
        if not self.approved_once:
            return True
        
        # Check for dangerous patterns
        cmd_lower = command.lower()
        for pattern in self.dangerous_patterns:
            if pattern.lower() in cmd_lower:
                return True
        
        return False
    
    def ask_approval(self, command: str, lang: str = "tr") -> bool:
        """Ask user for approval to run command"""
        if lang == "tr":
            print(f"\n🔍 Çalıştırılacak komut:")
            print(f"   {command}")
            response = input("\n⚠️  Bu komutu çalıştırmak istiyor musunuz? [e/H]: ").strip().lower()
            approved = response in ["e", "evet", "y", "yes"]
        else:
            print(f"\n🔍 Command to execute:")
            print(f"   {command}")
            response = input("\n⚠️  Do you want to run this command? [y/N]: ").strip().lower()
            approved = response in ["y", "yes", "e", "evet"]
        
        if approved and not self.approved_once:
            self.approved_once = True
            if lang == "tr":
                print("\n✅ Onay alındı. Bundan sonra benzer komutlar otomatik çalışacak.")
            else:
                print("\n✅ Approved. Similar commands will run automatically from now on.")
        
        return approved
    
    def run_command(self, command: str, timeout: int = 30, lang: str = "tr") -> CommandResult:
        """
        Execute a shell command safely
        
        Args:
            command: Shell command to execute
            timeout: Command timeout in seconds
            lang: Language for approval prompt
            
        Returns:
            CommandResult object
        """
        import time
        start_time = time.time()
        
        # Check if approval needed
        if self.needs_approval(command):
            if not self.auto_approve:
                if not self.ask_approval(command, lang):
                    return CommandResult(
                        command=command,
                        success=False,
                        output="",
                        error="Command rejected by user",
                        exit_code=-1,
                        execution_time=0.0
                    )
        
        try:
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            
            output = result.stdout.strip()
            error = result.stderr.strip()
            success = result.returncode == 0
            
            # Log command
            self._log_command(command, output, error, success)
            
            # Add to history
            self.command_history.append({
                "command": command,
                "success": success,
                "timestamp": datetime.datetime.now().isoformat()
            })
            
            return CommandResult(
                command=command,
                success=success,
                output=output,
                error=error,
                exit_code=result.returncode,
                execution_time=execution_time
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            error_msg = f"Command timed out after {timeout} seconds"
            self._log_command(command, "", error_msg, False)
            
            return CommandResult(
                command=command,
                success=False,
                output="",
                error=error_msg,
                exit_code=-1,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Execution error: {str(e)}"
            self._log_command(command, "", error_msg, False)
            
            return CommandResult(
                command=command,
                success=False,
                output="",
                error=error_msg,
                exit_code=-1,
                execution_time=execution_time
            )
    
    def _log_command(self, command: str, output: str, error: str, success: bool):
        """Log command execution to file"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            log_file = self.log_dir / f"{timestamp}.log"
            
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Command: {command}\n")
                f.write(f"Success: {success}\n")
                f.write(f"\n--- OUTPUT ---\n{output}\n")
                if error:
                    f.write(f"\n--- ERROR ---\n{error}\n")
        except Exception as e:
            print(f"⚠️  Log error: {e}")
    
    def get_history(self, limit: int = 10) -> list:
        """Get recent command history"""
        return self.command_history[-limit:]
    
    def clear_history(self):
        """Clear command history"""
        self.command_history = []
    
    def check_tool_available(self, tool: str) -> bool:
        """Check if a tool/command is available"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(
                    f"where {tool}",
                    shell=True,
                    capture_output=True,
                    text=True
                )
            else:  # Linux/Mac
                result = subprocess.run(
                    f"which {tool}",
                    shell=True,
                    capture_output=True,
                    text=True
                )
            return result.returncode == 0
        except:
            return False
    
    def get_available_tools(self) -> dict:
        """Get list of available pentest tools"""
        tools = {
            "nmap": "Network scanner",
            "nikto": "Web scanner",
            "sqlmap": "SQL injection",
            "gobuster": "Directory brute force",
            "hydra": "Password cracker",
            "metasploit": "Exploitation framework",
            "john": "Password cracker",
            "hashcat": "Password cracker",
            "burpsuite": "Web proxy",
            "wireshark": "Network analyzer"
        }
        
        available = {}
        for tool, description in tools.items():
            if self.check_tool_available(tool):
                available[tool] = description
        
        return available
