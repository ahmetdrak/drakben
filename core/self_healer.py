# core/self_healer.py
# DRAKBEN Self-Healing Module
# Extracted from RefactoredDrakbenAgent to improve modularity

import logging
import time
from typing import Any, Dict, Optional, Tuple, Callable

from rich.console import Console

logger = logging.getLogger(__name__)


class SelfHealer:
    """
    Handles automatic error diagnosis and recovery (Self-Healing).
    Detaches healing logic from the main agent class.
    """

    MAX_SELF_HEAL_PER_TOOL = 2

    def __init__(self, agent):
        """
        Initialize with reference to the main agent to access its components.

        Args:
            agent: Reference to RefactoredDrakbenAgent instance
                   (Needs access to: executor, tool_selector, brain, console, _install_tool)
        """
        self.agent = agent
        self.console = Console()
        self._self_heal_attempts: Dict[str, int] = {}

    def handle_tool_failure(
        self, tool_name: str, command: str, result, args: Dict,
        format_result_callback: Callable
    ) -> Dict:
        """
        Main entry point for healing a failed tool execution.

        Args:
            tool_name: Name of the failed tool
            command: The exact command line that failed
            result: The ExecutionResult object
            args: Original arguments passed to the tool
            format_result_callback: Function to format the final result
        """
        # Check limits
        heal_key = f"{tool_name}:{command[:50]}"
        current_attempts = self._self_heal_attempts.get(heal_key, 0)

        if current_attempts >= self.MAX_SELF_HEAL_PER_TOOL:
            self.console.print(
                f"⚠️ {tool_name} için self-heal limiti aşıldı ({current_attempts}/{self.MAX_SELF_HEAL_PER_TOOL})", style="yellow")
            # Record failure in agent's tool selector
            if hasattr(self.agent, "tool_selector"):
                self.agent.tool_selector.record_tool_failure(tool_name)
            return format_result_callback(result, args)

        # Prepare content for diagnosis
        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        combined_output = f"{stdout_str}\n{stderr_str}".lower()

        # Diagnose
        error_diagnosis = self._diagnose_error(
            combined_output, result.exit_code)

        if error_diagnosis["type"] != "unknown":
            self.console.print(
                f"🔍 Hata teşhisi: {error_diagnosis['type_tr']}",
                style="yellow")

        # Increment counter
        self._self_heal_attempts[heal_key] = current_attempts + 1
        self.console.print(
            f"🔧 Self-heal denemesi: {current_attempts + 1}/{self.MAX_SELF_HEAL_PER_TOOL}", style="dim")

        # Attempt healing
        healed, retry_result = self._apply_error_specific_healing(
            error_diagnosis, tool_name, command, combined_output
        )

        # Finalize
        if healed and retry_result:
            self.console.print(
                "✅ Hata otomatik olarak düzeltildi!",
                style="green")
            return format_result_callback(retry_result, args)

        # If not healed
        if hasattr(self.agent, "tool_selector"):
            self.agent.tool_selector.record_tool_failure(tool_name)

        return format_result_callback(result, args)

    def _apply_error_specific_healing(
        self, error_diagnosis: Dict[str, Any], tool_name: str, command: str,
        combined_output: str
    ) -> Tuple[bool, Optional[Any]]:
        """Dispatch to specific healing methods"""
        error_type = error_diagnosis["type"]

        healing_map = {
            "missing_tool": self._heal_missing_tool,
            "permission_denied": self._heal_permission_denied,
            "python_module_missing": self._heal_python_module_missing,
            "connection_error": self._heal_connection_error,
            "timeout": self._heal_timeout,
            "library_missing": self._heal_library_missing,
            "rate_limit": self._heal_rate_limit,
            "port_in_use": self._heal_port_in_use,
            "disk_full": self._heal_disk_full,
            "firewall_blocked": self._heal_firewall_blocked,
            "database_error": self._heal_database_error,
        }

        if error_type in healing_map:
            return healing_map[error_type](tool_name, command, error_diagnosis)
        elif error_type == "unknown" and getattr(self.agent, "brain", None):
            return self._llm_assisted_error_fix(
                tool_name, command, combined_output)

        return False, None

    # ==================== HEALING STRATEGIES ====================

    def _heal_missing_tool(self,
                           tool_name: str,
                           command: str,
                           error_diagnosis: Dict) -> Tuple[bool,
                                                           Optional[Any]]:
        """Heal missing tool error by auto-installing or synthesizing code"""

        # 1. Try standard installation
        if hasattr(
                self.agent,
                "_install_tool") and self.agent._install_tool(tool_name):
            self.console.print(
                f"🔄 {tool_name} yüklendi, yeniden deneniyor...",
                style="cyan")
            retry_result = self.agent.executor.terminal.execute(
                command, timeout=300)
            return retry_result.exit_code == 0, retry_result

        # 2. If installation failed, try to write own tool!
        if hasattr(self.agent, "coder"):
            self.console.print(
                f"🧬 Takım yüklenemedi. Yapay zeka ile {tool_name} klonlanıyor...",
                style="magenta")

            # Create synthetic tool
            result = self.agent.coder.create_alternative_tool(
                failed_tool=tool_name,
                action="scan" if "scan" in command else "exploit",  # Infer action
                target="unknown",  # We can't easily extract target here without parsing command
                error_message="Tool missing and not installable"
            )

            if result.get("success"):
                new_tool_name = result["tool_name"]
                self.console.print(
                    f"✨ Kendi aracımızı yazdık: {new_tool_name}",
                    style="green")

                # Execute the new tool immediately (mocking the command execution)
                # Note: In a real scenario, we would need to map the original arguments
                # to the new tool's format. Here we just return success to indicate healing worked
                # so the planner can perhaps re-schedule or use the new tool.

                # We can't retry the ORIGINAL command, but we healed the
                # capability gap.
                return False, None
                # Returning False here to stop the infinite retry of the bad command.
                # The planner should detect the new tool availability in next
                # step.

        return False, None

    def _heal_permission_denied(self,
                                tool_name: str,
                                command: str,
                                error_diagnosis: Dict) -> Tuple[bool,
                                                                Optional[Any]]:
        import platform
        if platform.system().lower() != "windows" and not command.startswith("sudo"):
            self.console.print(
                "🔐 İzin hatası - sudo ile deneniyor...",
                style="yellow")
            # Use -n to prevent blocking on password prompt
            sudo_cmd = f"sudo -n {command}"
            retry_result = self.agent.executor.terminal.execute(
                sudo_cmd, timeout=300)
            return retry_result.exit_code == 0, retry_result
        return False, None

    def _heal_python_module_missing(self,
                                    tool_name: str,
                                    command: str,
                                    error_diagnosis: Dict) -> Tuple[bool,
                                                                    Optional[Any]]:
        module_name = error_diagnosis.get("module")
        if module_name:
            self.console.print(
                f"📦 Python modülü eksik: {module_name} - yükleniyor...",
                style="yellow")
            pip_cmd = f"pip install {module_name}"
            pip_result = self.agent.executor.terminal.execute(
                pip_cmd, timeout=120)
            if pip_result.exit_code == 0:
                self.console.print(
                    f"✅ {module_name} yüklendi, yeniden deneniyor...",
                    style="green")
                retry_result = self.agent.executor.terminal.execute(
                    command, timeout=300)
                return retry_result.exit_code == 0, retry_result
        return False, None

    def _heal_connection_error(self,
                               tool_name: str,
                               command: str,
                               error_diagnosis: Dict) -> Tuple[bool,
                                                               Optional[Any]]:
        self.console.print(
            "🌐 Bağlantı hatası - 3 saniye bekleyip yeniden deneniyor...",
            style="yellow")
        time.sleep(3)
        retry_result = self.agent.executor.terminal.execute(
            command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_timeout(self, tool_name: str, command: str,
                      error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        self.console.print(
            "⏱️ Zaman aşımı - daha uzun timeout ile deneniyor...",
            style="yellow")
        retry_result = self.agent.executor.terminal.execute(
            command, timeout=600)
        return retry_result.exit_code == 0, retry_result

    def _heal_library_missing(self,
                              tool_name: str,
                              command: str,
                              error_diagnosis: Dict) -> Tuple[bool,
                                                              Optional[Any]]:
        library = error_diagnosis.get("library", "")
        if not library:
            return False, None

        self.console.print(
            f"📚 Kütüphane eksik: {library} - yükleniyor...",
            style="yellow")
        import platform
        system = platform.system().lower()
        lib_pkg_map = {
            "libssl": "openssl" if system == "darwin" else "libssl-dev",
            "libcrypto": "openssl" if system == "darwin" else "libssl-dev",
            "libffi": "libffi-dev",
            "libpython": "python3-dev",
        }
        pkg = lib_pkg_map.get(library.split(".")[0], library)

        install_cmd = ""
        if system == "linux":
            install_cmd = f"sudo apt-get install -y {pkg}"
        elif system == "darwin":
            install_cmd = f"brew install {pkg}"
        else:
            return False, None

        install_result = self.agent.executor.terminal.execute(
            install_cmd, timeout=180)
        if install_result.exit_code == 0:
            retry_result = self.agent.executor.terminal.execute(
                command, timeout=300)
            return retry_result.exit_code == 0, retry_result
        return False, None

    def _heal_rate_limit(self, tool_name: str, command: str,
                         error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        self.console.print(
            "⏳ İstek limiti - 30 saniye bekleniyor...",
            style="yellow")
        time.sleep(30)
        retry_result = self.agent.executor.terminal.execute(
            command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_port_in_use(self,
                          tool_name: str,
                          command: str,
                          error_diagnosis: Dict) -> Tuple[bool,
                                                          Optional[Any]]:
        port = error_diagnosis.get("port")
        if not port:
            return False, None

        self.console.print(
            f"🔌 Port {port} kullanımda - işlem sonlandırılmaya çalışılıyor...",
            style="yellow")
        import platform
        if platform.system().lower() != "windows":
            kill_cmd = f"sudo fuser -k {port}/tcp 2>/dev/null || sudo lsof -ti:{port} | xargs -r sudo kill -9"
        else:
            kill_cmd = f"for /f \"tokens=5\" %a in ('netstat -aon ^| find \":{port}\"') do taskkill /F /PID %a"

        self.agent.executor.terminal.execute(kill_cmd, timeout=30)
        time.sleep(2)
        retry_result = self.agent.executor.terminal.execute(
            command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_disk_full(self, tool_name: str, command: str,
                        error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        self.console.print(
            "💾 Disk alanı yetersiz - temizlik yapılıyor...",
            style="yellow")
        import platform
        if platform.system().lower() != "windows":
            cleanup_cmd = "sudo apt-get clean 2>/dev/null; rm -rf /tmp/* 2>/dev/null; rm -rf ~/.cache/* 2>/dev/null"
        else:
            cleanup_cmd = "del /q/f/s %TEMP%\\* 2>nul"

        self.agent.executor.terminal.execute(cleanup_cmd, timeout=60)
        retry_result = self.agent.executor.terminal.execute(
            command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_firewall_blocked(self,
                               tool_name: str,
                               command: str,
                               error_diagnosis: Dict) -> Tuple[bool,
                                                               Optional[Any]]:
        self.console.print(
            "🛡️ Güvenlik duvarı engeli - 10 saniye bekleyip stealth modda deneniyor...",
            style="yellow")
        time.sleep(10)
        if "--rate" in command or "-T" in command:
            slower_cmd = command.replace("-T4", "-T1").replace("-T5", "-T2")
            retry_result = self.agent.executor.terminal.execute(
                slower_cmd, timeout=600)
        else:
            retry_result = self.agent.executor.terminal.execute(
                command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_database_error(self,
                             tool_name: str,
                             command: str,
                             error_diagnosis: Dict) -> Tuple[bool,
                                                             Optional[Any]]:
        self.console.print(
            "🗄️ Veritabanı hatası - düzeltme deneniyor...",
            style="yellow")
        import glob
        import os
        for lock_file in glob.glob("*.db-journal") + \
                glob.glob("*.db-wal") + glob.glob("*.db-shm"):
            try:
                os.remove(lock_file)
                self.console.print(f"  🗑️ {lock_file} silindi", style="dim")
            except OSError as e:
                logger.debug(f"Could not remove lock file {lock_file}: {e}")
        retry_result = self.agent.executor.terminal.execute(
            command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _llm_assisted_error_fix(
            self,
            tool_name: str,
            command: str,
            error_output: str) -> tuple:
        """Use LLM to diagnose unknown errors via the agent's brain"""
        try:
            self.console.print(
                "🤖 LLM ile hata analizi yapılıyor...",
                style="dim")

            prompt = f"""Analyze this command execution error and suggest a fix:

Command: {command}
Tool: {tool_name}
Error Output: {error_output[:1000]}

Respond in JSON:
{"error_type": "brief error classification",
    "root_cause": "what caused this error",
    "fix_command": "shell command to fix (or null if not fixable)",
    "should_retry": true/false,
    "explanation": "brief explanation in Turkish"
} """

            result = self.agent.brain.llm_client.query(prompt, timeout=15)

            # Try to parse JSON response
            import json
            import re
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                fix_data = json.loads(json_match.group())

                self.console.print(
                    f"🔍 LLM Analizi: {
                        fix_data.get(
                            'explanation',
                            'Analiz tamamlandı')}",
                    style="dim")

                # Apply fix command if provided
                fix_cmd = fix_data.get("fix_command")
                if fix_cmd and fix_cmd != "null":
                    self.console.print(
                        f"🔧 Düzeltme uygulanıyor: {fix_cmd}", style="yellow")
                    fix_result = self.agent.executor.terminal.execute(
                        fix_cmd, timeout=120)

                    if fix_result.exit_code == 0 and fix_data.get(
                            "should_retry", False):
                        self.console.print(
                            "🔄 Düzeltme başarılı, orijinal komut yeniden deneniyor...", style="cyan")
                        retry_result = self.agent.executor.terminal.execute(
                            command, timeout=300)
                        return (retry_result.exit_code == 0, retry_result)

        except Exception as e:
            logger.warning(f"LLM-assisted error fix failed: {e}")

        return (False, None)

    # ==================== DIAGNOSTIC LOGIC ====================

    def _diagnose_error(self, output: str, exit_code: int) -> Dict:
        """Comprehensive error diagnosis"""
        output_lower = output.lower()
        diagnosis = self._run_error_checks(output_lower, exit_code, output)

        if diagnosis:
            return diagnosis

        return {"type": "unknown",
                "type_tr": "Tanımlanamayan hata",
                "raw_output": output[:500]}

    def _run_error_checks(
            self,
            output_lower: str,
            exit_code: int,
            output: str) -> Optional[Dict]:
        """Run all error checks in priority order"""
        checkers = [
            self._check_missing_tool, self._check_permission_error,
            self._check_python_module_error, self._check_library_error,
            self._check_network_error, self._check_timeout_error,
            self._check_syntax_error, self._check_file_error,
            self._check_memory_error, self._check_disk_error,
            self._check_auth_error, self._check_port_error,
            self._check_database_error, self._check_parse_error,
            self._check_version_error, self._check_rate_limit_error,
            self._check_firewall_error, self._check_resource_error,
        ]

        for checker in checkers:
            result = checker(output_lower)
            if result:
                return result

        return self._check_exit_code_error(exit_code, output)

    # ... Helper Checker Methods ...
    def _check_missing_tool(self, output_lower: str) -> Optional[Dict]:
        import re
        patterns = [
            "not found",
            "not recognized",
            "bulunamadı",
            "command not found",
            "komut bulunamadı"]
        if any(x in output_lower for x in patterns):
            match = re.search(
                r"['\"]?(\w+)['\"]?[:\s]*(command )?not found",
                output_lower)
            tool = match.group(1) if match else None
            return {
                "type": "missing_tool",
                "type_tr": "Araç bulunamadı",
                "tool": tool}
        return None

    def _check_permission_error(self, output_lower: str) -> Optional[Dict]:
        patterns = [
            "permission denied",
            "access denied",
            "izin reddedildi",
            "root privileges required"]
        if any(x in output_lower for x in patterns):
            return {"type": "permission_denied", "type_tr": "İzin hatası"}
        return None

    def _check_python_module_error(self, output_lower: str) -> Optional[Dict]:
        import re
        patterns = ["no module named", "modulenotfounderror", "importerror"]
        if any(x in output_lower for x in patterns):
            match = re.search(r"no module named ['\"]?([.\w]+)", output_lower)
            module = match.group(1) if match else None
            return {
                "type": "python_module_missing",
                "type_tr": "Python modülü eksik",
                "module": module}
        return None

    def _check_library_error(self, output_lower: str) -> Optional[Dict]:
        import re
        patterns = [
            "cannot open shared object",
            "library not found",
            "libssl",
            "libcrypto",
            ".so:"]
        if any(x in output_lower for x in patterns):
            match = re.search(r"(lib\w+\.so[.\d]*|[\w]+\.dll)", output_lower)
            library = match.group(1) if match else None
            return {
                "type": "library_missing",
                "type_tr": "Sistem kütüphanesi eksik",
                "library": library}
        return None

    def _check_network_error(self, output_lower: str) -> Optional[Dict]:
        patterns = [
            "connection refused",
            "network unreachable",
            "no route to host",
            "ssl error"]
        if any(x in output_lower for x in patterns):
            return {"type": "connection_error", "type_tr": "Bağlantı hatası"}
        return None

    def _check_timeout_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["timed out", "timeout", "zaman aşımı"]
        if any(x in output_lower for x in patterns):
            return {"type": "timeout", "type_tr": "Zaman aşımı"}
        return None

    def _check_syntax_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["invalid argument", "syntax error", "usage:"]
        if any(x in output_lower for x in patterns):
            return {"type": "invalid_argument", "type_tr": "Geçersiz argüman"}
        return None

    def _check_file_error(self, output_lower: str) -> Optional[Dict]:
        import re
        patterns = ["no such file", "file not found", "dosya bulunamadı"]
        if any(x in output_lower for x in patterns):
            match = re.search(
                r"['\"]?([/\\]?[\w./\\-]+\.\w+)['\"]?",
                output_lower)
            filepath = match.group(1) if match else None
            return {
                "type": "file_not_found",
                "type_tr": "Dosya bulunamadı",
                "file": filepath}
        return None

    def _check_memory_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["out of memory", "memory error", "segmentation fault"]
        if any(x in output_lower for x in patterns):
            return {"type": "memory_error", "type_tr": "Bellek hatası"}
        return None

    def _check_disk_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["disk full", "no space left"]
        if any(x in output_lower for x in patterns):
            return {"type": "disk_full", "type_tr": "Disk alanı yetersiz"}
        return None

    def _check_auth_error(self, output_lower: str) -> Optional[Dict]:
        patterns = [
            "authentication failed",
            "invalid credentials",
            "401",
            "403 forbidden"]
        if any(x in output_lower for x in patterns):
            return {"type": "auth_error", "type_tr": "Kimlik doğrulama hatası"}
        return None

    def _check_port_error(self, output_lower: str) -> Optional[Dict]:
        import re
        patterns = [
            "address already in use",
            "port already in use",
            "bind failed"]
        if any(x in output_lower for x in patterns):
            match = re.search(r"port[:\s]*(\d+)", output_lower)
            port = match.group(1) if match else None
            return {
                "type": "port_in_use",
                "type_tr": "Port kullanımda",
                "port": port}
        return None

    def _check_database_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["database", "sqlite", "db error", "locked"]
        if any(x in output_lower for x in patterns):
            return {"type": "database_error", "type_tr": "Veritabanı hatası"}
        return None

    def _check_parse_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["json", "xml", "parsing error"]
        if any(x in output_lower for x in patterns):
            return {"type": "parse_error", "type_tr": "Ayrıştırma hatası"}
        return None

    def _check_version_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["version", "incompatible", "unsupported"]
        if any(x in output_lower for x in patterns):
            return {"type": "version_error", "type_tr": "Sürüm uyumsuzluğu"}
        return None

    def _check_rate_limit_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["rate limit", "too many requests", "429"]
        if any(x in output_lower for x in patterns):
            return {"type": "rate_limit", "type_tr": "İstek limiti aşıldı"}
        return None

    def _check_firewall_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["blocked", "firewall", "waf", "filtered"]
        if any(x in output_lower for x in patterns):
            return {
                "type": "firewall_blocked",
                "type_tr": "Güvenlik duvarı engeli"}
        return None

    def _check_resource_error(self, output_lower: str) -> Optional[Dict]:
        patterns = ["too many open files", "resource temporarily unavailable"]
        if any(x in output_lower for x in patterns):
            return {"type": "resource_limit", "type_tr": "Kaynak limiti"}
        return None

    def _check_exit_code_error(
            self,
            exit_code: int,
            output: str) -> Optional[Dict]:
        if exit_code != 0 and not output.strip():
            exit_code_map = {
                1: {"type": "general_error", "type_tr": "Genel hata"},
                126: {"type": "permission_denied", "type_tr": "Çalıştırma izni yok"},
                127: {"type": "missing_tool", "type_tr": "Komut bulunamadı"},
                137: {"type": "killed", "type_tr": "İşlem sonlandırıldı (OOM?)"},
            }
            if exit_code in exit_code_map:
                return exit_code_map[exit_code]
        return None
