"""
DRAKBEN Error Diagnostics Module
Author: @drak_ben
Description: Comprehensive error diagnosis from command output and exit codes.

This module provides error pattern matching for 25+ error types
in multiple languages (English, Turkish) and suggests fixes.
"""

import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ErrorDiagnosticsMixin:
    """
    Mixin class providing error diagnosis capabilities.
    
    This mixin can be inherited by any class that needs to diagnose
    command execution errors.
    
    Features:
    - Pattern matching for 18+ error types
    - Multi-language support (English, Turkish)
    - Exit code based diagnosis
    - Unknown error logging for learning
    """
    
    def _diagnose_error(self, output: str, exit_code: int) -> Dict[str, Any]:
        """
        Comprehensive error diagnosis from output and exit code.
        Covers 25+ error types in multiple languages.
        
        Args:
            output: Command stdout/stderr output
            exit_code: Process exit code
            
        Returns:
            Dict with type, type_tr (Turkish), and additional context
        """
        output_lower = output.lower()
        diagnosis = self._run_error_checks(output_lower, exit_code, output)
        
        if diagnosis:
            return diagnosis
        
        self._log_unknown_error(output, exit_code)
        return {"type": "unknown", "type_tr": "Tanımlanamayan hata", "raw_output": output[:500]}
    
    def _run_error_checks(
        self, output_lower: str, exit_code: int, output: str
    ) -> Optional[Dict[str, Any]]:
        """Run all error checks in priority order"""
        checkers = [
            self._check_missing_tool,
            self._check_permission_error,
            self._check_python_module_error,
            self._check_library_error,
            self._check_network_error,
            self._check_timeout_error,
            self._check_syntax_error,
            self._check_file_error,
            self._check_memory_error,
            self._check_disk_error,
            self._check_auth_error,
            self._check_port_error,
            self._check_database_error,
            self._check_parse_error,
            self._check_version_error,
            self._check_rate_limit_error,
            self._check_firewall_error,
            self._check_resource_error,
        ]
        
        for checker in checkers:
            result = checker(output_lower)
            if result:
                return result
        
        return self._check_exit_code_error(exit_code, output)
    
    def _check_missing_tool(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for missing tool/command errors"""
        patterns = [
            "not found", "not recognized", "bulunamadı", "command not found",
            "komut bulunamadı", "no such command", "unknown command",
            "is not recognized as", "bash:", "sh:", "zsh:", "cmd:", "powershell:"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"['\"]?(\w+)['\"]?[:\s]*(command )?not found", output_lower)
            tool = match.group(1) if match else None
            return {"type": "missing_tool", "type_tr": "Araç bulunamadı", "tool": tool}
        return None
    
    def _check_permission_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for permission/access denied errors"""
        patterns = [
            "permission denied", "access denied", "izin reddedildi",
            "operation not permitted", "root privileges required",
            "sudo required", "eacces", "eperm", "requires elevation"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "permission_denied", "type_tr": "İzin hatası"}
        return None
    
    def _check_python_module_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for Python module missing errors"""
        patterns = [
            "no module named", "modulenotfounderror", "importerror",
            "cannot import name", "modül bulunamadı"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"no module named ['\"]?([.\w]+)", output_lower)
            if not match:
                match = re.search(r"cannot import name ['\"]?(\w+)", output_lower)
            module = match.group(1) if match else None
            return {"type": "python_module_missing", "type_tr": "Python modülü eksik", "module": module}
        return None
    
    def _check_library_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for missing library/shared object errors"""
        patterns = [
            "cannot open shared object", "library not found", ".so:", ".dll",
            "libssl", "libcrypto", "libpython", "kütüphane bulunamadı"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"(lib\w+\.so[.\d]*|[\w]+\.dll)", output_lower)
            library = match.group(1) if match else None
            return {"type": "library_missing", "type_tr": "Sistem kütüphanesi eksik", "library": library}
        return None
    
    def _check_network_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for connection/network errors"""
        patterns = [
            "connection refused", "connection reset", "network unreachable",
            "no route to host", "econnrefused", "ssl error", "tls"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "connection_error", "type_tr": "Bağlantı hatası"}
        return None
    
    def _check_timeout_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for timeout errors"""
        patterns = [
            "timed out", "timeout", "zaman aşımı", "etimedout",
            "deadline exceeded", "request timeout"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "timeout", "type_tr": "Zaman aşımı"}
        return None
    
    def _check_syntax_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for syntax/argument errors"""
        patterns = [
            "invalid argument", "invalid option", "unrecognized option",
            "syntax error", "bad argument", "usage:", "try '--help'"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "invalid_argument", "type_tr": "Geçersiz argüman/sözdizimi"}
        return None
    
    def _check_file_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for file not found errors"""
        patterns = [
            "no such file", "file not found", "dosya bulunamadı",
            "enoent", "path not found", "cannot find"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"['\"]?([/\\]?[\w./\\-]+\.\w+)['\"]?", output_lower)
            filepath = match.group(1) if match else None
            return {"type": "file_not_found", "type_tr": "Dosya bulunamadı", "file": filepath}
        return None
    
    def _check_memory_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for memory errors"""
        patterns = [
            "out of memory", "memory error", "enomem", "oom",
            "segmentation fault", "segfault", "core dumped"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "memory_error", "type_tr": "Bellek hatası"}
        return None
    
    def _check_disk_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for disk space errors"""
        patterns = [
            "no space left", "disk full", "disk quota", "enospc",
            "yetersiz disk alanı"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "disk_full", "type_tr": "Disk alanı yetersiz"}
        return None
    
    def _check_auth_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for authentication errors"""
        patterns = [
            "authentication failed", "invalid credentials", "unauthorized",
            "401", "403 forbidden", "login failed"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "auth_error", "type_tr": "Kimlik doğrulama hatası"}
        return None
    
    def _check_port_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for port in use errors"""
        patterns = [
            "address already in use", "port already in use", "eaddrinuse",
            "bind failed", "port kullanımda"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"port[:\s]*(\d+)", output_lower)
            port = match.group(1) if match else None
            return {"type": "port_in_use", "type_tr": "Port kullanımda", "port": port}
        return None
    
    def _check_database_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for database errors"""
        patterns = [
            "database", "sqlite", "mysql", "postgresql",
            "db error", "veritabanı hatası", "locked", "deadlock"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "database_error", "type_tr": "Veritabanı hatası"}
        return None
    
    def _check_parse_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for JSON/XML parsing errors"""
        patterns = [
            "json", "xml", "parsing error", "decode error",
            "invalid json", "malformed"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "parse_error", "type_tr": "Ayrıştırma hatası"}
        return None
    
    def _check_version_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for version/compatibility errors"""
        patterns = [
            "version", "incompatible", "requires python", "unsupported",
            "deprecated", "sürüm uyumsuz"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "version_error", "type_tr": "Sürüm uyumsuzluğu"}
        return None
    
    def _check_rate_limit_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for rate limiting errors"""
        patterns = [
            "rate limit", "too many requests", "429", "throttled",
            "quota exceeded", "istek limiti"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "rate_limit", "type_tr": "İstek limiti aşıldı"}
        return None
    
    def _check_firewall_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for firewall/WAF blocked errors"""
        patterns = [
            "blocked", "firewall", "waf", "forbidden", "filtered",
            "connection reset by peer", "güvenlik duvarı"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "firewall_blocked", "type_tr": "Güvenlik duvarı engeli"}
        return None
    
    def _check_resource_error(self, output_lower: str) -> Optional[Dict[str, Any]]:
        """Check for process/resource errors"""
        patterns = [
            "too many open files", "resource temporarily unavailable",
            "eagain", "emfile", "process limit"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "resource_limit", "type_tr": "Kaynak limiti"}
        return None
    
    def _check_exit_code_error(
        self, exit_code: int, output: str
    ) -> Optional[Dict[str, Any]]:
        """Check for exit code based errors"""
        if exit_code != 0 and not output.strip():
            exit_code_map = {
                1: {"type": "general_error", "type_tr": "Genel hata"},
                2: {"type": "invalid_argument", "type_tr": "Geçersiz argüman"},
                126: {"type": "permission_denied", "type_tr": "Çalıştırma izni yok"},
                127: {"type": "missing_tool", "type_tr": "Komut bulunamadı"},
                128: {"type": "invalid_argument", "type_tr": "Geçersiz çıkış kodu"},
                130: {"type": "interrupted", "type_tr": "Kullanıcı tarafından iptal"},
                137: {"type": "killed", "type_tr": "İşlem sonlandırıldı (OOM?)"},
                139: {"type": "segfault", "type_tr": "Segmentation fault"},
                143: {"type": "terminated", "type_tr": "SIGTERM ile sonlandırıldı"},
            }
            if exit_code in exit_code_map:
                return exit_code_map[exit_code]
            if exit_code > 128:
                signal_num = exit_code - 128
                return {"type": "signal_killed", "type_tr": f"Sinyal {signal_num} ile sonlandırıldı"}
        return None
    
    def _log_unknown_error(self, output: str, exit_code: int) -> None:
        """Log unknown errors for future pattern learning"""
        try:
            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "unknown_errors.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Exit Code: {exit_code}\n")
                f.write(f"Output:\n{output[:1000]}\n")
        except OSError as e:
            logger.debug(f"Could not write to unknown errors log: {e}")
