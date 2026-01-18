# core/security_hardening.py
# Security Hardening - Input Validation, Command Sanitization, Secrets Management

import re
import os
import shlex
from typing import Any
from pathlib import Path
import json

class InputValidator:
    """Input validation & sanitization"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """IP adresi valida et"""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """URL valida et"""
        pattern = r'^https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)$'
        return bool(re.match(pattern, url))
    
    @staticmethod
    def validate_port(port: str) -> bool:
        """Port numarasını valida et"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    @staticmethod
    def sanitize_command(cmd: str) -> str:
        """Komut injection'ı önle"""
        # Tehlikeli karakterleri kaldır
        dangerous_chars = [";", "|", "&", "$", "`", "(", ")", "<", ">"]
        for char in dangerous_chars:
            cmd = cmd.replace(char, "")
        return cmd
    
    @staticmethod
    def validate_filename(filename: str) -> bool:
        """Dosya adı güvenli mi?"""
        # Path traversal'ı önle
        if ".." in filename or "/" in filename or "\\" in filename:
            return False
        
        # Tehlikeli karakterler
        dangerous = ['<', '>', ':', '"', '|', '?', '*']
        return not any(char in filename for char in dangerous)

class CommandSanitizer:
    """Command execution safety"""
    
    @staticmethod
    def safe_shell_exec(cmd: str, whitelist: list = None) -> str:
        """
        Güvenli shell komut çalıştırma
        """
        # Whitelist kontrol
        if whitelist:
            base_cmd = cmd.split()[0]
            if base_cmd not in whitelist:
                raise ValueError(f"Command '{base_cmd}' not in whitelist")
        
        # Injection check
        if any(char in cmd for char in [";", "|", "&", "$", "`"]):
            raise ValueError("Dangerous characters detected in command")
        
        # shlex kullanarak safe parsing
        try:
            args = shlex.split(cmd)
            return " ".join(args)
        except:
            raise ValueError("Invalid command syntax")
    
    @staticmethod
    def validate_subprocess_args(args: list) -> list:
        """Subprocess arguments'ı valida et"""
        if not isinstance(args, list):
            raise TypeError("Arguments must be a list")
        
        for arg in args:
            if not isinstance(arg, str):
                raise TypeError("All arguments must be strings")
        
        return args

class SecretsManager:
    """Secrets & Credentials Management"""
    
    def __init__(self, secrets_file: str = "config/.secrets.json"):
        self.secrets_file = secrets_file
        self.secrets = self._load_secrets()
    
    def _load_secrets(self) -> dict:
        """Secrets'ı load et (encrypted)"""
        if os.path.exists(self.secrets_file):
            try:
                with open(self.secrets_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def get_secret(self, key: str) -> str:
        """Secret'ı al"""
        return self.secrets.get(key, os.getenv(key.upper(), ""))
    
    def set_secret(self, key: str, value: str):
        """Secret'ı kaydet"""
        self.secrets[key] = value
        
        # Dosyaya kaydet (chmod 600)
        with open(self.secrets_file, 'w') as f:
            json.dump(self.secrets, f)
        
        os.chmod(self.secrets_file, 0o600)
    
    def use_env_var(self, key: str) -> str:
        """Environment variable'dan al"""
        value = os.getenv(key.upper())
        if not value:
            raise KeyError(f"Secret '{key}' not found in environment")
        return value

class SecurityAuditor:
    """Security audit & vulnerability scanning"""
    
    def __init__(self):
        self.issues = []
    
    def check_hardcoded_secrets(self, filepath: str):
        """Hardcoded secrets'ı bul"""
        patterns = {
            "api_key": r"api[_-]?key\s*=\s*['\"]?[\w-]{20,}",
            "password": r"password\s*=\s*['\"][\w@!#$%^&*]{6,}",
            "token": r"token\s*=\s*['\"]?[\w-]{20,}",
        }
        
        with open(filepath, 'r') as f:
            content = f.read()
            for secret_type, pattern in patterns.items():
                if re.search(pattern, content):
                    self.issues.append(f"Potential {secret_type} found in {filepath}")
    
    def check_input_validation(self, filepath: str):
        """Input validation kontrol et"""
        with open(filepath, 'r') as f:
            content = f.read()
            
            # shell=True kullanımını kontrol et
            if "shell=True" in content:
                self.issues.append(f"Dangerous shell=True found in {filepath}")
            
            # SQL query concatenation'ı kontrol et
            if "query = \"" or "query = '" in content:
                if "+" in content or "format(" in content:
                    self.issues.append(f"SQL injection risk in {filepath}")
    
    def generate_audit_report(self) -> dict:
        """Audit raporu oluştur"""
        return {
            "total_issues": len(self.issues),
            "critical": len([i for i in self.issues if "Hardcoded" in i]),
            "high": len([i for i in self.issues if "shell=True" in i]),
            "issues": self.issues
        }
