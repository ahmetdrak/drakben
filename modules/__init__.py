# Modules paketi - DRAKBEN Attack Modules
"""
DRAKBEN modül paketi.

Bu paket pentest operasyonları için gerekli tüm saldırı modüllerini içerir:
- recon: Pasif ve aktif keşif
- subdomain: Subdomain enumeration
- exploit: Zafiyet istismarı ve payload'lar
- c2_framework: Command & Control altyapısı
- hive_mind: Lateral movement ve network mapping
- ad_attacks: Active Directory saldırıları
- ad_extensions: Advanced AD attacks (BloodHound, Impacket)
- weapon_foundry: Payload üretimi
- payload: Payload obfuscation ve AV bypass
- waf_evasion: WAF bypass teknikleri (legacy)
- waf_bypass_engine: Advanced WAF bypass engine
- post_exploit: Post-exploitation modülü
- cve_database: CVE veritabanı ve eşleştirme
- nuclei: Nuclei scanner entegrasyonu
- metasploit: Metasploit RPC entegrasyonu
- stealth_client: Stealth HTTP client
- report_generator: Profesyonel raporlama

Uses lazy imports to avoid loading all submodules on ``import modules``.
"""

from __future__ import annotations

import importlib
from typing import Any

# =============================================================================
# Module path constants (SonarQube S1192: avoid duplicate literals)
# =============================================================================
_MOD_AD_ATTACKS = "modules.ad_attacks"
_MOD_AD_EXTENSIONS = "modules.ad_extensions"
_MOD_C2_FRAMEWORK = "modules.c2_framework"
_MOD_CVE_DATABASE = "modules.cve_database"
_MOD_EXPLOIT = "modules.exploit"
_MOD_HIVE_MIND = "modules.hive_mind"
_MOD_METASPLOIT = "modules.metasploit"
_MOD_NUCLEI = "modules.nuclei"
_MOD_PAYLOAD = "modules.payload"
_MOD_POST_EXPLOIT = "modules.post_exploit"
_MOD_RECON = "modules.recon"
_MOD_REPORT_GENERATOR = "modules.report_generator"
_MOD_STEALTH_CLIENT = "modules.stealth_client"
_MOD_SUBDOMAIN = "modules.subdomain"
_MOD_WAF_BYPASS_ENGINE = "modules.waf_bypass_engine"
_MOD_WAF_EVASION = "modules.waf_evasion"
_MOD_WEAPON_FOUNDRY = "modules.weapon_foundry"

# =============================================================================
# Lazy-import mapping: symbol → (submodule, name)
# =============================================================================
_LAZY_MAP: dict[str, tuple[str, str]] = {
    # AD Attacks
    "ActiveDirectoryAttacker": (_MOD_AD_ATTACKS, "ActiveDirectoryAttacker"),
    "KerberosPacketFactory": (_MOD_AD_ATTACKS, "KerberosPacketFactory"),
    # AD Extensions
    "BloodHoundAnalyzer": (_MOD_AD_EXTENSIONS, "BloodHoundAnalyzer"),
    "BloodHoundRelationship": (_MOD_AD_EXTENSIONS, "BloodHoundRelationship"),
    "ImpacketTool": (_MOD_AD_EXTENSIONS, "ImpacketTool"),
    "ImpacketWrapper": (_MOD_AD_EXTENSIONS, "ImpacketWrapper"),
    "TokenImpersonator": (_MOD_AD_EXTENSIONS, "TokenImpersonator"),
    "TokenPrivilege": (_MOD_AD_EXTENSIONS, "TokenPrivilege"),
    # C2 Framework
    "C2Channel": (_MOD_C2_FRAMEWORK, "C2Channel"),
    "C2Config": (_MOD_C2_FRAMEWORK, "C2Config"),
    "C2Protocol": (_MOD_C2_FRAMEWORK, "C2Protocol"),
    "DNSTunneler": (_MOD_C2_FRAMEWORK, "DNSTunneler"),
    "DoHTransport": (_MOD_C2_FRAMEWORK, "DoHTransport"),
    "DomainFronter": (_MOD_C2_FRAMEWORK, "DomainFronter"),
    "HeartbeatManager": (_MOD_C2_FRAMEWORK, "HeartbeatManager"),
    "JitterEngine": (_MOD_C2_FRAMEWORK, "JitterEngine"),
    # CVE Database
    "AutoUpdater": (_MOD_CVE_DATABASE, "AutoUpdater"),
    "CVEDatabase": (_MOD_CVE_DATABASE, "CVEDatabase"),
    "CVEEntry": (_MOD_CVE_DATABASE, "CVEEntry"),
    "CVSSSeverity": (_MOD_CVE_DATABASE, "CVSSSeverity"),
    "VulnerabilityMatch": (_MOD_CVE_DATABASE, "VulnerabilityMatch"),
    "VulnerabilityMatcher": (_MOD_CVE_DATABASE, "VulnerabilityMatcher"),
    # Exploit
    "AIEvasion": (_MOD_EXPLOIT, "AIEvasion"),
    "PolyglotEngine": (_MOD_EXPLOIT, "PolyglotEngine"),
    # Hive Mind
    "AttackPath": (_MOD_HIVE_MIND, "AttackPath"),
    "AutoPivot": (_MOD_HIVE_MIND, "AutoPivot"),
    "CredentialHarvester": (_MOD_HIVE_MIND, "CredentialHarvester"),
    "CredentialType": (_MOD_HIVE_MIND, "CredentialType"),
    "HiveMind": (_MOD_HIVE_MIND, "HiveMind"),
    "LateralMover": (_MOD_HIVE_MIND, "LateralMover"),
    "MovementTechnique": (_MOD_HIVE_MIND, "MovementTechnique"),
    "NetworkHost": (_MOD_HIVE_MIND, "NetworkHost"),
    "TunnelConfig": (_MOD_HIVE_MIND, "TunnelConfig"),
    "TunnelManager": (_MOD_HIVE_MIND, "TunnelManager"),
    # Metasploit
    "ExploitResult": (_MOD_METASPLOIT, "ExploitResult"),
    "ExploitStatus": (_MOD_METASPLOIT, "ExploitStatus"),
    "MetasploitRPC": (_MOD_METASPLOIT, "MetasploitRPC"),
    "MSFSession": (_MOD_METASPLOIT, "MSFSession"),
    "SessionType": (_MOD_METASPLOIT, "SessionType"),
    # Nuclei
    "NucleiResult": (_MOD_NUCLEI, "NucleiResult"),
    "NucleiScanConfig": (_MOD_NUCLEI, "NucleiScanConfig"),
    "NucleiScanner": (_MOD_NUCLEI, "NucleiScanner"),
    "NucleiSeverity": (_MOD_NUCLEI, "NucleiSeverity"),
    "NucleiTemplateType": (_MOD_NUCLEI, "NucleiTemplateType"),
    # Payload
    "AVBypass": (_MOD_PAYLOAD, "AVBypass"),
    "BashObfuscator": (_MOD_PAYLOAD, "BashObfuscator"),
    "PayloadError": (_MOD_PAYLOAD, "PayloadError"),
    "PayloadObfuscator": (_MOD_PAYLOAD, "PayloadObfuscator"),
    "PowerShellObfuscator": (_MOD_PAYLOAD, "PowerShellObfuscator"),
    # Post-Exploitation
    "C2ShellWrapper": (_MOD_POST_EXPLOIT, "C2ShellWrapper"),
    "LinuxPostExploit": (_MOD_POST_EXPLOIT, "LinuxPostExploit"),
    "PostExploitEngine": (_MOD_POST_EXPLOIT, "PostExploitEngine"),
    "ReverseTCPShell": (_MOD_POST_EXPLOIT, "ReverseTCPShell"),
    "ShellInterface": (_MOD_POST_EXPLOIT, "ShellInterface"),
    "SSHShell": (_MOD_POST_EXPLOIT, "SSHShell"),
    "WebShell": (_MOD_POST_EXPLOIT, "WebShell"),
    "WindowsPostExploit": (_MOD_POST_EXPLOIT, "WindowsPostExploit"),
    "WinRMShell": (_MOD_POST_EXPLOIT, "WinRMShell"),
    # Recon
    "detect_cms": (_MOD_RECON, "detect_cms"),
    "detect_technologies": (_MOD_RECON, "detect_technologies"),
    "get_dns_records": (_MOD_RECON, "get_dns_records"),
    "get_whois_info": (_MOD_RECON, "get_whois_info"),
    "passive_recon": (_MOD_RECON, "passive_recon"),
    "passive_recon_sync": (_MOD_RECON, "passive_recon_sync"),
    "scan_ports": (_MOD_RECON, "scan_ports"),
    "scan_ports_sync": (_MOD_RECON, "scan_ports_sync"),
    # Report Generator
    "Finding": (_MOD_REPORT_GENERATOR, "Finding"),
    "FindingSeverity": (_MOD_REPORT_GENERATOR, "FindingSeverity"),
    "ReportFormat": (_MOD_REPORT_GENERATOR, "ReportFormat"),
    "ReportGenerator": (_MOD_REPORT_GENERATOR, "ReportGenerator"),
    "ScanResult": (_MOD_REPORT_GENERATOR, "ScanResult"),
    # Stealth Client
    "AsyncStealthSession": (_MOD_STEALTH_CLIENT, "AsyncStealthSession"),
    "ProxyManager": (_MOD_STEALTH_CLIENT, "ProxyManager"),
    "StealthSession": (_MOD_STEALTH_CLIENT, "StealthSession"),
    # Subdomain
    "SubdomainEnumerator": (_MOD_SUBDOMAIN, "SubdomainEnumerator"),
    "SubdomainResult": (_MOD_SUBDOMAIN, "SubdomainResult"),
    # WAF Bypass Engine
    "AdaptiveMutationMemory": (_MOD_WAF_BYPASS_ENGINE, "AdaptiveMutationMemory"),
    "CommandBypassEngine": (_MOD_WAF_BYPASS_ENGINE, "CommandBypassEngine"),
    "EncodingEngine": (_MOD_WAF_BYPASS_ENGINE, "EncodingEngine"),
    "HTTPBypassEngine": (_MOD_WAF_BYPASS_ENGINE, "HTTPBypassEngine"),
    "PayloadAttempt": (_MOD_WAF_BYPASS_ENGINE, "PayloadAttempt"),
    "SQLBypassEngine": (_MOD_WAF_BYPASS_ENGINE, "SQLBypassEngine"),
    "WAFBypassEngine": (_MOD_WAF_BYPASS_ENGINE, "WAFBypassEngine"),
    "WAFSignature": (_MOD_WAF_BYPASS_ENGINE, "WAFSignature"),
    "WAFType": (_MOD_WAF_BYPASS_ENGINE, "WAFType"),
    "XSSBypassEngine": (_MOD_WAF_BYPASS_ENGINE, "XSSBypassEngine"),
    # WAF Evasion (Legacy)
    "WAFEvasion": (_MOD_WAF_EVASION, "WAFEvasion"),
    # Weapon Foundry
    "EncryptionMethod": (_MOD_WEAPON_FOUNDRY, "EncryptionMethod"),
    "PayloadFormat": (_MOD_WEAPON_FOUNDRY, "PayloadFormat"),
    "ShellType": (_MOD_WEAPON_FOUNDRY, "ShellType"),
    "WeaponFoundry": (_MOD_WEAPON_FOUNDRY, "WeaponFoundry"),
}


def __getattr__(name: str) -> Any:
    """Lazy-load symbols on first access."""
    if name in _LAZY_MAP:
        module_path, attr_name = _LAZY_MAP[name]
        module = importlib.import_module(module_path)
        return getattr(module, attr_name)
    msg = f"module 'modules' has no attribute {name!r}"
    raise AttributeError(msg)


# =============================================================================
# __all__ - Public API (unchanged for static analysers)
# =============================================================================
__all__ = list(_LAZY_MAP.keys())
