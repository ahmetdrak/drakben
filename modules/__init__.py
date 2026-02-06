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
"""

# =============================================================================
# AD Extensions (BloodHound, Impacket, Token)
# =============================================================================
# =============================================================================
# AD Attacks (Kerberos, LDAP)
# =============================================================================
from modules.ad_attacks import (
    ActiveDirectoryAttacker,
    KerberosPacketFactory,
)
from modules.ad_extensions import (
    BloodHoundAnalyzer,
    BloodHoundRelationship,
    ImpacketTool,
    ImpacketWrapper,
    TokenImpersonator,
    TokenPrivilege,
)

# =============================================================================
# C2 Framework
# =============================================================================
from modules.c2_framework import (
    C2Channel,
    C2Config,
    C2Protocol,
    DNSTunneler,
    DoHTransport,
    DomainFronter,
    HeartbeatManager,
    JitterEngine,
)

# =============================================================================
# CVE Database
# =============================================================================
from modules.cve_database import (
    AutoUpdater,
    CVEDatabase,
    CVEEntry,
    CVSSSeverity,
    VulnerabilityMatch,
    VulnerabilityMatcher,
)

# =============================================================================
# Exploit module
# =============================================================================
from modules.exploit import (
    AIEvasion,
    PolyglotEngine,
)

# =============================================================================
# Hive Mind (Lateral Movement & Network Mapping)
# =============================================================================
from modules.hive_mind import (
    AttackPath,
    AutoPivot,
    CredentialHarvester,
    CredentialType,
    HiveMind,
    LateralMover,
    MovementTechnique,
    NetworkHost,
    TunnelConfig,
    TunnelManager,
)

# =============================================================================
# Metasploit RPC
# =============================================================================
from modules.metasploit import (
    ExploitResult,
    ExploitStatus,
    MetasploitRPC,
    MSFSession,
    SessionType,
)

# =============================================================================
# Nuclei Scanner
# =============================================================================
from modules.nuclei import (
    NucleiResult,
    NucleiScanConfig,
    NucleiScanner,
    NucleiSeverity,
    NucleiTemplateType,
)

# =============================================================================
# Payload Obfuscation & AV Bypass
# =============================================================================
from modules.payload import (
    AVBypass,
    BashObfuscator,
    PayloadError,
    PayloadObfuscator,
    PowerShellObfuscator,
)

# =============================================================================
# Post-Exploitation
# =============================================================================
from modules.post_exploit import (
    C2ShellWrapper,
    LinuxPostExploit,
    PostExploitEngine,
    ReverseTCPShell,
    ShellInterface,
    SSHShell,
    WebShell,
    WindowsPostExploit,
    WinRMShell,
)

# =============================================================================
# Recon module
# =============================================================================
from modules.recon import (
    detect_cms,
    detect_technologies,
    get_dns_records,
    get_whois_info,
    passive_recon,
    passive_recon_sync,
)

# =============================================================================
# Report Generator
# =============================================================================
from modules.report_generator import (
    Finding,
    FindingSeverity,
    ReportFormat,
    ReportGenerator,
    ScanResult,
)

# =============================================================================
# Stealth HTTP Client
# =============================================================================
from modules.stealth_client import (
    AsyncStealthSession,
    ProxyManager,
    StealthSession,
)

# =============================================================================
# Subdomain Enumeration
# =============================================================================
from modules.subdomain import (
    SubdomainEnumerator,
    SubdomainResult,
)
from modules.waf_bypass_engine import (
    AdaptiveMutationMemory,
    CommandBypassEngine,
    EncodingEngine,
    HTTPBypassEngine,
    PayloadAttempt,
    SQLBypassEngine,
    WAFBypassEngine,
    WAFSignature,
    WAFType,
    XSSBypassEngine,
)

# =============================================================================
# WAF Bypass (Legacy + New Engine)
# =============================================================================
from modules.waf_evasion import WAFEvasion

# =============================================================================
# Weapon Foundry (Payload Generation)
# =============================================================================
from modules.weapon_foundry import (
    EncryptionMethod,
    PayloadFormat,
    ShellType,
    WeaponFoundry,
)

# =============================================================================
# __all__ - Public API
# =============================================================================
__all__ = [
    # Recon
    "passive_recon",
    "passive_recon_sync",
    "get_dns_records",
    "get_whois_info",
    "detect_cms",
    "detect_technologies",
    # Subdomain
    "SubdomainEnumerator",
    "SubdomainResult",
    # Exploit
    "PolyglotEngine",
    "AIEvasion",
    # C2
    "C2Protocol",
    "C2Config",
    "C2Channel",
    "DomainFronter",
    "DNSTunneler",
    "DoHTransport",
    "HeartbeatManager",
    "JitterEngine",
    # Hive Mind
    "HiveMind",
    "MovementTechnique",
    "CredentialType",
    "NetworkHost",
    "AttackPath",
    "LateralMover",
    "CredentialHarvester",
    "AutoPivot",
    "TunnelManager",
    "TunnelConfig",
    # AD Attacks
    "ActiveDirectoryAttacker",
    "KerberosPacketFactory",
    # AD Extensions
    "BloodHoundAnalyzer",
    "BloodHoundRelationship",
    "ImpacketTool",
    "ImpacketWrapper",
    "TokenImpersonator",
    "TokenPrivilege",
    # Payload Obfuscation
    "PayloadError",
    "PayloadObfuscator",
    "PowerShellObfuscator",
    "BashObfuscator",
    "AVBypass",
    # Post-Exploitation
    "ShellInterface",
    "LinuxPostExploit",
    "WindowsPostExploit",
    "PostExploitEngine",
    "C2ShellWrapper",
    "SSHShell",
    "WebShell",
    "ReverseTCPShell",
    "WinRMShell",
    # CVE Database
    "CVSSSeverity",
    "CVEEntry",
    "VulnerabilityMatch",
    "AutoUpdater",
    "CVEDatabase",
    "VulnerabilityMatcher",
    # Nuclei
    "NucleiSeverity",
    "NucleiTemplateType",
    "NucleiResult",
    "NucleiScanConfig",
    "NucleiScanner",
    # Metasploit
    "SessionType",
    "ExploitStatus",
    "MSFSession",
    "ExploitResult",
    "MetasploitRPC",
    # Stealth Client
    "ProxyManager",
    "StealthSession",
    "AsyncStealthSession",
    # WAF Bypass (Legacy)
    "WAFEvasion",
    # WAF Bypass Engine (Advanced)
    "WAFType",
    "WAFSignature",
    "PayloadAttempt",
    "AdaptiveMutationMemory",
    "EncodingEngine",
    "SQLBypassEngine",
    "XSSBypassEngine",
    "CommandBypassEngine",
    "HTTPBypassEngine",
    "WAFBypassEngine",
    # Weapon Foundry
    "WeaponFoundry",
    "PayloadFormat",
    "EncryptionMethod",
    "ShellType",
    # Reporting
    "ReportGenerator",
    "ReportFormat",
    "FindingSeverity",
    "Finding",
    "ScanResult",
]
