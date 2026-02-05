# Modules paketi - DRAKBEN Attack Modules
"""
DRAKBEN modül paketi.

Bu paket pentest operasyonları için gerekli tüm saldırı modüllerini içerir:
- recon: Pasif ve aktif keşif
- exploit: Zafiyet istismarı ve payload'lar
- c2_framework: Command & Control altyapısı
- hive_mind: AD saldırıları ve lateral movement
- weapon_foundry: Payload üretimi
- waf_evasion: WAF bypass teknikleri
- report_generator: Profesyonel raporlama
- subdomain: Subdomain enumeration
- ad_extensions: Advanced AD attacks
"""

# AD Extensions (BloodHound, Impacket, Token)
from modules.ad_extensions import (
    BloodHoundAnalyzer,
    BloodHoundRelationship,
    ImpacketTool,
    ImpacketWrapper,
    TokenImpersonator,
    TokenPrivilege,
)

# Recon module
# C2 Framework
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

# Exploit module
from modules.exploit import (
    AIEvasion,
    PolyglotEngine,
)

# Hive Mind (AD & Lateral Movement)
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
from modules.recon import (
    detect_cms,
    detect_technologies,
    get_dns_records,
    get_whois_info,
    passive_recon,
    passive_recon_sync,
)

# Report Generator
from modules.report_generator import (
    Finding,
    FindingSeverity,
    ReportFormat,
    ReportGenerator,
    ScanResult,
)

# Subdomain Enumeration
from modules.subdomain import (
    SubdomainEnumerator,
    SubdomainResult,
)

# WAF Evasion
from modules.waf_evasion import WAFEvasion

# Weapon Foundry (Payload Generation)
from modules.weapon_foundry import (
    EncryptionMethod,
    PayloadFormat,
    ShellType,
    WeaponFoundry,
)

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
    # AD Extensions
    "BloodHoundAnalyzer",
    "BloodHoundRelationship",
    "ImpacketTool",
    "ImpacketWrapper",
    "TokenImpersonator",
    "TokenPrivilege",
    # Weapon Foundry
    "WeaponFoundry",
    "PayloadFormat",
    "EncryptionMethod",
    "ShellType",
    # WAF
    "WAFEvasion",
    # Reporting
    "ReportGenerator",
    "ReportFormat",
    "FindingSeverity",
    "Finding",
    "ScanResult",
]
