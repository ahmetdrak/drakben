# Changelog

All notable changes to DRAKBEN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-02-07

### Added
- **Stanford Memory System** - Graph-based memory with semantic search and ChromaDB
- **Self-Refining Engine** - Policy engine, conflict resolution, failure context analysis
- **Singularity Engine** - AST-based code synthesis with 7 real templates, polymorphic mutation
- **Advanced WAF Bypass Engine** - Intelligent fingerprinting (Cloudflare, AWS, ModSecurity, Imperva, Akamai, F5), multi-layer encoding, adaptive mutation with SQLite memory
- **NVD CVE Integration** - `fetch_and_prepare_exploit()` with 5-CVE deep analysis
- **Boundary-Aware Symbolic Executor** - Heuristic constraint solver with per-operator dispatch
- **C2 Framework** - Domain fronting, DNS tunneling, AES-256-GCM beacons, Telegram C2, steganography
- **Hive Mind** - Distributed operations, network topology discovery, BloodHound-style pathfinding
- **Active Directory Attacks** - Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash, lateral movement
- **Weapon Foundry** - Multi-format payloads (Python, PowerShell, VBS, HTA, Bash, C#), multi-layer encryption
- **Ghost Protocol** - AST-based code transformation, variable obfuscation, dead code injection
- **Sandbox Execution** - Docker isolation with resource limits and automatic cleanup
- **DoH C2 Transport** - DNS over HTTPS for covert C2 communication
- **Auto-Pivoting** - TunnelManager and AutoPivot for automatic lateral movement
- **Real SMTP Phishing** - `smtplib.SMTP` + STARTTLS + MIME multipart construction
- **Systemd Persistence** - Real user-level systemd service unit installation
- **Error Diagnostics** - Advanced error analysis and recovery suggestions
- **Interactive Shell i18n** - Full Turkish/English bilingual support
- **Professional Reporting** - HTML, Markdown, JSON, PDF with CVSS scoring
- Tool Registry with 30+ built-in tools
- Pentest Orchestrator with state machine
- 1330+ tests passing with comprehensive coverage
- CI/CD pipelines (GitHub Actions) with multi-Python matrix
- SonarQube compliance (0 critical issues)
- CodeQL security analysis

### Changed
- **Architecture Overhaul** - Brain split into cognitive modules, agent into mixins
- **UI Modernization** - Minimalist Dracula theme with Cyan/Green colors
- `modules/exploit/` refactored from single file to package
- Ruff expanded to 36 rule groups (all passing)
- Mypy strict mode compliance
- Python 3.11 / 3.12 / 3.13 support

### Security
- Command sanitization prevents shell injection
- Forbidden command blocking
- High-risk operation confirmation
- SSL verification configurable
- Anti-sandbox detection

## [1.0.0] - 2025-12-01

### Added
- Initial release
- Core agent functionality
- Basic reconnaissance tools
- Exploit module
- Report generation
