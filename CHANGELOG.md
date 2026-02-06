# Changelog

All notable changes to DRAKBEN will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.2.0] - 2026-02-05

### Added
- **Advanced WAF Bypass Engine** - Complete rewrite with intelligent WAF fingerprinting
  - WAF detection: Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, F5, and more
  - PayloadType enum for SQLI, XSS, RCE, LFI, SSTI, XXE, SSRF classification
  - Adaptive mutation memory with SQLite backend
  - Multi-layer encoding: Unicode, UTF-8, double URL, hex encoding
  - SQL injection bypass: inline comments, CONCAT, CHAR functions
  - XSS bypass: SVG payloads, event handlers, protocol wrappers
  - Command injection: string concatenation, wildcard injection
  - HTTP smuggling & chunked encoding techniques
- Full module integration in `modules/__init__.py` with 70+ exported classes
- Comprehensive type annotations for all modules
- test_waf_bypass_engine.py with 50+ tests for WAF bypass validation

### Changed
- WAFEvasion now wraps WAFBypassEngine for backward compatibility
- Test count increased from 527 to 583
- Improved Mypy strict mode compliance
- All truthy-function checks converted to explicit `is not None`

### Fixed
- `fingerprint_waf` method call error in waf_evasion.py wrapper
- Missing PayloadType export in modules/__init__.py
- Type annotation errors in test files
- Float equality comparison issues in test_memory_system.py
- Conditional expression bug in menu.py returning same value

## [3.1.0] - 2026-02-05

### Added
- **Stanford Memory System** - Graph-based memory with semantic search and ChromaDB
- **Brain Integration** - Memory system integrated into AI reasoning engine
- **Unified Display System** - ThinkingDisplay, ScanDisplay, UnifiedConfirmation
- **Interactive Shell i18n** - Full Turkish/English support in `/shell` command
- **Error Diagnostics Module** - Advanced error analysis and recovery suggestions
- API.md documentation file with complete API reference
- Tool availability caching in PentestOrchestrator
- test_subdomain.py (18 tests) for subdomain enumeration module
- test_ad_extensions.py (29 tests) for AD extensions module
- test_cve_database.py (26 tests) for CVE database module
- test_metasploit.py (15 tests) for Metasploit integration
- test_nuclei.py (15 tests) for Nuclei scanner integration

### Changed
- **UI Modernization** - Minimalist Dracula theme with Cyan/Green colors
- **Menu System** - All commands updated with new gradient styling
- PentestOrchestrator now caches tool availability checks
- Improved performance with `_tool_cache` dictionary
- Test count increased from 418 to 527

### Fixed
- Ruff lint errors (19 fixed with auto-fix)
- Type annotation quotes (UP037)
- isinstance patterns (UP038)
- Import sorting (I001)
- f-string placeholders (F541)

## [3.0.0] - 2026-02-04

### Added
- **DoH C2 Transport** - DNS over HTTPS support for covert C2 communication
- **Auto-Pivoting** - TunnelManager and AutoPivot classes for automatic lateral movement
- **LLM Provider Switching** - switch_model(), switch_provider(), list_ollama_models()
- **MFA Bypass Enhancements** - ModlishkaProxy, SimpleReverseProxy, UnifiedMFABypass
- **Exploit Templates** - ExploitType enum with 5 exploit template types
- **Fuzzer Enhancements** - fuzz_binary() and fuzz_endpoint() methods
- **Windows Daemon Support** - NSSM integration and run_as_background_process()
- **Redis Fallback** - In-memory fallback for distributed state
- **JSON Error Logging** - Brain.py now logs JSONDecodeError events
- Tool Registry with 30 built-in tools
- Pentest Orchestrator with state machine
- Synthesizer LLM integration (real _call_llm())
- 418+ tests passing

### Changed
- Migrated to Python 3.13+
- Updated all dependencies
- Improved type annotations throughout

### Fixed
- Empty except blocks (3 real fixes)
- Bandit B602 warnings (nosec annotations)
- Mypy type errors (170+ → 0)
- Vulture dead code warnings

### Security
- SSL verification is now configurable
- Added CommandSanitizer for input validation
- Test fixtures marked with nosec

## [2.0.0] - 2026-01-15

### Added
- HiveMind module for multi-agent coordination
- Weapon Foundry for payload generation
- C2 Framework with domain fronting
- DNS tunneling support
- Singularity AI code generation engine

### Changed
- Major architecture refactoring
- Improved LLM integration

## [1.0.0] - 2025-12-01

### Added
- Initial release
- Core agent functionality
- Basic reconnaissance tools
- Exploit module
- Report generation
