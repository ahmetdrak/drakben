# DRAKBEN - Professional Penetration Testing AI Assistant

## Project Vision (2026)

**DRAKBEN** is an advanced, production-grade penetration testing automation platform designed for Kali Linux. It combines NLP-driven command interfaces with intelligent exploit chain planning, zero-day detection, and modern evasion techniques.

**Core Philosophy**: 
- Interactive AI conversation + Automated offensive operations
- User approval before dangerous execution
- OPSEC-aware strategies (stealthy/balanced/aggressive)
- Modern payload generation with evasion
- Real-time CVE matching and exploitation

---

## Architecture

### Main Components

1. **`drakben.py`** - ULTIMATE main program
   - Menu-driven interface + NLP fallback
   - Session management (target, strategy, findings)
   - Approval system integration
   - Real-time reporting

2. **Core Modules** (`core/`)
   - `executor.py` - Execute system commands with logging
   - `chain_planner.py` - Basic pentest workflows
   - `advanced_chain_builder.py` - Strategy-based chain generation (NEW)
   - `kali_detector.py` - Auto-detect Kali tools & versions
   - `zero_day_scanner.py` - CVE matching & exploitation
   - `payload_intelligence.py` - Modern payload generation (2026 edition)
   - `approval.py` - Approval dialogs with risk levels
   - `opsec_intelligence.py` - Detection avoidance analysis

3. **LLM Brain** (`llm/`)
   - `brain.py` - Intent analysis + fallback responses
   - `openrouter_client.py` - OpenRouter/DeepSeek integration
   - Handles natural Türkçe/English conversation

4. **Pentest Modules** (`modules/`)
   - `recon.py` - Passive reconnaissance
   - `exploit.py` - Exploit automation
   - `payload.py` - Payload delivery
   - 15+ specialized modules (web, network, crypto, etc.)

---

## Advanced Features

### 1. OPSEC Strategy System
**Three operational modes:**
```
stealthy   → Rate limiting, decoys, slow scans
            Detection risk: LOW
            Speed: SLOW

balanced   → Standard pentest with normal timing
            Detection risk: MEDIUM  
            Speed: MEDIUM

aggressive → Full enumeration, fast scanning
            Detection risk: HIGH
            Speed: FAST
```

**Usage:**
```bash
strategy stealthy      # Switch to stealth mode
scan 192.168.1.100     # Tarama automatical applies evasion
```

### 2. Zero-Day Detection
- **CVE Database Integration**: Matches scan results to known exploits
- **Automatic Exploitation**: Suggests and executes relevant exploits
- **Severity Scoring**: Prioritizes by criticality

### 3. Modern Payload Generation (2026-Level)
Supports advanced evasion:
- **Multiple reverse shells**: Bash, Python, Perl, PowerShell
- **Obfuscation**: Base64, Hex, Base32, URL encoding
- **Wrapper techniques**: Bash encoding, Python eval, multi-layer encoding
- **Polyglot files**: JPG+PHP, GIF+PHP combinations
- **SQLi payloads**: UNION-based, blind, time-based

### 4. Approval System (With Risk Levels)
Every dangerous operation requires confirmation before execution.

### 5. Kali Tool Integration
Auto-detects all pentest tools on the system.

---

## Development Notes

- Use strategy-based chain building for all offensive operations
- Always call `ask_approval()` before executing dangerous commands
- CVE scanner matches scan outputs to known exploits
- Payloads support multiple evasion techniques
- All commands logged to `logs/` directory

**Run**: `python drakben.py`
