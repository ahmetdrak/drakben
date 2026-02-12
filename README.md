<div align="center">

<img src="https://capsule-render.vercel.app/api?type=venom&color=0:8B0000,100:1a1a2e&height=200&section=header&text=DRAKBEN&fontSize=70&fontColor=ff5555&fontAlignY=35&desc=Autonomous%20Penetration%20Testing%20Framework&descAlignY=55&descSize=18&descColor=f8f8f2&animation=fadeIn" width="100%"/>

*Let AI handle the methodology. You focus on the results.*

[![CI](https://github.com/ahmetdrak/drakben/actions/workflows/drakben_ci.yml/badge.svg)](https://github.com/ahmetdrak/drakben/actions/workflows/drakben_ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/)
[![Tests](https://img.shields.io/badge/tests-1363%20passed-brightgreen.svg)](https://github.com/ahmetdrak/drakben/actions)
[![Ruff](https://img.shields.io/badge/linting-ruff%2035%20rule%20groups-brightgreen.svg)](https://github.com/astral-sh/ruff)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Advanced](#-advanced-capabilities) • [Contributing](#-contributing)

</div>

---

## 🎯 What is DRAKBEN?

DRAKBEN is an **AI-powered autonomous penetration testing framework** that understands natural language commands and executes security assessments with minimal human intervention. Instead of memorizing complex tool syntax, describe what you want in plain language—DRAKBEN handles the rest.

```
You: "Scan the target for open ports and check for web vulnerabilities"
DRAKBEN: Executing nmap → Analyzing services → Running nikto → Found 3 potential issues...
```

### 🌟 Key Differentiators

| Feature | Traditional Tools | DRAKBEN |
|---------|-------------------|---------|
| Interface | CLI flags & syntax | Natural language |
| Decision Making | Manual | AI-driven autonomous |
| Learning | Static | Self-evolving strategies |
| State | Stateless | Persistent state awareness |
| Recovery | Manual restart | Self-healing |

---

## ✨ Features

### 🧠 AI-Driven Decision Making
- **Natural Language Interface** - Talk to DRAKBEN like a colleague
- **Context-Aware Tool Selection** - Automatically picks the right tool
- **Multi-LLM Support** - OpenRouter, Ollama, OpenAI, Custom APIs
- **Bilingual UI** - Full Turkish and English support with `/tr` and `/en`
- **Stanford Memory System** - Graph-based memory with semantic search
- **ChromaDB Vector Store** - Persistent embedding-based knowledge retrieval
- **Anti-Hallucination Protocol** - Validates AI outputs against reality

### 🔄 Self-Evolution Engine (Singularity)
- **Code Synthesis** - Generates new tools from descriptions (6 real templates)
- **AST-Based Refactoring** - Real code improvement via Abstract Syntax Trees
- **Polymorphic Mutation** - Transforms code to evade detection
- **Strategy Mutation** - Adapts attack strategies based on failures
- **Dynamic Tool Registration** - Creates and registers tools at runtime

### 🧬 Evolution Memory
- **Persistent Learning** - Remembers what works across sessions
- **Tool Penalty System** - Deprioritizes failing tools automatically
- **Strategy Profiles** - Multiple behavioral variants per attack type
- **Pattern Recognition** - Learns from failure contexts

### 🖥️ Modern UI System
- **Unified Display** - Consistent, minimalist interface
- **Dracula Theme** - Cyan/Green color scheme
- **Interactive Shell** - Full Turkish/English support
- **Real-time Scanning** - Live progress indicators
- **Smart Confirmations** - Context-aware prompts

### 🛡️ Self-Refining Engine
- **Policy Engine** - Learned behavioral constraints
- **Conflict Resolution** - Handles conflicting strategies
- **Failure Context Analysis** - Extracts patterns from errors
- **Automatic Replanning** - Recovers from failed steps

### 🔍 Reconnaissance
- **Port Scanning** - Nmap integration with smart defaults
- **Service Enumeration** - Automatic version detection
- **Subdomain Discovery** - Multiple techniques
- **WHOIS & DNS Intelligence** - Full DNS record analysis
- **Web Technology Fingerprinting** - CMS and framework detection
- **Passive OSINT** - Non-intrusive information gathering

### ⚡ Exploitation
- **Automated Vulnerability Scanning** - Nikto, Nuclei integration
- **SQL Injection** - Detection and exploitation with SQLMap
- **Web Application Testing** - XSS, CSRF, LFI/RFI, SSTI
- **Polyglot Payloads** - Context-agnostic exploit strings
- **AI Evasion** - Semantic mutation for WAF bypass
- **CVE Database Integration** - NVD-backed automatic exploit matching
- **Symbolic Execution** - Boundary-aware constraint solving for vulnerability discovery

### 🏢 Active Directory Attacks
- **Domain Enumeration** - Users, groups, computers, trusts
- **Kerberoasting** - Extract service account hashes
- **AS-REP Roasting** - Target accounts without pre-auth
- **Pass-the-Hash / Pass-the-Ticket** - Credential reuse
- **DCSync** - Domain controller replication attack
- **Lateral Movement** - PSExec, WMIExec, WinRM, SSH

### 🐝 Hive Mind (Distributed Operations)
- **Network Topology Discovery** - Map internal networks
- **Credential Harvesting** - SSH keys, passwords, tokens
- **Attack Path Analysis** - BloodHound-style pathfinding
- **Pivot Point Management** - Coordinate multi-hop attacks

### 📡 Command & Control Framework
- **Domain Fronting** - Hide C2 behind legitimate CDNs
- **DNS Tunneling** - Covert channel over DNS
- **Encrypted Beacons** - AES-256-GCM communication
- **Jitter Engine** - Human-like traffic patterns
- **Telegram C2** - Use Telegram as C2 channel
- **Steganography** - Hide data in images

### 🛡️ Evasion & Stealth
- **Advanced WAF Bypass Engine** - Intelligent WAF fingerprinting & evasion
  - WAF Fingerprinting: Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, F5, and more
  - Multi-layer encoding: Unicode, UTF-8, double URL, hex encoding
  - Adaptive mutation with pattern learning (SQLite-backed memory)
  - SQL injection bypass: inline comments, case variation, encoding chains
  - XSS bypass: SVG payloads, event handlers, protocol wrappers
  - Command injection: string concatenation, wildcard injection
  - HTTP smuggling & chunked encoding techniques
- **Ghost Protocol** - AST-based code transformation
- **Variable Obfuscation** - Random name generation
- **Dead Code Injection** - Anti-signature techniques
- **String Encryption** - Hide sensitive strings
- **Anti-Sandbox Checks** - Detect analysis environments

### 🔧 Weapon Foundry (Payload Generation)
- **Multi-Format Output** - Python, PowerShell, VBS, HTA, Bash, C#
- **Multi-Layer Encryption** - XOR, AES, RC4, ChaCha20-Poly1305
- **Shellcode Generation** - Pure Python/ASM (Keystone)
- **Anti-Debug Techniques** - Evade debuggers
- **Staged Payloads** - Multi-stage delivery

### 🐳 Sandbox Execution
- **Docker Isolation** - Run commands in containers
- **Resource Limits** - CPU and memory constraints
- **Automatic Cleanup** - No traces left on host
- **Graceful Fallback** - Works without Docker

### 📊 Professional Reporting
- **Multiple Formats** - HTML, Markdown, JSON, PDF
- **Executive Summary** - AI-generated overview
- **Risk Scoring** - CVSS-based severity
- **Evidence Documentation** - Screenshot embedding and logs
- **Remediation Guidance** - Actionable fixes

### 🔒 Security Features
- **Command Sanitization** - Prevents shell injection
- **Forbidden Command Blocking** - Protects against destructive commands
- **High-Risk Confirmation** - Requires approval for dangerous operations
- **Crash Reporter** - Detailed crash dumps for debugging

---

## 🚀 Installation

### Docker (Recommended)

```bash
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
docker-compose up -d
docker exec -it drakben python3 drakben.py
```

### Manual Installation

**Kali Linux / Debian:**
```bash
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 drakben.py
```

**Windows:**
```powershell
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python drakben.py
```

---

## ⚙️ Configuration

### LLM Setup

DRAKBEN works offline with rule-based fallback, but AI features require an LLM provider. Create `config/api.env`:

```env
# Option 1: OpenRouter (recommended - multiple models)
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct:free

# Option 2: OpenAI
OPENAI_API_KEY=your_key_here

# Option 3: Local Ollama (free, private)
LOCAL_LLM_URL=http://localhost:11434
LOCAL_LLM_MODEL=llama3.1
```

For Ollama, install from [ollama.ai](https://ollama.ai) and run:
```bash
ollama pull llama3.1
```

---

## 💻 Usage

### Interactive Mode

```bash
python drakben.py
```

### Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/target <IP/URL>` | Set target |
| `/untarget` | Clear target |
| `/scan` | Start autonomous scan |
| `/tools` | List available tools |
| `/status` | Show current state |
| `/shell` | Interactive shell mode (bilingual) |
| `/memory` | View memory system status |
| `/report` | Generate report |
| `/llm` | Configure LLM provider |
| `/config` | View/edit configuration |
| `/tr` | Switch to Turkish |
| `/en` | Switch to English |
| `/clear` | Clear screen |
| `/research` | Research mode |
| `/exit` | Exit DRAKBEN |

### Natural Language Examples

**Web Application Assessment:**
```
drakben> scan target.com
drakben> check for common web vulnerabilities
drakben> test sql injection on the login form
drakben> generate report
```

**Network Penetration Test:**
```
drakben> discover hosts on 10.0.0.0/24
drakben> identify services and versions
drakben> search for known CVEs
drakben> attempt exploitation on critical findings
```

**Active Directory Attack:**
```
drakben> enumerate the domain
drakben> find kerberoastable accounts
drakben> extract hashes
drakben> attempt lateral movement to DC
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DRAKBEN CORE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Brain   │──│ Planner  │──│  State   │──│ Executor │──│ Tool Selector│  │
│  │  (LLM)   │  │(Strategy)│  │(Singleton│  │ (Engine) │  │   (Kali)     │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │
│       │                           │                            │            │
│       ▼                           ▼                            ▼            │
│  ┌──────────┐              ┌──────────┐                 ┌──────────────┐   │
│  │ Evolution│              │ Self-    │                 │  Singularity │   │
│  │ Memory   │◄────────────►│ Refining │◄───────────────►│   Engine     │   │
│  │ (SQLite) │              │ Engine   │                 │ (Code Gen)   │   │
│  └──────────┘              └──────────┘                 └──────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                              MODULES                                        │
│  ┌────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ ┌──────────┐ ┌───────────┐  │
│  │ Recon  │ │ Exploit │ │ Payload │ │   C2   │ │ Hive Mind│ │ AD Attacks│  │
│  └────────┘ └─────────┘ └─────────┘ └────────┘ └──────────┘ └───────────┘  │
│  ┌────────────┐ ┌─────────────┐ ┌──────────────┐ ┌─────────────────────┐   │
│  │ WAF Evasion│ │ Ghost Proto │ │Weapon Foundry│ │   Report Generator  │   │
│  └────────────┘ └─────────────┘ └──────────────┘ └─────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                           LLM PROVIDERS                                     │
│           OpenRouter  │  OpenAI  │  Ollama  │  Custom API                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Attack Phases

| Phase | Description |
|-------|-------------|
| `IDLE` | Waiting for target assignment |
| `INIT` / `TARGET_SET` | Target validation and scope definition |
| `RECON` | Information gathering and enumeration |
| `VULN_SCAN` | Vulnerability identification |
| `EXPLOIT` | Exploitation attempts |
| `FOOTHOLD` | Initial access establishment |
| `POST_EXPLOIT` | Privilege escalation and persistence |
| `REPORTING` | Report generation and documentation |
| `COMPLETE` | Mission accomplished |
| `FAILED` | Attack chain terminated (recovery possible) |

---

## 🔬 Advanced Capabilities

### Singularity Engine

The Singularity Engine allows DRAKBEN to create new capabilities on-the-fly:

```python
# DRAKBEN can generate tools from descriptions
singularity.create_capability("A tool to exploit CVE-2024-XXXX")
```

### Evolution Memory

Persistent learning across sessions:
- **Tool Penalties** - Tools that fail repeatedly are deprioritized
- **Strategy Profiles** - Behavioral variants that mutate on failure
- **Pattern Learning** - Extracts patterns from failure contexts

### Ghost Protocol

Advanced evasion through code transformation:
- **AST Transformation** - Modifies code structure
- **Variable Renaming** - Randomized identifiers
- **Dead Code Injection** - Anti-signature noise
- **String Encryption** - Hides sensitive data

---

## 📁 Project Structure

```
drakben/
├── drakben.py                  # Main entry point
├── core/                       # Core engine
│   ├── agent/                  # Agent subsystem
│   │   ├── brain.py            # AI reasoning engine with memory integration
│   │   ├── state.py            # Global state management (singleton)
│   │   ├── planner.py          # Attack phase planning
│   │   ├── pentest_orchestrator.py  # State machine + LLM coordinator
│   │   ├── error_diagnostics.py     # Error analysis and recovery
│   │   ├── refactored_agent.py      # Self-refining agent loop
│   │   ├── cognitive/          # Cognitive subsystem
│   │   ├── memory/             # Stanford Memory System (graph + semantic)
│   │   └── recovery/           # Error recovery mechanisms
│   ├── execution/              # Execution layer
│   │   ├── execution_engine.py # Command runner
│   │   ├── sandbox_manager.py  # Docker sandbox isolation
│   │   └── tool_selector.py    # AI-driven tool selection
│   ├── intelligence/           # AI modules
│   │   ├── evolution_memory.py # Persistent learning (SQLite)
│   │   ├── self_refining_engine.py  # Policy engine + strategy mutation
│   │   └── coder.py            # Code generation assistant
│   ├── llm/                    # LLM abstraction layer
│   ├── network/                # Network utilities
│   ├── security/               # Security modules (sanitization, blocking)
│   ├── singularity/            # Code generation engine
│   │   ├── synthesizer.py      # AST-based code synthesis + refactoring
│   │   └── mutation.py         # Polymorphic code mutation
│   ├── storage/                # Persistence layer
│   ├── tools/                  # Tool registry system
│   │   ├── tool_registry.py    # Central tool hub (34+ tools)
│   │   ├── tool_parsers.py     # Output parsers
│   │   └── computer.py         # Computer interaction
│   └── ui/                     # User interface
│       ├── menu.py             # Main menu (bilingual TR/EN)
│       ├── interactive_shell.py # Interactive shell mode
│       └── unified_display.py  # Modern Dracula-themed display
├── modules/                    # Attack modules
│   ├── recon.py                # Reconnaissance (port scan, DNS, WHOIS)
│   ├── exploit/                # Exploitation package
│   │   ├── common.py           # SQLi, XSS, CSRF, SSTI, LFI, SSRF, etc.
│   │   └── __init__.py         # Public API re-exports
│   ├── c2_framework.py         # Command & Control (DNS tunneling, domain fronting)
│   ├── hive_mind.py            # Distributed operations & lateral movement
│   ├── weapon_foundry.py       # Payload generation (multi-format, multi-layer)
│   ├── waf_bypass_engine.py    # WAF fingerprinting & intelligent evasion
│   ├── waf_evasion.py          # WAF evasion utilities
│   ├── post_exploit.py         # Post-exploitation & persistence
│   ├── ad_attacks.py           # Active Directory attacks
│   ├── ad_extensions.py        # AD advanced attacks
│   ├── cve_database.py         # NVD CVE database integration
│   ├── nuclei.py               # Nuclei scanner integration
│   ├── metasploit.py           # Metasploit framework integration
│   ├── stealth_client.py       # Stealth communication client
│   ├── subdomain.py            # Subdomain enumeration
│   ├── payload.py              # Payload utilities
│   ├── report_generator.py     # Professional report generation
│   ├── native/                 # Low-level syscalls (Rust FFI)
│   ├── research/               # Research modules (symbolic execution)
│   └── social_eng/             # Social engineering modules
├── llm/                        # LLM integration
│   └── openrouter_client.py    # OpenRouter API client
├── tests/                      # Test suite (1363+ tests)
├── config/                     # Configuration files
│   ├── settings.json           # Application settings
│   ├── plugins.json            # Plugin configuration
│   └── api.env                 # API keys (gitignored)
├── plugins/                    # External plugins directory
├── .github/workflows/          # CI/CD pipelines
│   ├── drakben_ci.yml          # Continuous integration
│   └── drakben_cd.yml          # Continuous deployment
├── docker-compose.yml          # Docker orchestration
├── Dockerfile                  # Container image
├── requirements.txt            # Python dependencies
├── ruff.toml                   # Ruff linter config (36 rule groups)
├── mypy.ini                    # Mypy type checking config
└── sonar-project.properties    # SonarQube analysis config
```

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest --disable-warnings

# Run with coverage
python -m pytest --cov=core --cov=modules --cov-report=html

# Run quick tests (fail fast)
python -m pytest --maxfail=10 --disable-warnings --tb=short
```

**Current Status:** 1363+ tests passing | Ruff (35 rule groups) clean | Mypy strict | SonarQube compliant

---

## ⚠️ Legal Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Users are responsible for obtaining proper authorization before conducting any security assessments. Unauthorized access to computer systems is illegal.

**⚡ Always obtain written permission before testing systems you do not own.**

The developers assume no liability for misuse of this software.

---

## 🤝 Contributing

Contributions are welcome! Please read the contribution guidelines before submitting pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**DRAKBEN** — *Autonomous Pentesting, Simplified.*

Made with 🧛 by [@ahmetdrak](https://github.com/ahmetdrak)

</div>
