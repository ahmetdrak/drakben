<div align="center">

<img src="https://capsule-render.vercel.app/api?type=venom&color=0:8B0000,100:1a1a2e&height=200&section=header&text=DRAKBEN&fontSize=70&fontColor=ff5555&fontAlignY=35&desc=Autonomous%20Penetration%20Testing%20Framework&descAlignY=55&descSize=18&descColor=f8f8f2&animation=fadeIn" width="100%"/>

*Let AI handle the methodology. You focus on the results.*

[![CI](https://github.com/ahmetdrak/drakben/actions/workflows/drakben_ci.yml/badge.svg)](https://github.com/ahmetdrak/drakben/actions/workflows/drakben_ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-kali--rolling-blue.svg)](Dockerfile)
[![Tests](https://img.shields.io/badge/tests-1609%20passed-brightgreen.svg)](https://github.com/ahmetdrak/drakben/actions)
[![SonarCloud](https://img.shields.io/badge/SonarCloud-0%20issues-brightgreen.svg)](https://sonarcloud.io/)
[![Ruff](https://img.shields.io/badge/ruff-35%20rule%20groups-brightgreen.svg)](https://github.com/astral-sh/ruff)
[![MyPy](https://img.shields.io/badge/mypy-strict-blue.svg)](https://mypy-lang.org/)
[![Bandit](https://img.shields.io/badge/bandit-pass-brightgreen.svg)](https://bandit.readthedocs.io/)

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Architecture](#-architecture) · [Intelligence](#-intelligence-pipeline) · [Modules](#-attack-modules) · [CI/CD](#-cicd-pipeline) · [Contributing](#-contributing)

</div>

---

## 🎯 What is DRAKBEN?

DRAKBEN is an **AI-powered autonomous penetration testing framework** built in Python. It understands natural language commands and executes full security assessments — from reconnaissance to exploitation to reporting — with minimal human intervention. Instead of memorizing complex tool syntax, describe what you want in plain language.

```
You: "Scan the target for open ports and check for web vulnerabilities"
DRAKBEN: Executing nmap → Analyzing services → Running nikto → Found 3 potential issues...
```

**v2.5.0** — 234 tracked files · 105 core modules · 38 attack modules · 53 test suites · 34 registered tools · 21 intelligence modules

### Key Differentiators

| Feature | Traditional Tools | DRAKBEN |
|---------|-------------------|---------|
| Interface | CLI flags & syntax | Natural language (TR/EN) |
| Decision Making | Manual | AI-driven autonomous |
| Learning | Static | Self-evolving (SQLite-backed) |
| State Management | Stateless | Persistent singleton state |
| Error Recovery | Manual restart | Self-healing with diagnostics |
| Memory | None | Stanford graph + ChromaDB vectors |
| Evasion | Manual payloads | Polymorphic mutation engine |
| Multi-LLM | Single provider | OpenRouter / Ollama / OpenAI / Custom |

---

## ✨ Features

### 🧠 AI-Driven Core

- **Natural Language Interface** — Talk to DRAKBEN like a colleague
- **Multi-LLM Support** — OpenRouter (100+ models), Ollama (local/private), OpenAI, Custom APIs
- **Stanford Memory System** — Graph-based memory with perceive → retrieve → reflect cycle
- **ChromaDB Vector Store** — Persistent embedding-based knowledge retrieval
- **Anti-Hallucination Protocol** — Validates AI outputs against runtime reality
- **Bilingual UI** — Full Turkish and English support (`/tr` and `/en`)
- **Context-Aware Tool Selection** — Picks the right tool based on attack phase and target state

### 🔄 Self-Evolution Engine (Singularity)

- **Code Synthesis** — Generates new tools from natural language descriptions (6 real templates)
- **AST-Based Refactoring** — Real code improvement via Abstract Syntax Trees
- **Polymorphic Mutation** — Transforms attack code to evade detection
- **Strategy Mutation** — Adapts attack strategies based on failure patterns
- **Dynamic Tool Registration** — Creates and registers new tools at runtime

### 🧬 Evolution Memory

- **Persistent Learning** — Remembers what works across sessions (SQLite-backed)
- **Tool Penalty System** — Deprioritizes failing tools automatically
- **Strategy Profiles** — Multiple behavioral variants per attack type
- **Pattern Recognition** — Extracts actionable patterns from failure contexts

### 🖥️ Modern UI System

- **Unified Display** — Consistent, minimalist Dracula-themed interface (Cyan/Green)
- **Interactive Shell** — Full bilingual TR/EN support with `prompt_toolkit`
- **Real-time Scanning** — Live progress indicators during operations
- **Smart Confirmations** — Context-aware prompts for high-risk operations
- **Web API** — FastAPI REST endpoints + SSE event streaming for external dashboards

---

## 🧪 Intelligence Pipeline

DRAKBEN's intelligence system spans three generations: built-in reasoning, structured AI reasoning (v2), and advanced predictive modules (v3).

### Intelligence v2 — Reasoning Pipeline

| Module | Purpose |
|--------|---------|
| **ReAct Loop** | Thought → Action → Observation cycle for structured multi-step LLM reasoning with iteration tracking |
| **Structured Output Parser** | Multi-strategy extraction of JSON, tables, key-value pairs from raw LLM responses with fallback chains |
| **Tool Output Analyzer** | Classifies tool results (success / partial / fail), extracts IPs, ports, CVEs, URLs from output text |
| **Context Compressor** | Token-aware conversation history compression with priority scoring and budget management |
| **Self-Reflection Engine** | Post-action reflection with confidence scoring, lesson extraction, and improvement suggestions |

### Intelligence v3 — Advanced AI Modules

| Module | Purpose |
|--------|---------|
| **Few-Shot Learning Engine** | Dynamic example selection from past successes for in-context learning with similarity matching |
| **Cross-Tool Correlator** | Pattern recognition across tool outputs: port↔CVE mapping, service↔vulnerability correlation, multi-source evidence |
| **Adversarial Adapter** | WAF/IDS evasion payload generator with encoding mutations (URL, Unicode, hex, double-encode) |
| **Exploit Predictor** | ML-style probability scoring for exploit success based on service fingerprints and version analysis |
| **Knowledge Base** | SQLite-backed cross-session knowledge store with semantic recall and deduplication |
| **Model Router** | Intelligent LLM model selection based on task complexity, token budget, and provider capabilities |

### Self-Refining Engine

- **Policy Engine** — Learned behavioral constraints from past runs
- **Conflict Resolution** — Handles conflicting strategy recommendations
- **Failure Context Analysis** — Extracts patterns from diverse error types
- **Automatic Replanning** — Recovers from failed steps without human intervention

---

## 🗡️ Attack Modules

### 🔍 Reconnaissance
- **Port Scanning** — Nmap integration with smart defaults and stealth scans
- **Service Enumeration** — Automatic version detection and fingerprinting
- **Subdomain Discovery** — Multiple techniques (brute force, Certificate Transparency)
- **WHOIS & DNS Intelligence** — Full DNS record analysis (A, AAAA, MX, NS, CNAME, TXT, SOA)
- **Web Technology Fingerprinting** — CMS and framework detection
- **Passive OSINT** — Non-intrusive information gathering

### ⚡ Exploitation
- **SQL Injection** — Error-based, time-based blind, UNION-based with 5+ DBMS signature detection (SQLMap + native)
- **NoSQL Injection** — MongoDB operator injection
- **XSS / CSRF / SSTI / LFI / RFI / SSRF** — Full web application vulnerability testing
- **File Inclusion** — PHP wrappers (filter, input, data, phar), path traversal with encoding bypass, log poisoning LFI→RCE
- **File Upload Bypass** — 8 techniques for bypassing upload restrictions
- **Authentication Bypass** — JWT token manipulation (none algorithm, claim tampering), session fixation, 20+ default credential sets
- **Header Security Audit** — HTTP security header scoring (A-F grading), CORS misconfiguration, CSP bypass analysis
- **LDAP Injection** — Directory service exploitation
- **OS Command Injection** — String concatenation, wildcard injection techniques
- **Polyglot Payloads** — Context-agnostic exploit strings
- **CVE Database Integration** — NVD-backed automatic exploit matching with CVSS scoring
- **Symbolic Execution** — Boundary-aware constraint solving for vulnerability discovery

### 🏢 Active Directory Attacks
- **Domain Enumeration** — Users, groups, computers, trusts
- **Kerberoasting** — Extract service account hashes
- **AS-REP Roasting** — Target accounts without pre-authentication
- **Pass-the-Hash / Pass-the-Ticket** — Credential reuse
- **DCSync** — Domain controller replication attack
- **Lateral Movement** — PSExec, WMIExec, WinRM, SSH
- **BloodHound-style Pathfinding** — Shortest path to Domain Admin

### 🐝 Hive Mind (Distributed Operations)
- **Network Topology Discovery** — Map internal network architecture
- **Credential Harvesting** — SSH keys, passwords, tokens
- **Attack Path Analysis** — Multi-hop path finding and scoring
- **Pivot Point Management** — Coordinate multi-hop attacks
- **Auto-Pivoting** — TunnelManager for automatic lateral movement

### 📡 Command & Control Framework
- **Domain Fronting** — Hide C2 behind legitimate CDNs
- **DNS Tunneling** — Covert channel over DNS
- **DNS-over-HTTPS (DoH)** — C2 transport over encrypted DNS
- **Encrypted Beacons** — AES-256-GCM communication
- **Jitter Engine** — Human-like traffic patterns to evade detection
- **Telegram C2** — Use Telegram as control channel
- **Steganography** — Hide data in images (LSB encoding)

### 🛡️ Evasion & Stealth
- **Advanced WAF Bypass Engine** — Intelligent WAF fingerprinting & adaptive evasion
  - WAF Fingerprinting: Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, F5 BIG-IP, and more
  - Multi-layer encoding: Unicode, UTF-8, double URL, hex encoding
  - Adaptive mutation with pattern learning (SQLite-backed memory)
  - SQL injection bypass: inline comments, case variation, encoding chains
  - XSS bypass: SVG payloads, event handlers, protocol wrappers
  - Command injection: string concatenation, wildcard injection
  - HTTP smuggling & chunked encoding techniques
- **Ghost Protocol** — AST-based code transformation for evasion
- **Variable Obfuscation** — Randomized identifier generation
- **Dead Code Injection** — Anti-signature techniques
- **String Encryption** — Hide sensitive strings in payloads
- **Anti-Sandbox Checks** — Detect analysis environments

### 🔧 Weapon Foundry (Payload Generation)
- **Multi-Format Output** — Python, PowerShell, VBS, HTA, Bash, C#
- **Multi-Layer Encryption** — XOR, AES, RC4, ChaCha20-Poly1305
- **Shellcode Generation** — Pure Python/ASM (Keystone engine)
- **Anti-Debug Techniques** — Evade debugger analysis
- **Staged Payloads** — Multi-stage delivery chains

### 🐳 Sandbox Execution
- **Docker Isolation** — Run commands in isolated containers
- **Resource Limits** — CPU and memory constraints
- **Automatic Cleanup** — No traces left on host
- **Graceful Fallback** — Works without Docker (native mode)

### 📊 Professional Reporting
- **Multiple Formats** — HTML, Markdown, JSON, PDF
- **Executive Summary** — AI-generated overview
- **Risk Scoring** — CVSS-based severity classification
- **Evidence Documentation** — Screenshots, logs, and proof-of-concept
- **Remediation Guidance** — Actionable fix recommendations

### 🔒 Security Features
- **Command Sanitization** — Prevents shell injection
- **Forbidden Command Blocking** — Protects against destructive commands (`rm -rf /`, etc.)
- **High-Risk Confirmation** — Requires approval for dangerous operations
- **API Key Protection** — Keys excluded from config repr, never logged
- **Crash Reporter** — Detailed crash dumps for debugging

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

### Optional Extras

```bash
# For enhanced capabilities (Metasploit, Nuclei, etc.)
pip install -r requirements-extra.txt
```

---

## ⚙️ Configuration

### LLM Setup

DRAKBEN works offline with rule-based fallback, but AI features require an LLM provider. Create `config/api.env`:

```env
# Option 1: OpenRouter (recommended — access to 100+ models)
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct:free

# Option 2: OpenAI
OPENAI_API_KEY=your_key_here

# Option 3: Local Ollama (free, private, no data leaves your machine)
LOCAL_LLM_URL=http://localhost:11434
LOCAL_LLM_MODEL=llama3.1
```

For Ollama, install from [ollama.ai](https://ollama.ai) and run:
```bash
ollama pull llama3.1
```

### Settings

Application settings are stored in `config/settings.json`. Available options:

| Setting | Default | Description |
|---------|---------|-------------|
| `llm_provider` | `auto` | LLM provider: `auto`, `openrouter`, `ollama`, `openai` |
| `language` | `en` | UI language: `en`, `tr` |
| `stealth_mode` | `false` | Enable stealth scanning mode |
| `max_threads` | `4` | Maximum concurrent threads |
| `timeout` | `30` | Default operation timeout (seconds) |
| `auto_approve` | `false` | Auto-approve all commands (dangerous!) |

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
| `/tools` | List available tools (34 built-in) |
| `/status` | Show current state |
| `/shell` | Interactive shell mode |
| `/memory` | View memory system status |
| `/report` | Generate report |
| `/llm` | Configure LLM provider |
| `/config` | View/edit configuration |
| `/tr` | Switch to Turkish |
| `/en` | Switch to English |
| `/research` | Research mode |
| `/clear` | Clear screen |
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
│                           drakben.py (Entry Point)                          │
│        CLI bootstrap · config loading · LLM client init · UI loop          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐ │
│  │  Agent   │  │ Planner  │  │Intelligence  │  │ Executor │  │  Tools   │ │
│  │ (Brain)  │──│(Strategy)│──│(21 modules)  │──│ (Engine) │──│(34 tools)│ │
│  │ 28 files │  │          │  │  v2 + v3     │  │ sandbox  │  │ registry │ │
│  └──────────┘  └──────────┘  └──────────────┘  └──────────┘  └──────────┘ │
│       │              │              │                  │            │       │
│       ▼              ▼              ▼                  ▼            ▼       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐│
│  │ Memory   │  │ Security │  │Singularity│  │ Network  │  │   Storage    ││
│  │(Stanford)│  │(Ghost    │  │(Code Gen) │  │(Stealth) │  │(ChromaDB +   ││
│  │graph+vec │  │ Protocol)│  │AST mutate │  │curl_cffi │  │ SQLite)      ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────────┘│
│                                                                             │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────────┐              │
│  │  LLM     │  │ Events    │  │Observ-   │  │ Knowledge    │              │
│  │ Engine   │  │ Bus(pub/  │  │ability   │  │ Graph        │              │
│  │ 8 files  │  │  sub)     │  │(tracing) │  │ (SQLite BFS) │              │
│  └──────────┘  └───────────┘  └──────────┘  └──────────────┘              │
│                                                                             │
│                           core/ — 105 Python files                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                          ATTACK MODULES (38 files)                          │
│                                                                             │
│  ┌────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌─────────┐ │
│  │ Recon  │ │Exploit  │ │ Payload │ │   C2    │ │Hive Mind │ │AD Attack│ │
│  │        │ │(6 files)│ │         │ │Framework│ │          │ │         │ │
│  └────────┘ └─────────┘ └─────────┘ └─────────┘ └──────────┘ └─────────┘ │
│  ┌────────────┐ ┌───────────┐ ┌─────────────┐ ┌──────────┐ ┌───────────┐ │
│  │WAF Bypass  │ │Ghost Proto│ │Weapon Foundry│ │Social Eng│ │  Report   │ │
│  │(adaptive)  │ │(AST-based)│ │(multi-format)│ │(OSINT+   │ │ Generator │ │
│  └────────────┘ └───────────┘ └─────────────┘ │ phishing) │ └───────────┘ │
│                                                └──────────┘               │
├─────────────────────────────────────────────────────────────────────────────┤
│                           LLM PROVIDERS                                     │
│         OpenRouter  │  OpenAI  │  Ollama (local)  │  Custom API            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Sub-packages (10)

| Package | Files | Purpose |
|---------|-------|---------|
| `core/agent/` | 28 (incl. 3 sub-pkgs) | Brain, planner, state, memory, cognitive, recovery |
| `core/intelligence/` | 21 | Self-refining engine, ReAct loop, context compression, v2 + v3 AI |
| `core/execution/` | — | Execution engine, sandbox manager, tool selector |
| `core/llm/` | 8 | LLM engine, token counter, multi-turn, RAG pipeline, async client |
| `core/network/` | — | Web researcher, stealth client |
| `core/security/` | — | Ghost protocol, credential store, command sanitization |
| `core/singularity/` | — | Code synthesis, AST mutation, chaos engine |
| `core/storage/` | — | Persistence layer, vector store |
| `core/tools/` | — | Tool registry (34 built-in tools), output parsers |
| `core/ui/` | — | Menu, interactive shell, display, web API |

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

- **AST-based code synthesis** with 6+ real templates
- **Security gates** prevent generation of destructive code
- **Polymorphic mutation** for evasion-aware payloads

### Ghost Protocol

Advanced evasion through code transformation:
- **AST Transformation** — Modifies code structure at the abstract syntax tree level
- **Variable Renaming** — Randomized identifier generation
- **Dead Code Injection** — Anti-signature noise insertion
- **String Encryption** — Hides sensitive data in encoded form

### Evolution Memory

Persistent learning across sessions:
- **Tool Penalties** — Tools that fail repeatedly are deprioritized
- **Strategy Profiles** — Multiple behavioral variants that mutate on failure
- **Pattern Learning** — Extracts patterns from failure contexts for future decisions

### Error Diagnostics

Advanced error analysis with 18+ recognized patterns:
- Missing tool, permission denied, timeout, syntax error, authentication failure
- Network unreachable, memory exhaustion, disk full, port conflict
- Database error, parse failure, version mismatch, rate limiting, firewall block
- Full Turkish and English error descriptions with recovery suggestions

---

## 🔄 CI/CD Pipeline

### Continuous Integration (8 Jobs)

Every push and pull request triggers the full quality pipeline:

```
┌──────────┐  ┌──────────┐  ┌──────────┐
│   Ruff   │  │  MyPy    │  │  Bandit  │     Stage 1 (parallel)
│  Lint &  │  │ Strict   │  │ Security │
│  Format  │  │Type Check│  │  Audit   │
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │
     └─────────────┼─────────────┘
                   ▼
     ┌─────────────────────────┐
     │    Tests (Matrix)       │          Stage 2
     │  Python 3.11 / 3.12 /  │
     │        3.13             │
     └────────────┬────────────┘
                  ▼
     ┌────────────────────────┐
     │  E2E Integration Tests │           Stage 3
     └────────────┬───────────┘
                  ▼
  ┌───────────┐  ┌─────────────┐
  │ SonarCloud│  │Docker Build │          Stage 4
  │ Analysis  │  │   Check     │
  └─────┬─────┘  └──────┬──────┘
        └────────┬───────┘
                 ▼
        ┌────────────────┐
        │   CI Gate ✓    │                Final
        └────────────────┘
```

| Job | Tool | Scope |
|-----|------|-------|
| **Lint & Format** | Ruff (35 rule groups) | All Python files |
| **Type Safety** | MyPy (strict mode) | `core/` (105 files) |
| **Security Audit** | Bandit | `core/` + `modules/` |
| **Tests** | pytest (1609+ tests) | Python 3.11, 3.12, 3.13 matrix |
| **E2E Integration** | pytest | Cross-module integration flows |
| **SonarCloud** | SonarQube | Full project analysis |
| **Docker Build** | Docker | Kali Linux image validation |
| **CI Gate** | — | All-jobs-must-pass gate |

### Continuous Deployment

Tag-triggered release pipeline:
- Auto-changelog generation from commits
- GitHub Release creation with assets
- Docker Hub multi-tag push (`latest`, `vX.Y.Z`)

---

## 📁 Project Structure

```
drakben/
├── drakben.py                       # Main entry point
├── core/                            # Core engine (105 files)
│   ├── agent/                       # Agent subsystem (28 files incl. sub-pkgs)
│   │   ├── brain.py                 # MasterOrchestrator — central reasoning hub
│   │   ├── brain_*.py               # Brain decomposition (cognitive, context, decision, reasoning, self-correction)
│   │   ├── state.py                 # AgentState singleton — single source of truth
│   │   ├── planner.py               # AdaptivePlanner — multi-step attack plans
│   │   ├── pentest_orchestrator.py  # Phase-driven pentest state machine
│   │   ├── refactored_agent.py      # Self-refining agent loop with Intelligence v2/v3
│   │   ├── tool_dispatch.py         # Centralized tool routing with error isolation
│   │   ├── multi_agent.py           # Parallel agent orchestration
│   │   ├── error_diagnostics.py     # 18+ error pattern matching (TR/EN)
│   │   ├── ra_tool_executors.py     # Refactored agent tool execution handlers
│   │   ├── ra_tool_recovery.py      # Tool failure recovery strategies
│   │   ├── ra_state_updates.py      # Agent state transition logic
│   │   ├── cognitive/               # Generative Memory (perceive → retrieve → reflect)
│   │   ├── memory/                  # Tool effectiveness & strategy evolution
│   │   └── recovery/                # Error recovery & automatic retry
│   ├── intelligence/                # AI modules (21 files)
│   │   ├── react_loop.py            # ReAct: Thought → Action → Observation
│   │   ├── structured_output.py     # LLM output parsing (JSON, tables, KV)
│   │   ├── tool_output_analyzer.py  # Tool result classification & data extraction
│   │   ├── context_compressor.py    # Token-budget context compression
│   │   ├── self_reflection.py       # Post-action confidence scoring
│   │   ├── few_shot_engine.py       # Dynamic few-shot example selection
│   │   ├── cross_correlator.py      # Cross-tool finding correlation
│   │   ├── adversarial_adapter.py   # WAF/IDS evasion mutation generator
│   │   ├── exploit_predictor.py     # Exploit success probability scoring
│   │   ├── knowledge_base.py        # Cross-session knowledge (SQLite)
│   │   ├── model_router.py          # Intelligent LLM model selection
│   │   ├── evolution_memory.py      # Persistent learning (SQLite)
│   │   ├── self_refining_engine.py  # Policy engine + strategy mutation
│   │   ├── coder.py                 # Code generation assistant
│   │   └── ...                      # SRE sub-modules, universal adapter
│   ├── llm/                         # LLM abstraction layer (8 files)
│   │   ├── llm_engine.py            # Unified LLM interface with caching & retry
│   │   ├── token_counter.py         # Per-model token counting (tiktoken)
│   │   ├── multi_turn.py            # Conversation history with sliding window
│   │   ├── output_models.py         # Pydantic-based output validation
│   │   ├── rag_pipeline.py          # Retrieval-Augmented Generation
│   │   ├── async_client.py          # Non-blocking LLM calls
│   │   └── local_provider.py        # Local LLM provider (Ollama) integration
│   ├── execution/                   # Command execution & tool selection
│   ├── network/                     # Stealth HTTP client, web research
│   ├── security/                    # Ghost protocol, credential store, sanitization
│   ├── singularity/                 # Code synthesis, AST mutation, chaos engine
│   ├── storage/                     # Persistence layer, vector store
│   ├── tools/                       # Tool registry (34 built-in tools)
│   ├── ui/                          # Menu, shell, display, web API
│   ├── events.py                    # Thread-safe pub/sub EventBus
│   ├── observability.py             # Distributed tracing & metrics (p50/p95/p99)
│   ├── knowledge_graph.py           # SQLite-backed graph DB with BFS pathfinding
│   ├── config.py                    # Configuration management (dataclass)
│   ├── plugin_loader.py             # Dynamic plugin loading system
│   └── stop_controller.py           # Graceful shutdown controller
├── modules/                         # Attack modules (38 files)
│   ├── recon.py                     # Reconnaissance (nmap, DNS, WHOIS)
│   ├── exploit/                     # Exploitation package (6 files)
│   │   ├── common.py                # SQLi, XSS, CSRF, SSTI, LFI, SSRF, brute-force
│   │   ├── injection.py             # Advanced injection (SQL, NoSQL, LDAP, OS cmd)
│   │   ├── auth_bypass.py           # JWT manipulation, session fixation, default creds
│   │   ├── header_security.py       # HTTP header audit, CORS, CSP analysis
│   │   └── file_inclusion.py        # LFI/RFI, PHP wrappers, upload bypass
│   ├── c2_framework.py              # C2 (DNS tunneling, domain fronting, beacons)
│   ├── hive_mind.py                 # Distributed ops & lateral movement
│   ├── weapon_foundry.py            # Payload generation (multi-format, encrypted)
│   ├── waf_bypass_engine.py         # WAF fingerprinting & intelligent evasion
│   ├── waf_evasion.py               # WAF evasion utilities
│   ├── post_exploit.py              # Post-exploitation & persistence
│   ├── ad_attacks.py                # Active Directory attacks
│   ├── ad_extensions.py             # AD advanced attacks (DCSync, lateral)
│   ├── cve_database.py              # NVD CVE database integration
│   ├── nuclei.py                    # Nuclei scanner integration
│   ├── metasploit.py                # Metasploit framework integration
│   ├── stealth_client.py            # Stealth communication (curl_cffi)
│   ├── subdomain.py                 # Subdomain enumeration
│   ├── payload.py                   # Payload utilities
│   ├── report_generator.py          # Professional report generation
│   ├── cloud_scanner.py             # AWS/GCP/Azure misconfiguration detection
│   ├── native/                      # Low-level syscalls (Rust FFI)
│   ├── research/                    # Symbolic execution, constraint solving
│   └── social_eng/                  # OSINT spider, phishing, social profiling
├── llm/                             # LLM integration
│   └── openrouter_client.py         # OpenRouter API client
├── tests/                           # Test suite (53 test files, 1609+ tests)
│   ├── conftest.py                  # Shared fixtures (tmp_path, mock LLM, etc.)
│   ├── test_e2e_integration.py      # 35 end-to-end cross-module tests
│   ├── test_exploit_modules.py      # 50+ exploit sub-module tests
│   ├── test_architecture_improvements.py  # 93 architecture tests
│   └── ...                          # Unit tests per module
├── config/                          # Configuration files
│   ├── settings.json                # Application settings
│   ├── plugins.json                 # Plugin configuration
│   └── api.env                      # API keys (gitignored)
├── plugins/                         # External plugins directory
├── .github/workflows/               # CI/CD pipelines
│   ├── drakben_ci.yml               # 8-job quality & security pipeline
│   └── drakben_cd.yml               # Tag-triggered release pipeline
├── docker-compose.yml               # Docker orchestration
├── Dockerfile                       # Kali Linux container image
├── requirements.txt                 # Core + test dependencies (21 packages)
├── requirements-extra.txt           # Optional dependencies
├── ruff.toml                        # Ruff linter (35 rule groups, line-length 120)
├── mypy.ini                         # MyPy strict type checking
├── tools.json                       # Tool definitions (16 entries)
├── scripts/                         # Utility scripts
│   └── update_imports.py            # Import path updater
├── sonar-project.properties         # SonarCloud analysis config
├── API.md                           # REST API documentation
├── ARCHITECTURE.md                  # Detailed architecture document
├── CHANGELOG.md                     # Full version history
├── CONTRIBUTING.md                  # Contribution guidelines
├── SECURITY.md                      # Security policy
└── LICENSE                          # MIT License
```

---

## 🧪 Testing

```bash
# Run all tests (1609+ tests)
python -m pytest --disable-warnings

# Run with coverage
python -m pytest --cov=core --cov=modules --cov-report=html

# Run quick tests (fail fast)
python -m pytest --maxfail=10 --disable-warnings --tb=short

# Run specific test suite
python -m pytest tests/test_e2e_integration.py -v
python -m pytest tests/test_exploit_modules.py -v
```

### Quality Metrics

| Metric | Status |
|--------|--------|
| **Tests** | 1609+ passing (0 failures, 0 skips) |
| **Ruff** | Clean — 35 rule groups enforced |
| **MyPy** | Strict mode on `core/` — 0 errors |
| **Bandit** | Security scan — passing |
| **SonarCloud** | 0 issues |
| **CI Matrix** | Python 3.11, 3.12, 3.13 all green |

---

## ⚠️ Legal Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Users are responsible for obtaining proper authorization before conducting any security assessments. Unauthorized access to computer systems is illegal.

**⚡ Always obtain written permission before testing systems you do not own.**

The developers assume no liability for misuse of this software.

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Ensure all CI checks pass (`ruff`, `mypy`, `pytest`, `bandit`)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

See also:
- [ARCHITECTURE.md](ARCHITECTURE.md) — Detailed architecture documentation
- [API.md](API.md) — REST API reference
- [CHANGELOG.md](CHANGELOG.md) — Version history
- [SECURITY.md](SECURITY.md) — Security policy and reporting

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**DRAKBEN v2.5.0** — *Autonomous Pentesting, Simplified.*

234 files · 105 core modules · 38 attack modules · 34 tools · 21 AI modules · 1609 tests

Made with 🧛 by [@ahmetdrak](https://github.com/ahmetdrak)

</div>
