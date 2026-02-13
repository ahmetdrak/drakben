# DRAKBEN Architecture

> **Autonomous AI-Driven Penetration Testing Framework**

This document describes the layered architecture, data flow, module responsibilities, and design decisions behind DRAKBEN.

---

## High-Level Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        drakben.py (Entry)                        │
│   CLI bootstrap · config loading · LLM client init · UI loop    │
└─────────────────────────────┬────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────┐
│                         core/ (Engine)                            │
│                                                                  │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │  agent/   │  │  execution/  │  │intelligence/ │               │
│  │ brain     │──│ engine       │──│ self-refine  │               │
│  │ planner   │  │ tool_select  │  │ react_loop   │               │
│  │ state     │  │ sandbox      │  │ few_shot     │               │
│  │ memory/   │  └──────────────┘  │ correlator   │               │
│  │ cognitive/│                    │ predictor    │               │
│  │ recovery/ │  ┌──────────────┐  │ knowledge_db │               │
│  └──────────┘  │  security/   │  │ model_router │               │
│                 │ ghost_proto  │  └──────────────┘               │
│                 │ cred_store   │  ┌──────────────┐               │
│                 └──────────────┘  │ singularity/ │               │
│                                   │ chaos engine │               │
│                                   │ infinite loop│               │
│                                   └──────────────┘               │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐                   │
│  │  llm/    │  │ network/ │  │   storage/   │                   │
│  │ llm_utils│  │ stealth  │  │ vector store │                   │
│  └──────────┘  └──────────┘  └──────────────┘                   │
└──────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────┐
│                      modules/ (Attack Suite)                     │
│                                                                  │
│  recon · subdomain · exploit · c2_framework · hive_mind          │
│  ad_attacks · ad_extensions · weapon_foundry · payload            │
│  waf_bypass_engine · waf_evasion · post_exploit · cve_database   │
│  nuclei · metasploit · stealth_client · report_generator         │
└──────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────┐
│                       llm/ (AI Backend)                          │
│              openrouter_client.py — Ollama / OpenAI              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Layer Descriptions

### 1. Entry Point — `drakben.py`

The single CLI entry point. Responsibilities:
- Parse command-line arguments
- Load `config/settings.json`, `config/api.env`, `config/plugins.json`
- Instantiate the LLM client (`llm/openrouter_client.py`)
- Boot the `MasterOrchestrator` (brain) and run the interactive loop
- Handle graceful shutdown via `core/stop_controller.py`

### 2. Core Engine — `core/`

The core package is the framework backbone. It never performs attacks directly — it **orchestrates** modules.

#### 2.1 Agent (`core/agent/`)

| File | Purpose |
|---|---|
| `brain.py` | `MasterOrchestrator` — central reasoning hub. Receives user requests, decomposes into steps, dispatches tool calls, self-corrects. Contains `ContinuousReasoning`, `DecisionEngine`, `SelfCorrection`, `ContextManager`. |
| `planner.py` | `AdaptivePlanner` — creates multi-step attack plans from strategy profiles. Supports dependency resolution, re-planning, and step success/failure tracking. |
| `state.py` | `AgentState` — **single source of truth** (thread-safe singleton). Tracks target, attack phase, open services, vulnerabilities, credentials, foothold status, iteration count, agentic-loop protections (hallucination detection, stagnation check, state hash). |
| `error_diagnostics.py` | `ErrorDiagnosticsMixin` — pattern-matches 18+ error types (missing tool, permission, timeout, syntax, auth, network, memory, disk, port, database, parse, version, rate-limit, firewall, resource) in English and Turkish. |
| `pentest_orchestrator.py` | High-level orchestrator wrapping phase-driven pentest flow: RECON → VULN_SCAN → EXPLOIT → FOOTHOLD → POST_EXPLOIT → COMPLETE. |

##### Sub-packages

- **`cognitive/`** — Generative Memory architecture (perceive → retrieve → reflect cycle). Contains `MemoryNode`, `CognitiveMemory`, `PentestRetrieval`, and `ReflectionEngine`.
- **`memory/`** — Evolution memory for long-term learning. Stores tool effectiveness, attack patterns, and strategy evolution across sessions.
- **`recovery/`** — Error recovery and automatic retry strategies.

#### 2.2 Execution (`core/execution/`)

| File | Purpose |
|---|---|
| `execution_engine.py` | `ExecutionEngine` + `SmartTerminal` — sandboxed command execution with timeout, output parsing, kill handling. `OutputParser` normalizes tool stdout. `CommandGenerator` builds tool-specific CLI commands. |
| `tool_selector.py` | `ToolSelector` + `ToolSpec` — deterministic tool selection based on current phase, target services, and evolutionary priority scores. Supports dynamic plugin registration. |
| `sandbox.py` | `ASTSandbox` — static analysis of code before execution. Blocks dangerous imports, eval/exec, system calls. |

#### 2.3 Intelligence (`core/intelligence/`)

Self-evolution, adaptive reasoning, and AI-augmented analysis capabilities.

| Module | Description |
|---|---|
| `evolution_memory.py` | Persistent learning across sessions with tool penalty system (SQLite) |
| `self_refining_engine.py` | Policy engine, conflict resolution, strategy mutation |
| `coder.py` | Code generation assistant |
| **Intelligence v2** | |
| `react_loop.py` | ReAct reasoning: Thought→Action→Observation cycle for multi-step LLM reasoning |
| `structured_output.py` | Multi-strategy LLM output parser (JSON, tables, key-value extraction) |
| `tool_output_analyzer.py` | Tool result classification (success/partial/fail), finding extraction |
| `context_compressor.py` | Token-budget conversation compression with priority scoring |
| `self_reflection.py` | Post-action reflection, confidence scoring, lesson extraction |
| **Intelligence v3** | |
| `few_shot_engine.py` | Dynamic few-shot example selection from past successes |
| `cross_correlator.py` | Cross-tool pattern recognition (port↔CVE, service↔vulnerability) |
| `adversarial_adapter.py` | WAF/IDS evasion variant generation with encoding mutations |
| `exploit_predictor.py` | ML-style exploit success probability scoring |
| `knowledge_base.py` | SQLite-backed cross-session knowledge with semantic recall |
| `model_router.py` | Intelligent LLM selection based on task complexity and token budget |

#### 2.4 Security (`core/security/`)

- **Ghost Protocol** — code obfuscation (identifier mangling, XOR encoding, ROT13), RAM cleaning (`SecureRAMCleaner`), session cleanup, secure file deletion
- **Credential Store** — encrypted credential storage with AES-256-GCM
- **Security Utils** — input sanitization, URL validation

#### 2.5 Singularity (`core/singularity/`)

Chaos engineering and stability testing:
- State pollution injection
- Infinite-loop detection
- Stress testing harness

#### 2.6 Other Core Modules

| File | Purpose |
|---|---|
| `config.py` | `DrakbenConfig` singleton — loads/saves settings, manages API keys, timeout configs, LLM client factory |
| `llm_utils.py` | `parse_llm_json_response` (3-strategy JSON extractor), `format_llm_prompt` (standardized prompt builder) |
| `plugin_loader.py` | `PluginLoader` — dynamically loads `.py` files from `plugins/` directory, validates `register()` → `ToolSpec`, deduplicates |
| `logging_config.py` | Structured logging setup with file + console handlers |
| `stop_controller.py` | Graceful shutdown signal handler |

### 3. Attack Modules — `modules/`

All attack modules use **lazy imports** via `modules/__init__.py` (`__getattr__` pattern). Only loaded when first accessed.

| Module | Lines | Description |
|---|---|---|
| `recon.py` | ~700 | Passive recon (DNS, WHOIS, technology detection, CMS fingerprinting) + **native async TCP port scanner** (`scan_ports`) |
| `subdomain.py` | ~400 | Subdomain enumeration via DNS brute-force, certificate transparency |
| `exploit/` | ~2200 | Package: SQLi, XSS, LFI, XXE, SSRF, CSRF, SSTI, IDOR, Deserialization testing. `PolyglotEngine`, `AIEvasion`. |
| `c2_framework.py` | ~600 | Command & Control: AES-256-GCM encrypted beacons, domain fronting, DNS tunneling, DoH transport, jitter engine |
| `hive_mind.py` | ~800 | Lateral movement: credential harvesting, pivot detection, SSH tunneling, Pass-the-Hash/Ticket, attack path calculation |
| `ad_attacks.py` | ~500 | Active Directory: Kerberos attacks, LDAP enumeration, AS-REP roasting |
| `ad_extensions.py` | ~600 | BloodHound graph analysis, Impacket wrappers, token impersonation |
| `weapon_foundry.py` | ~1200 | Payload generation: reverse shells (Bash/Python/PowerShell/C#/VBS/HTA), AES/ChaCha20 encryption, staged loaders |
| `payload.py` | ~500 | Payload obfuscation: PowerShell, Bash, AV bypass techniques |
| `waf_bypass_engine.py` | ~900 | Adaptive WAF bypass: SQL/XSS/Command injection variants, encoding chains, mutation memory |
| `waf_evasion.py` | ~300 | Legacy WAF evasion techniques |
| `post_exploit.py` | ~800 | Post-exploitation: Linux/Windows privesc, shell wrappers (SSH, WinRM, WebShell, C2) |
| `cve_database.py` | ~600 | CVE database: CVSS scoring, vulnerability matching, auto-update |
| `nuclei.py` | ~500 | Nuclei scanner integration |
| `metasploit.py` | ~500 | Metasploit RPC client: exploit execution, session management |
| `stealth_client.py` | ~400 | Stealth HTTP: fingerprint rotation, proxy chains, browser emulation |
| `report_generator.py` | ~1050 | Professional reports: HTML (Chart.js), Markdown, JSON, PDF. Executive summary, **real LLM-powered AI insight**. |

### 4. LLM Backend — `llm/`

`openrouter_client.py` provides a unified client for:
- **OpenRouter API** (cloud models)
- **Ollama** (local models)
- **Any OpenAI-compatible API**

Features: streaming, token tracking, timeout handling, model-specific configurations.

---

## Data Flow

### Attack Lifecycle

```
User Input
    │
    ▼
MasterOrchestrator (brain.py)
    │
    ├─ LLM reasoning → plan generation
    │
    ▼
AdaptivePlanner (planner.py)
    │
    ├─ Creates phased attack plan
    │
    ▼
ToolSelector (tool_selector.py)
    │
    ├─ Selects best tool for current phase + target
    │
    ▼
ExecutionEngine (execution_engine.py)
    │
    ├─ Sandbox check → AST analysis
    ├─ Execute command → capture output
    │
    ▼
AgentState (state.py)
    │
    ├─ Update: services, vulnerabilities, foothold
    ├─ Hallucination check
    ├─ Stagnation detection
    │
    ▼
CognitiveMemory (cognitive/)
    │
    ├─ Perceive → Retrieve → Reflect
    │
    ▼
Next Iteration (or HALT)
```

### State Transitions

```
INIT → RECON → VULN_SCAN → EXPLOIT → FOOTHOLD → POST_EXPLOIT → COMPLETE
                                                                    │
                                              (any point) ──────► FAILED
```

---

## Design Principles

1. **Single Source of Truth** — `AgentState` is the only place state lives. All modules read/write through its API.
2. **Thread Safety** — `AgentState` uses `RLock` for all mutations. Singleton pattern via `__new__`.
3. **Lazy Loading** — `modules/__init__.py` uses `__getattr__` + `_LAZY_MAP` dict. Submodules are only imported when symbols are first accessed.
4. **No Insecure Fallbacks** — Crypto operations (C2 encryption, credential storage) use AES-256-GCM with no XOR/plaintext fallback. `pycryptodome` is a hard dependency.
5. **Agentic Safety** — Hallucination detection, state stagnation checks, tool repetition limits, phase-gated tool access, max iteration cap.
6. **LLM-Agnostic** — Works with any OpenAI-compatible API (OpenRouter, Ollama, Azure OpenAI, etc.).
7. **Plugin Extensibility** — Drop `.py` files in `plugins/` with a `register()` → `ToolSpec` function.

---

## Directory Structure

```
drakben.py                  # Entry point
config/                     # Runtime configuration
    settings.json           # Main settings
    api.env                 # API keys
    plugins.json            # Plugin config
core/                       # Framework engine
    agent/                  # AI agent (brain, planner, state, memory)
    execution/              # Tool execution + sandboxing
    intelligence/           # Self-evolution + adaptive reasoning
    security/               # Ghost protocol + credential storage
    singularity/            # Chaos engineering
    llm/                    # LLM utilities
    network/                # Network utilities
    storage/                # Vector storage
    tools/                  # Tool definitions
    ui/                     # Terminal UI
modules/                    # Attack modules (lazy-loaded)
    exploit/                # Exploit package (SQLi, XSS, LFI, etc.)
llm/                        # LLM backend client
plugins/                    # User-defined tool plugins
tests/                      # 1609+ pytest tests
sessions/                   # Session persistence
logs/                       # Runtime logs + screenshots
```

---

## Testing Strategy

- **1609+ tests** across 50+ test files
- Frameworks: `pytest`, `pytest-asyncio`, `pytest-mock`, `pytest-cov`
- Categories: unit, integration, chaos, stress, simulation
- Coverage targets: core agent, all attack modules, error diagnostics, plugin loading, lazy imports, port scanner, report generation, LLM utils
- CI: GitHub Actions with Python 3.11/3.12/3.13 matrix, ruff lint, bandit security scan, mypy type checking, pytest with coverage

---

## Security Considerations

- All credentials are registered with `SecureRAMCleaner` for memory wiping
- Ghost Protocol provides code obfuscation and anti-forensics capabilities  
- ASTSandbox prevents execution of dangerous code patterns
- Command sanitization prevents injection attacks
- Session data is encrypted at rest
- Reports are marked CONFIDENTIAL by default
