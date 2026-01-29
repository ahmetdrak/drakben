# 🩸 DRAKBEN V2 - Autonomous Cognitive Pentest AI

> **The Next Generation of Autonomous offensive Security Orchestration.**
> *Drakben is not just a tool; it's a self-evolving autonomous operative designed to bridge the gap between human reasoning and machine-speed exploitation.*

[![Python](https://img.shields.io/badge/Python-3.10+-red?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows-000?style=flat-square&logo=terminal)](https://github.com/ahmetdrak/drakben)
[![Intelligence](https://img.shields.io/badge/Core-Self--Refining%20Engine-9333ea?style=flat-square&logo=intel)](https://github.com/ahmetdrak/drakben)
[![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)

---

## 🌩️ Vision & Concept
Drakben V2 is an **Autonomous Cognitive Pentest AI** that utilizes a persistent evolution loop. Unlike traditional scanners, Drakben simulates a real threat actor's thought process, combining reconnaissance, vulnerability research, and custom tool synthesis.

Built on the **Self-Refining Evolving Agent** architecture, it dreams, iterates, and adapts its strategies based on successful or failed outcomes, stored in a persistent SQLite neural-state.

---

## 🧪 Core Architectural Pillars

### 🧠 1. Neural Orchestration (The Brain)
- **Refactored Agent (V2 Hub):** The central command unit managing sub-engines and tool dispatching.
- **Self-Refining Engine:** A closed-loop optimization system that mutates attack strategies based on failure analysis.
- **Brain.py:** The reasoning layer that maps high-level goals into actionable technical plans.

### ⚡ 2. Singularity Engine (Self-Coding)
- **Dynamic Synthesis:** When a required tool is missing, Drakben uses its `Coder` module to write, test, and validate custom Python scripts on the fly.
- **AST Validation:** All AI-generated code passes through an Abstract Syntax Tree (AST) security checker to prevent self-sabotage or dangerous execution.

### 🎭 3. Ghost Protocol (Evasion & Stealth)
- **Polymorphic Obfuscation:** Dynamically mutates payload structures to evade signature-based detection.
- **Memory Forensics Protection:** Includes a specialized `RAMCleaner` to securely wipe sensitive credentials and attack artifacts from system memory.
- **Anti-Forensics:** Automatic cleanup of temporary files, shell history, and execution artifacts.

### �️ 4. HiveMind (Network Supremacy)
- **Autonomous Mapping:** Discovers and classifies network hosts, services, and attack paths.
- **Lateral Movement Plan:** Uses graph-based reasoning to find the shortest path to the domain controller or high-value targets.

---

## 📁 System Blueprint

```bash
drakben/
├── drakben.py                  # Core Entry Point & Interactive CLI
├── core/
│   ├── refactored_agent.py      # Main Orchestrator (V2)
│   ├── brain.py                 # Cognitive Decision Layer
│   ├── state.py                 # Persistent Agent State & Neural Memory
│   ├── self_refining_engine.py   # Strategy Mutation & Genetic Loop
│   ├── execution_engine.py      # Hardened Execution Hub & Sandbox
│   ├── ghost_protocol.py        # Stealth, Evasion & Anti-Forensics
│   ├── coder.py                 # AI Self-Coding & Tool Synthesis
│   └── universal_adapter.py     # MCP Hardware/Software Interface
├── modules/
│   ├── hive_mind.py             # Network Recon & Lateral Movement
│   ├── weapon_foundry.py        # Advanced Payload Generation Lab
│   ├── c2_framework.py          # Hardened Command & Control (TLS)
│   └── recon.py                 # OSINT & Attack Surface Enumeration
├── config/                      # Neural settings & API Environments
├── tests/                       # High-coverage Test Suite (Pytest)
└── drakben_evolution.db         # Persistent Neural Database
```

---

## ⚙️ Deployment

### Prerequisites
- Python 3.10+
- Nmap, Metasploit (optional, but recommended for full capability)
- API Keys for AI Providers (Ollama, OpenAI, or OpenRouter)

### Installation (The Quick Way)
```bash
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python -m venv .venv
# Linux:
source .venv/bin/activate
# Windows:
.\.venv\Scripts\activate.ps1

pip install -r requirements.txt
python drakben.py
```

---

## 🎮 Command Center

Drakben supports both **Natural Language** and **Command-Line Interface**:

| Command | Action |
|:---|:---|
| `/target <IP>` | Initialize target reconnaissance |
| `/scan` | Execute autonomous vulnerability assessment |
| `/shell` | Drop into an interactive AI-assisted session |
| `/status` | View agent cognitive status and neural health |
| `/report` | Generate professional-grade pentest findings |
| `[Prompt]` | i.e., "Find SQLi on 192.168.1.5 and try to dump the users table" |

---

## ⚠️ Legal & Ethical Notice
**Drakben is developed for authorized security research and professional penetration testing only.** Usage of this software for attacking targets without prior mutual consent is illegal. The developers assume no liability for misuse or damage caused by this program.

---

## 📄 License
Released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Elevating Security Through Autonomous Intelligence</b><br>
  Developed by <a href="https://github.com/ahmetdrak">@ahmetdrak</a>
</p>
