# 🩸 DRAKBEN V2 - Autonomous Cognitive Pentest AI

> **The Singularity of Offensive Security.**
> *Drakben is not merely a tool; it is a self-evolving, cognitive artificial lifeform designed to bridge the gap between human intuition and machine-speed exploitation.*

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.10+-red?style=for-the-badge&logo=python)](https://python.org)
[![Core](https://img.shields.io/badge/Intel-Self--Refining%20Engine-9333ea?style=for-the-badge&logo=openai)](https://github.com/ahmetdrak/drakben)
[![Technique](https://img.shields.io/badge/Stealth-Ghost%20Protocol-000?style=for-the-badge&logo=kali-linux)](https://github.com/ahmetdrak/drakben)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

</div>

---

## 🌩️ Vision: The Cognitive Attacker

Drakben V2 abandons legacy "scanner" logic in favor of a **Cognitive Loop**. It doesn't just run scripts; it *thinks*, *plans*, *fails*, *learns*, and *evolves*.

By leveraging a persistent **Neural State (SQLite + Vector Memory)**, Drakben remembers every interaction. If an attack fails against a specific WAF or EDR, it mutates its strategy, records the failure in its `SelfRefiningEngine`, and spawns a new behavioral profile for the next attempt.

---

## � Architectural DNA

### 🧠 1. Neural Orchestration (The Brain)
The decision-making core that emulates a senior Red Teamer's intuition.
- **Self-Refining Engine:** A genetic algorithm that optimizes attack strategies over generations.
- **Strategy Profiles:** Dynamic behavioral templates (e.g., "Stealthy-Low-Noise", "Aggressive-Smash-Grab").
- **Adaptive Planning:** Real-time replanning based on target responses (403 Forbidden? -> Switch to Domain Fronting).

### ⚡ 2. Singularity Engine (Dynamic Code Synthesis)
When pre-built tools fail, Drakben builds its own.
- **Just-In-Time (JIT) Coding:** Generates custom Python/C++ tools on the fly for unique scenarios.
- **Secure Sandbox:** Validates all AI-generated code via AST parsing and Docker sandboxing before execution.
- **Self-Healing:** Detects runtime errors in its own modules and attempts to patch them automatically.

### ⚔️ 3. Weapon Foundry (Advanced Payload Lab)
A fully automated arsenal for generating military-grade malware.
- **Polymorphic Engine:** Mutates payload signatures on every generation to bypass static analysis.
- **Encryption Standards:** Native support for **AES-256**, **ChaCha20**, **RC4**, and **Multi-layer XOR**.
- **Formatted Payloads:** Generates `.exe`, `.dll`, `.elf`, `.ps1`, `.hta`, `.vbs`, and Polyglots.
- **Anti-Analysis:** Built-in anti-debug, anti-sandbox, and time-accelerated sleep techniques.

### 👻 4. Ghost Protocol (Stealth & Evasion)
Drakben operates in the shadows, leaving zero evidence.
- **RAM Wiper:** Specialized `RAMCleaner` class ensuring sensitive credentials are scrubbed from memory immediately after use.
- **Forensic Cleanse:** Automates the removal of event logs, prefetch files, and shell history.
- **Obfuscation:** Code and traffic are heavily obfuscated to mimic legitimate administrator activity.

### 🕸️ 5. HiveMind (Network Supremacy)
Intelligent lateral movement and domain dominance.
- **Active Directory Assualt:** Kerberoasting, AS-REP Roasting, DCSync, and ZeroLogon checks.
- **BloodHound Integration:** Graph-based pathfinding to identify the shortest route to Domain Admin.
- **Lateral Movement:** Pass-the-Hash (PtH), Pass-the-Ticket (PtT), WMIExec, and WinRM pivoting.

### 📡 6. C2 Framework (Command & Control)
Enterprise-grade communication channels meant to survive deep packet inspection.
- **Domain Fronting:** Hides traffic behind legitimate CDNs (e.g., Cloudflare, Azure).
- **DNS Tunneling:** Fallback covert channel encoding data in DNS TXT records.
- **Jitter Engine:** Randomized beacon intervals with statistical noise to defeat traffic analysis.

---

## 📁 System Blueprint

The architecture is modular, scalable, and built for speed.

```bash
drakben/
├── drakben.py                  # Core Entry Point (Interactive CLI)
├── core/
│   ├── refactored_agent.py      # V2 Orchestrator & Logic Hub
│   ├── self_refining_engine.py  # Genetic Strategy Optimization
│   ├── ghost_protocol.py        # Forensics Evasion & RAM Cleaning
│   └── singularity/             # AI Code Synthesis & Validation
├── modules/
│   ├── weapon_foundry.py        # Payload Generation (AES/XOR/Poly)
│   ├── hive_mind.py             # Active Directory & Lateral Move
│   ├── c2_framework.py          # Domain Fronting & DNS Tunneling
│   └── ad_attacks.py            # Kerberoasting/DCSync Implementation
└── drakben_evolution.db         # Persistent Neural Knowledge Base
```

---

## ⚙️ Deployment & Usage

### 🐳 Docker (Recommended)
Deploy the full offensive stack in seconds.

```bash
# Production Deployment
docker-compose up -d --build
docker exec -it drakben python3 drakben.py
```

### 🐍 Manual Installation
```bash
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
pip install -r requirements.txt
python drakben.py
```

---

## 🎮 Command Center & Interaction

Drakben prioritizes **Natural Language Interaction**. You lead; it executes.

### �️ Conversational Commands
> *"Scan 10.10.10.5 for high-risk vulnerabilities and attempt to exploit SMB."*
> *"Create a FUD reverse shell payload using AES encryption and save it as update.exe."*
> *"I have domain admin credentials. Map the network and find the backup server."*

### 💻 System Controls
| Command | Description |
|:--- |:--- |
| **`/target <IP>`** | Lock onto a new target scope. |
| **`/status`** | View live neural state, evolution generation, and active plan. |
| **`/report`** | Compile a professional HTML/PDF penetration test report. |
| **`/llm`** | Configure AI backend (Ollama, OpenAI, Anthropic). |
| **`/shell`** | Drop into a raw system shell (use with caution). |

---

## ⚠️ Compliance & Disclaimer
**Drakben is a specialized tool for authorized security professionals.**
Usage for unauthorized attacks is strictly prohibited. The developers assume no liability for misuse.
*Always obtain written consent before scanning any network.*

---

<p align="center">
  <b>Developed by <a href="https://github.com/ahmetdrak">@ahmetdrak</a></b><br>
  <i>Forging the Future of Autonomous Cyber Weaponry</i>
</p>
