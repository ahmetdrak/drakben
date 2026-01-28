# 🩸 DRAKBEN - Next-Gen Autonomous Pentest Agent

**The World's First "Self-Refining" Cyber Security Intelligence**

![Status](https://img.shields.io/badge/Status-Zero%20Defect-brightgreen)
![Security](https://img.shields.io/badge/Security-Nuclear%20Tested-red)
![Architecture](https://img.shields.io/badge/Architecture-Modular%20plugin%20System-blueviolet)
![License](https://img.shields.io/badge/License-MIT-yellow)

Drakben is not just an automation tool; it is a **bio-mechanical artificial intelligence** designed for offensive security operations. Unlike traditional scanners, it possesses **cognitive capabilities** that allow it to learn from failures, adapt strategies in real-time, and store experiences in a persistent memory.

---

## 🚀 Core Capabilities

### 🧬 1. Self-Refining Engine (Auto-Correction)
Most tools stop when they encounter an error. Drakben evolves.
- **Root Cause Analysis:** It uses LLM-based reasoning to understand *why* a command failed.
- **Dynamic Strategy Generation:** Automatically attempts alternative methods/payloads without user intervention.
- **Evolution Memory:** It "remembers" successful techniques for specific targets, becoming smarter with every operation.

### 🛡️ 2. Zero-Defect Architecture
Built with **Enterprise-Grade** engineering standards.
- **Nuclear Stress Tested:** Validated under 1000+ concurrent threads with zero crashes.
- **Memory Safety:** Leak-proof design ensures stability during long-term red team engagements.
- **Thread-Safe Core:** Asynchronous non-blocking I/O for maximum performance.

### 🔌 3. Extensible Ecosystem (Universal Adapter)
Designed for limitless expansion.
- **Hot-Swappable Plugins:** New capabilities can be added dynamically without restarting the core.
- **Hybrid Tooling:** Seamlessly integrates standard industry tools (Nmap, Nikto, etc.) with custom AI-generated scripts.
- **Future-Ready:** Ready for "Model Context Protocol (MCP)" integration to connect with external intelligence feeds.

### 🧠 4. Persistent Intelligence (The Brain)
- **Context Awareness:** Maintains a deep understanding of the target environment (Topology, Services, OS).
- **Campaign Logic:** Capable of executing multi-stage attacks rather than isolated commands.
- **Offline Reasoning:** Operates effectively even without internet access using local heuristics.

---

## ⚡ Quick Start

### Seçenek 1: Docker (Önerilen)
Bağımlılık karmaşası yaşamadan Drakben'i dağıtmanın en hızlı yolu.

```bash
docker build -t drakben .
docker run -it drakben
```

### Seçenek 2: Manuel Kurulum
Linux/Windows ortamında geliştirme yapmak için.

```bash
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
pip install -r requirements.txt
python drakben.py
```

### Usage
Drakben understands **Natural Language**. You don't need to memorize flags.

```
> Scan the target 10.0.0.5 for high-risk vulnerabilities.
> Analyze example.com and suggest an SQL Injection strategy.
> Perform a stealth reconnaissance on the internal network.
```

---

## 📂 Architecture Overview

The system is composed of four main pillars:

1.  **The Brain (Cortex):** High-level decision making and planning.
2.  **The Spine (Execution Engine):** Safe and robust command execution.
3.  **The Memory (Hippocampus):** SQLite-based long term experience storage.
4.  **The Limbs (Plugins & Modules):** Dynamic capability layer.

---

## ⚠️ Legal Disclaimer

This software is designed for **defensive and educational purposes only**. Using it on systems without explicit permission is illegal. The developers assume no liability for misuse.

---

**Made with ❤️ by Drakben Team**
