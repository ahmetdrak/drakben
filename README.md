# 🩸 Autonomous Pentest AI Framework

Kali Linux Autonomous Pentest AI Framework with 25 Intelligent Modules

![Python](https://img.shields.io/badge/Python-3.8+-green)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

⭐ **Star this repo if it helps you!**

---

## 🚀 Installation

### Option 1: Kali Linux / Ubuntu / Debian
```bash
git clone <your-repo-url>
cd <your-repo>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 drakben.py
```

### Option 2: Windows
```powershell
git clone <your-repo-url>
cd <your-repo>
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python .\drakben.py
```

### Option 3: Docker
```bash
git clone <your-repo-url>
cd <your-repo>
docker-compose up -d
docker exec -it drakben_main bash
python3 drakben.py
```

---

## 🤖 AI/LLM Setup (Optional)

This framework works **100% offline** without any API key. For AI-powered features, choose one:

### Free Options

| Provider | Setup | Notes |
|----------|-------|-------|
| **Ollama** (Local) | Install from [ollama.ai](https://ollama.ai), then `ollama pull llama3.2` | 100% Free, runs on your machine |
| **OpenRouter** | Get free key at [openrouter.ai](https://openrouter.ai) | Free models: `deepseek/deepseek-chat`, `mistral-7b` |

### Paid Options

| Provider | Setup | Notes |
|----------|-------|-------|
| **OpenAI** | Get key at [platform.openai.com](https://platform.openai.com) | GPT-4o, GPT-4o-mini |
| **Custom API** | Any OpenAI-compatible endpoint | Self-hosted models |

### Configuration

```bash
# Copy example config
cp .env.example config/api.env

# Edit with your choice
nano config/api.env
```

**Example configs:**

```bash
# For Ollama (FREE - Local)
LOCAL_LLM_URL=http://localhost:11434/api/generate
LOCAL_LLM_MODEL=llama3.2

# For OpenRouter (FREE models available)
OPENROUTER_API_KEY=sk-or-v1-xxxxx
OPENROUTER_MODEL=deepseek/deepseek-chat

# For OpenAI (Paid)
OPENAI_API_KEY=sk-xxxxx
OPENAI_MODEL=gpt-4o-mini
```

---

## 🎯 Quick Start

```bash
python3 drakben.py

# Natural language or slash commands:
💬 "10.0.0.1 portlarını tara"
💬 "example.com sql injection test et"

# Slash commands:
/target 192.168.1.100
/scan
/status
/help
/exit
```

---

## 📋 Commands

| Command | Description |
|----------|----------|
| `/target <IP>` | Set target |
| `/scan` | Scan current target |
| `/status` | Show system status |
| `/clear` | Clear screen |
| `/help` | Show detailed help |
| `/exit` | Exit |
| Natural language | Talk to AI for any pentest task |

---

## ✨ Key Features

- 🧠 **25+ Intelligent Modules** - Distributed across core and modules packages
- 🎨 **Dracula Theme UI** - Beautiful minimal terminal interface
- 🤖 **GPT-5 Level Reasoning** - Continuous reasoning and self-correction
- ✅ **One-Time Approval** - First command approval, then autonomous
- 🔧 **Auto-Healing** - Automatically fixes errors and installs missing tools
- 🛡️ **Security Toolkit** - Built-in safety checks and risk analysis
- 🧩 **Single Brain Layer** - core.brain contains the primary brain class
- ⚡ **Single Execution Layer** - TerminalExecutor is the unified command runner

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| `paramiko` import error | `pip install paramiko` (optional for SSH) |
| No API response | Works offline! Or check `config/api.env` |
| Permission denied | Run with `sudo` on Linux |

---

## 📁 Project Structure

```
project-root/
├── drakben.py                    # Main entry point
├── core/
│   ├── agent.py                  # Main agent orchestrator
│   ├── brain.py                  # Core reasoning and planning
│   ├── system_intelligence.py    # System context & environment scan
│   ├── execution_engine.py       # Command execution & analysis
│   ├── autonomous_solver.py      # Error analysis & auto-healing
│   ├── security_toolkit.py       # Safety checks & payload helpers
│   ├── terminal.py               # Safe terminal executor
│   ├── tools.py                  # Tool wrappers (nmap/sqlmap/etc.)
│   ├── events.py                 # Event bus
│   ├── web_scanner.py            # Web application scanner
│   ├── ad_bloodhound.py          # AD/BloodHound integration
│   ├── c2_beacon.py              # C2 beacon infrastructure
│   ├── cloud_scanner.py          # Cloud security scanner
│   ├── zero_day_scanner.py       # Zero-day pattern scanner
│   ├── lateral_movement_engine.py
│   ├── post_exploitation_automation.py
│   ├── opsec_implementation.py
│   └── payload_intelligence.py
├── core/plugins/
│   ├── base.py
│   ├── registry.py
│   └── adapters/noop.py
├── llm/                          # LLM integration
│   ├── brain.py                  # Thin re-export (core.brain)
│   └── openrouter_client.py      # Multi-provider client
├── modules/                      # Pentest modules
│   ├── recon.py, exploit.py
│   ├── payload.py, report.py
│   └── ai_bridge.py, memory.py
└── config/
    ├── api.env                   # API keys
    ├── plugins.json              # Plugin registry
    └── settings.json             # Configuration
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE)

---

## 📚 Documentation

- [INSTALLATION.md](INSTALLATION.md) - Detailed installation guide
- [QUICKSTART.md](QUICKSTART.md) - Usage examples
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
- [CHANGELOG.md](CHANGELOG.md) - Release history

---

**Made with ❤️ for the security community**
