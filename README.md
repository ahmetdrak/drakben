# 🩸 DRAKBEN v5.0 - AI Penetration Testing Assistant

> **Düşünen, Reaktif, Akıllı, Karanlık Bilgi Engeli**
>
> Modern AI-powered penetration testing automation for Kali Linux

![Version](https://img.shields.io/badge/Version-5.0-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

⭐ **Star this repo if it helps you!**

---

## 🚀 Installation (2 Minutes)

### Option 1: Kali Linux / Ubuntu / Debian
```bash
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 drakben.py
```

### Option 2: Windows
```powershell
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python drakben.py
```

### Option 3: Docker
```bash
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
docker-compose up -d
docker exec -it drakben bash
python3 drakben.py
```

---

## 🤖 AI/LLM Setup (Optional)

DRAKBEN works **100% offline** without any API key. For AI-powered features, choose one:

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

# Set target
🩸 Drakben > target 192.168.1.100

# Choose strategy
🩸 Drakben > strategy balanced    # or: stealthy, aggressive

# Scan
🩸 Drakben > scan

# Exploit found vulnerabilities
🩸 Drakben > exploit

# View results
🩸 Drakben > results
```

---

## 📋 Commands

| Category | Commands |
|----------|----------|
| **Setup** | `target <ip>`, `strategy <mode>`, `setup` |
| **Scanning** | `scan`, `scan_parallel` |
| **Exploitation** | `exploit`, `payload`, `enum` |
| **Post-Exploit** | `post_exp`, `lateral`, `web_shell`, `ssh_shell` |
| **Analysis** | `results`, `chain`, `ml_analyze`, `ml_summary` |
| **Utility** | `help`, `clear`, `exit` |

---

## ✨ Key Features

- 🔥 **Modern Evasion** - AMSI/ETW bypass, LOLBins, fileless execution
- 🛡️ **CVE Database** - 2024-2025 vulnerabilities (Log4Shell, Spring4Shell, etc.)
- 🧠 **ML OPSEC** - AI-powered detection avoidance
- ⚡ **Parallel Scanning** - 100 targets in ~25 minutes
- 🔗 **Lateral Movement** - Automated SSH key chaining
- 🐚 **Multi-Shell** - Web shells, SSH, reverse shells
- 💾 **Session Management** - SQLite-backed persistence

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
drakben/
├── drakben.py          # Main program
├── core/               # 34 core modules
├── modules/            # 17 pentest modules  
├── llm/                # AI/LLM integration
├── config/             # Configuration files
├── tests/              # Unit tests
└── logs/               # Execution logs
```

---

## ⚖️ Legal Disclaimer

**For authorized penetration testing only.**

- Only test systems you own or have written permission for
- Unauthorized access is illegal
- User assumes all responsibility

---

## 📄 License

MIT License - See [LICENSE](LICENSE)

---

## 📚 Documentation

- [INSTALLATION.md](INSTALLATION.md) - Detailed installation guide
- [QUICKSTART.md](QUICKSTART.md) - Usage examples
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
- [CHANGELOG.md](CHANGELOG.md) - Version history

---

**Made with ❤️ for the security community**
