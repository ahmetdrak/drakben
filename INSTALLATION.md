# 📦 Installation Guide

Kali Linux Autonomous Pentest AI - Complete Setup for All Platforms

---

## 🐧 Linux (Kali / Ubuntu / Debian)

**Time: ~2 minutes**

```bash
# 1. Clone the repository
git clone https://github.com/ahmetdrak/drakben.git
cd drakben

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python3 drakben.py
```

## 🪟 Windows

**Time: ~3 minutes**

```powershell
# 1. Clone the repository
git clone https://github.com/ahmetdrak/drakben.git
cd drakben

# 2. Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python .\drakben.py
```

 

---

## 🍎 macOS

**Time: ~3 minutes**

```bash
# 1. Clone the repository
git clone https://github.com/ahmetdrak/drakben.git
cd drakben

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python3 drakben.py
```

### Optional: Install Tools via Homebrew

```bash
brew install nmap sqlmap nikto hydra john hashcat
```

---

## 🤖 AI/LLM Configuration (Optional)

This framework works **100% offline**. For AI features, configure one of these:

### Option A: Ollama (Free, Local)

```bash
# 1. Install Ollama: https://ollama.ai
# 2. Pull a model
ollama pull llama3.2

# 3. Configure the app
cp .env.example config/api.env
nano config/api.env
```

Add to `config/api.env`:
```
LOCAL_LLM_URL=http://localhost:11434/api/generate
LOCAL_LLM_MODEL=llama3.2
```

### Option B: OpenRouter (Free models available)

```bash
# 1. Get free API key: https://openrouter.ai
# 2. Configure the app
cp .env.example config/api.env
nano config/api.env
```

Add to `config/api.env`:
```
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=deepseek/deepseek-chat
```

### Option C: OpenAI (Paid)

```bash
# 1. Get API key: https://platform.openai.com
# 2. Configure the app
cp .env.example config/api.env
nano config/api.env
```

Add to `config/api.env`:
```
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4o-mini
```

---

## ✅ Verify Installation

```bash
# Activate virtual environment (if not active)
source .venv/bin/activate  # Linux/Mac
# or
.\.venv\Scripts\Activate.ps1  # Windows

# Run the app
python3 drakben.py

# Test slash commands
/help
/target 127.0.0.1
/scan
/status
/exit

# Or use natural language
💬 "127.0.0.1'i tara"
💬 "portları listele"
```

---

## 🔧 Troubleshooting

### `python3: command not found`
```bash
# Install Python 3.10+
sudo apt install python3.11
```

### `ModuleNotFoundError: No module named 'xxx'`
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

### `paramiko` or `pycryptodome` error
```bash
# These are optional, install if needed
pip install paramiko pycryptodome
```

### Permission denied on Linux
```bash
# Run with sudo or fix permissions
sudo python3 drakben.py
# or
chmod +x drakben.py
```

### API key not working
- The app works fine without API (offline mode)
- Check `config/api.env` format
- Verify key is valid at provider's website

---

## 📋 Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Python | 3.10+ | 3.11+ |
| RAM | 2 GB | 4 GB |
| Disk | 200 MB | 500 MB |
| OS | Linux/Windows/macOS | Kali Linux |

---

## 🚀 Next Steps

1. Read [README.md](README.md) for features overview
2. Check [QUICKSTART.md](QUICKSTART.md) for usage examples
3. Configure AI if desired (see above)

---

**Installation complete! Happy hacking! 🎉**

⚠️ **Remember: Only use on authorized targets.**
