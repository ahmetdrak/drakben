# INSTALLATION GUIDE - DRAKBEN v5.0 (2026)

Complete setup instructions for all platforms with 2024-2025 modern features.

---

## 🚀 Kali Linux (Recommended)

**Estimated time: 3 minutes**

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/drakben.git
cd drakben/drakbendosyalar
```

### 2. Create Virtual Environment (Python 3.13+)
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Dependencies:**
- requests, beautifulsoup4, flask
- paramiko, pycryptodome (SSH/encryption)
- scikit-learn, numpy (ML OPSEC)
- pytest (testing)
- rich, colorama (UI)

### 4. Configure API (Optional - for cloud AI)
```bash
nano config/api.env
# Add your OpenRouter API key:
# OPENROUTER_API_KEY=sk-or-xxxxxxxxxxxxxxxxxxxxx
# Get free key at: https://openrouter.ai
```

**Note:** DRAKBEN works 100% offline without API key. Cloud mode adds conversational AI.

### 5. Run DRAKBEN
```bash
python3 drakben.py
```

**First commands:**
```
🩸 Drakben > target 192.168.1.1
🩸 Drakben > scan
```

---

## 💻 Linux (Ubuntu/Debian)

If not Kali Linux, install missing pentesting tools:

### 1. Setup DRAKBEN
```bash
# Same as Kali steps 1-4 above
```

### 2. Install Missing Tools
```bash
# For full functionality, install:
sudo apt-get update
sudo apt-get install -y nmap sqlmap nikto hydra hashcat john

# Optional but recommended:
sudo apt-get install -y metasploit-framework
```

### 3. Run
```bash
source .venv/bin/activate
python3 drakben.py
```

---

## 🍎 macOS

### 1. Clone & Setup
```bash
git clone https://github.com/yourusername/drakben.git
cd drakben/drakbendosyalar
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Install Tools (via Homebrew)
```bash
brew install nmap sqlmap nikto hydra john hashcat
```

### 3. Run
```bash
python3 drakben.py
```

**Note:** Some shell features may need Terminal/iTerm2

---

## 🪟 Windows (PowerShell)

### 1. Clone Repository
```powershell
git clone https://github.com/yourusername/drakben.git
cd drakben\drakbendosyalar
```

### 2. Create Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure
```powershell
notepad config\api.env
# Add: OPENROUTER_API_KEY=sk-or-xxxxxxxxxxxxx
```

### 5. Run
```powershell
python drakben.py
```

**Note:** Some features (SSH shells, lateral movement) work best on Linux. Windows works for command execution and testing only.

---

## 🐳 Docker (Optional - Advanced)

Create `Dockerfile`:
```dockerfile
FROM kalilinux/kali-linux-docker

WORKDIR /root/drakben

# Install Python and dependencies
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-venv \
    nmap sqlmap nikto hydra \
    metasploit-framework

# Copy project
COPY . .

# Install Python packages
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install -r requirements.txt

# Run
CMD ["python3", "drakben.py"]
```

Build and run:
```bash
docker build -t drakben:latest .
docker run -it drakben:latest
```

---

## 🔧 Troubleshooting

### Issue: `python3: command not found`
**Solution:** Install Python 3.8+
```bash
sudo apt-get install python3.11  # or higher
```

### Issue: `paramiko` or `scikit-learn` import error
**Solution:** Reinstall specific packages
```bash
pip install --upgrade paramiko scikit-learn numpy
```

### Issue: SSH shell says "connection refused"
**Solution:** 
- Ensure target SSH is running: `ssh user@target`
- Check firewall rules
- Verify SSH port (default: 22)

### Issue: No pentest tools available
**Solution:** DRAKBEN works without external tools (Python-only mode)
- All core functionality works offline
- Install tools for enhanced scanning: `sudo apt-get install nmap sqlmap nikto`

### Issue: "API key invalid" error
**Solution:**
- Check `config/api.env` is correctly formatted
- Verify key at https://openrouter.ai/keys
- DRAKBEN works fine without API (offline mode)

### Issue: Database locked
**Solution:** Close any open sessions and restart
```bash
rm drakben.db
python3 drakben.py
```

---

## ✅ Verify Installation

After installation, verify everything works:

```bash
python3 drakben.py

🩸 Drakben > help
# Should show full command menu

🩸 Drakben > target 127.0.0.1
🩸 Drakben > results
# Should show ready for operations

🩸 Drakben > exit
# Should save session and exit cleanly
```

---

## 📊 Post-Installation Setup

### 1. Create Test Target (Optional)
```bash
# Run simple HTTP server on localhost
python3 -m http.server 8000 &

# Then in DRAKBEN:
🩸 Drakben > target 127.0.0.1:8000
🩸 Drakben > scan
```

### 2. Configure for Your Network
```bash
🩸 Drakben > target 192.168.1.0/24    # Your subnet
🩸 Drakben > strategy balanced
🩸 Drakben > scan_parallel            # Fast scan
```

### 3. Enable Cloud AI (Optional)
```bash
# Edit config/api.env with your API key
# Then DRAKBEN automatically uses cloud AI
🩸 Drakben > ml_analyze              # Uses AI analysis
```

---

## 🚀 Next Steps

1. Read [COMMANDS.md](COMMANDS.md) for full command reference
2. See [README.md](README.md) for feature overview
3. Try example workflows in [QUICKSTART.md](QUICKSTART.md)
4. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues

---

## 📞 Support

- 🐛 Report issues: GitHub Issues
- 💬 Discussions: GitHub Discussions
- 📖 Docs: Full documentation in repo

---

**Installation complete! Ready for penetration testing. ✅**

Remember: **Only use on authorized targets.**
