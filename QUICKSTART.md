# ⚡ DRAKBEN v5.0 - Quick Start Guide

Get started with DRAKBEN in under 5 minutes.

---

## 🚀 First Run

```bash
# Start DRAKBEN
python3 drakben.py

# You'll see:
# 🩸 DRAKBEN v5.0 - AI Penetration Testing Assistant
# 🩸 Drakben > _
```

---

## 🎯 Basic Workflow

### Step 1: Set Your Target

```bash
🩸 Drakben > target 192.168.1.100
# ✅ Target set: 192.168.1.100
```

### Step 2: Choose Strategy

```bash
🩸 Drakben > strategy balanced
# ✅ Strategy: balanced
```

| Strategy | Speed | Detection Risk | Best For |
|----------|-------|----------------|----------|
| `stealthy` | Slow | Low | Production systems |
| `balanced` | Medium | Medium | General testing |
| `aggressive` | Fast | High | Lab environments |

### Step 3: Scan Target

```bash
🩸 Drakben > scan
# Scanning 192.168.1.100...
# Found: SSH (22), HTTP (80), MySQL (3306)
```

### Step 4: Exploit Vulnerabilities

```bash
🩸 Drakben > exploit
# [!] Found CVE-2024-21626 on port 80
# [?] Exploit? (y/n): y
# ✅ Exploitation successful
```

### Step 5: View Results

```bash
🩸 Drakben > results
# === Scan Results ===
# Target: 192.168.1.100
# Vulnerabilities: 3
# Exploited: 1
```

---

## 📋 Essential Commands

| Command | Description |
|---------|-------------|
| `target <ip>` | Set target IP or range |
| `strategy <mode>` | Set OPSEC strategy |
| `scan` | Scan target for services/vulns |
| `exploit` | Exploit found vulnerabilities |
| `results` | Show findings |
| `help` | Show all commands |
| `exit` | Save and quit |

---

## 🔥 Advanced Examples

### Parallel Scanning (Multiple Targets)

```bash
🩸 Drakben > target 192.168.1.0/24
🩸 Drakben > scan_parallel
# Scanning 254 targets in parallel...
# Completed in 25 minutes
```

### Lateral Movement

```bash
🩸 Drakben > lateral
# [+] Found SSH keys on compromised host
# [+] Pivoting to 192.168.1.50...
# [+] 3 new hosts compromised
```

### Payload Generation

```bash
🩸 Drakben > payload
# Select type:
# 1. Reverse Shell (Bash)
# 2. Reverse Shell (Python)
# 3. Meterpreter
# 4. Web Shell
```

### Web Shell Deployment

```bash
🩸 Drakben > web_shell
# [+] Uploading shell to target...
# [+] Shell available at: http://target/uploads/shell.php
```

### ML OPSEC Analysis

```bash
🩸 Drakben > ml_analyze
# Analyzing detection risk...
# Stealth Score: 72/100
# Suggestions: Use process injection, avoid netcat
```

---

## 💡 Tips

1. **Always set target first** - Most commands need a target
2. **Use `stealthy` strategy** for production systems
3. **Check `results` often** - See what you've found
4. **Use `help`** if unsure about a command

---

## 🔧 Common Workflows

### Web Application Test

```bash
target 192.168.1.100
strategy balanced
scan
# Look for web vulns
exploit
web_shell
```

### Network Pentest

```bash
target 10.0.0.0/24
strategy aggressive
scan_parallel
exploit
lateral
post_exp
```

### Stealth Assessment

```bash
target 192.168.1.50
strategy stealthy
ml_analyze
scan
# Only exploit critical vulns
```

---

## ❓ Need Help?

```bash
🩸 Drakben > help
# Shows all available commands

🩸 Drakben > help scan
# Shows help for specific command
```

---

**Happy hacking! 🎉**

⚠️ **Remember: Authorized targets only!**
