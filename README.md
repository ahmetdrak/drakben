<div align="center">

```
    ██████╗ ██████╗  █████╗ ██╗  ██╗██████╗ ███████╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝████╗  ██║
    ██║  ██║██████╔╝███████║█████╔╝ ██████╔╝█████╗  ██╔██╗ ██║
    ██║  ██║██╔══██╗██╔══██║██╔═██╗ ██╔══██╗██╔══╝  ██║╚██╗██║
    ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝███████╗██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
```

### Autonomous Penetration Testing Framework

*Let AI handle the methodology. You focus on the results.*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/)

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Architecture](#architecture) • [Contributing](#contributing)

</div>

---

## What is DRAKBEN?

DRAKBEN is an AI-powered penetration testing framework that understands natural language commands and autonomously executes security assessments. Instead of memorizing tool syntax, describe what you want in plain English—DRAKBEN handles the rest.

```
You: "Scan the target for open ports and check for web vulnerabilities"
DRAKBEN: Executing nmap → Analyzing services → Running nikto → Found 3 potential issues...
```

The framework maintains state awareness throughout engagements, tracks tested attack surfaces, and intelligently selects tools based on discovered information.

---

## Features

### 🧠 AI-Driven Decision Making
- Natural language command interface
- Context-aware tool selection
- Automatic attack chain orchestration
- Multi-LLM support (OpenRouter, Ollama, OpenAI)

### 🔍 Reconnaissance
- Port scanning and service enumeration
- Subdomain discovery
- WHOIS and DNS intelligence
- Web technology fingerprinting
- Passive OSINT gathering

### ⚡ Exploitation
- Automated vulnerability scanning
- SQL injection detection and exploitation
- Web application testing (XSS, CSRF, LFI/RFI)
- Authentication attacks (brute-force, spray)
- CVE database integration with exploit matching

### 🏢 Active Directory
- Domain enumeration
- Kerberoasting and AS-REP roasting
- Pass-the-Hash / Pass-the-Ticket
- BloodHound integration
- Automated lateral movement

### 📡 Command & Control
- Domain fronting support
- DNS tunneling
- Encrypted beacon communication
- Traffic analysis evasion
- Steganography channels

### 🛡️ Evasion
- WAF bypass techniques
- Payload obfuscation
- EDR-aware execution
- Anti-forensics capabilities

### 📊 Reporting
- Automated finding documentation
- Risk-scored vulnerability reports
- Attack timeline visualization
- Executive summary generation

---

## Installation

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

---

## Configuration

### LLM Setup

DRAKBEN works offline, but AI features require an LLM provider. Create `config/api.env`:

```env
# Option 1: OpenRouter (recommended)
OPENROUTER_API_KEY=your_key_here

# Option 2: OpenAI
OPENAI_API_KEY=your_key_here

# Option 3: Local Ollama (free)
OLLAMA_HOST=http://localhost:11434
```

For Ollama, install from [ollama.ai](https://ollama.ai) and run:
```bash
ollama pull llama3.2
```

---

## Usage

### Interactive Mode

```bash
python drakben.py
```

Once started, interact using natural language:

```
drakben> scan 192.168.1.0/24 for web servers
drakben> find vulnerabilities on port 80
drakben> test sql injection on the login form
drakben> enumerate the domain controller
drakben> generate report
```

### Examples

**Web Application Assessment:**
```
scan target.com
check for common web vulnerabilities
test authentication bypass
look for sensitive data exposure
```

**Network Penetration Test:**
```
discover hosts on 10.0.0.0/24
identify services and versions
search for known CVEs
attempt exploitation on critical findings
```

**Active Directory Attack:**
```
enumerate the domain
find kerberoastable accounts
extract hashes
attempt lateral movement to DC
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        DRAKBEN CORE                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐ │
│  │  Brain  │──│ Planner │──│  State  │──│ Execution Engine│ │
│  └─────────┘  └─────────┘  └─────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                         MODULES                             │
│  ┌───────┐ ┌─────────┐ ┌────────┐ ┌──────┐ ┌─────────────┐ │
│  │ Recon │ │ Exploit │ │ Payload│ │  C2  │ │ Social Eng  │ │
│  └───────┘ └─────────┘ └────────┘ └──────┘ └─────────────┘ │
│  ┌────────────┐ ┌───────────┐ ┌────────────┐ ┌───────────┐ │
│  │ AD Attacks │ │ Metasploit│ │ WAF Evasion│ │  Nuclei   │ │
│  └────────────┘ └───────────┘ └────────────┘ └───────────┘ │
├─────────────────────────────────────────────────────────────┤
│                      LLM PROVIDERS                          │
│         OpenRouter  │  OpenAI  │  Ollama (Local)            │
└─────────────────────────────────────────────────────────────┘
```

### Attack Phases

DRAKBEN follows a structured methodology:

| Phase | Description |
|-------|-------------|
| `INIT` | Target validation and scope definition |
| `RECON` | Information gathering and enumeration |
| `VULN_SCAN` | Vulnerability identification |
| `EXPLOIT` | Exploitation attempts |
| `POST_EXPLOIT` | Privilege escalation and persistence |
| `REPORT` | Documentation and cleanup |

---

## Modules

| Module | Description |
|--------|-------------|
| `recon` | Passive and active reconnaissance |
| `exploit` | Vulnerability exploitation engine |
| `payload` | Payload generation and encoding |
| `c2_framework` | Command & control infrastructure |
| `ad_attacks` | Active Directory attack techniques |
| `metasploit` | Metasploit Framework integration |
| `nuclei` | Nuclei scanner integration |
| `waf_evasion` | WAF bypass techniques |
| `social_eng` | Social engineering toolkit |
| `hive_mind` | Distributed agent coordination |

---

## Legal Disclaimer

This tool is provided for authorized security testing and educational purposes only. Users are responsible for obtaining proper authorization before conducting any security assessments. Unauthorized access to computer systems is illegal.

**Always obtain written permission before testing systems you do not own.**

---

## Contributing

Contributions are welcome. Please read the contribution guidelines before submitting pull requests.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**DRAKBEN** — *Autonomous Pentesting, Simplified.*

</div>
