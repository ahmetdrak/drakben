# DRAKBEN - Autonomous Pentest AI Framework

Otonom Penetrasyon Test AI Framework - Kalıcı Hafıza, Self-Refining ve Evrim Özellikleri

![Python](https://img.shields.io/badge/Python-3.10+-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Kurulum

### Linux (Kali / Ubuntu / Debian)
```bash
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 drakben.py
```

### Windows
```powershell
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python drakben.py
```

---

## AI/LLM Kurulumu (Opsiyonel)

Framework **%100 offline** çalışır. AI özellikleri için:

| Provider | Kurulum | Not |
|----------|---------|-----|
| **Ollama** (Ücretsiz) | [ollama.ai](https://ollama.ai) → `ollama pull llama3.2` | Yerel, ücretsiz |
| **OpenRouter** (Ücretsiz) | [openrouter.ai](https://openrouter.ai) | `deepseek/deepseek-chat` ücretsiz |
| **OpenAI** (Ücretli) | [platform.openai.com](https://platform.openai.com) | GPT-4o, GPT-4o-mini |

```bash
# İlk çalıştırmada interaktif setup yapılır
python drakben.py
# veya manuel: cp .env.example config/api.env && nano config/api.env
```

---

## Kullanım

```bash
python drakben.py

# Doğal dil ile konuş:
"10.0.0.1 portlarını tara"
"example.com sql injection test et"
"192.168.1.1'e shell at"

# Slash komutları:
/target 192.168.1.100   # Hedef belirle
/scan                    # Hedefi tara
/shell                   # İnteraktif kabuk
/status                  # Sistem durumu
/clear                   # Ekranı temizle
/tr                      # Türkçe mod
/en                      # English mode
/help                    # Yardım
/exit                    # Çıkış
```

---

## Özellikler

### Kalıcı Hafıza & Evrim Sistemi
- **SQLite Persistance**: Tüm aksiyonlar, planlar ve heuristikler kalıcı olarak saklanır
- **Tool Penalty System**: Başarısız araçlar cezalandırılır, 3+ başarısızlıkta bloklanır
- **Strategy Profiles**: Farklı hedef tiplerine göre strateji profilleri seçilir
- **Profile Mutation**: Başarısız profiller mutasyona uğrar ve yeni varyantlar oluşturulur
- **Policy System**: Tier-based policy sistemi ile deterministik karar verme

### Self-Refining Agent
- **Otomatik Replanning**: Başarısız adımlar için alternatif plan oluşturur
- **Stagnation Detection**: Döngüsel davranışları tespit eder ve kırar
- **Heuristic Self-Modification**: Parametreler deneyime göre otomatik ayarlanır
- **Self-Coding**: LLM ile eksik araçlar için kod üretir (API gerektirir)

### Güvenlik
- **AST-Based Security Check**: Üretilen kodlar AST analizi ile kontrol edilir
- **Command Sanitization**: Tehlikeli komutlar engellenir
- **Thread-Safe State**: Çoklu iş parçacığı güvenliği
- **Structured Logging**: Detaylı log sistemi
- **Audit Logging**: Forensic-ready denetim kaydı
- **Secure Credential Storage**: Keyring/encrypted file desteği
- **Proxy Support**: HTTP/SOCKS5/Tor proxy desteği

### Modüler Tasarım
- **Recon Module**: Pasif bilgi toplama (DNS, WHOIS, CMS detection, subdomain enum)
- **Exploit Module**: SQL injection, XSS, LFI, XXE, SSRF, SSTI, IDOR testleri
- **Payload Module**: 15+ payload şablonu, obfuscation, AV bypass
- **CVE Database**: NVD entegrasyonu, zafiyet eşleştirme
- **Report Generator**: PDF/HTML/Markdown/JSON rapor çıktısı
- **Nuclei Scanner**: Template-based zafiyet tarama
- **Metasploit RPC**: Otomatik exploitation desteği

---

## Proje Yapısı

```
drakben/
├── drakben.py                  # Ana giriş noktası
├── core/
│   ├── refactored_agent.py     # Self-refining evolving agent
│   ├── brain.py                # AI reasoning ve planlama
│   ├── evolution_memory.py     # Kalıcı evrim hafızası (SQLite)
│   ├── self_refining_engine.py # Strateji profilleri ve policy motoru
│   ├── planner.py              # Plan yönetimi ve replanning
│   ├── execution_engine.py     # Komut çalıştırma (sanitized)
│   ├── tool_selector.py        # Deterministik araç seçimi
│   ├── coder.py                # AI ile dinamik tool oluşturma
│   ├── state.py                # Thread-safe agent state
│   ├── config.py               # Thread-safe konfigürasyon
│   ├── logging_config.py       # Structured logging
│   ├── menu.py                 # İnteraktif CLI menü
│   ├── i18n.py                 # Çoklu dil desteği
│   ├── prompt_utils.py         # Auto-complete, history, progress
│   └── security_utils.py       # Credential storage, audit, proxy
├── llm/
│   └── openrouter_client.py    # Multi-provider LLM client (cache, rate limit)
├── modules/
│   ├── recon.py                # Keşif modülü (async, logging)
│   ├── exploit.py              # Exploit modülü (XXE, SSRF, SSTI, IDOR)
│   ├── payload.py              # Payload templates + obfuscation
│   ├── cve_database.py         # CVE/NVD entegrasyonu
│   ├── report_generator.py     # PDF/HTML/Markdown rapor
│   ├── nuclei.py               # Nuclei scanner entegrasyonu
│   ├── subdomain.py            # Subdomain enumeration
│   └── metasploit.py           # Metasploit RPC client
├── config/
│   ├── api.env                 # API anahtarları
│   └── settings.json           # Uygulama ayarları
├── tests/
│   ├── test_core.py            # Core module testleri
│   ├── test_modules.py         # Module testleri
│   └── conftest.py             # Pytest fixtures
├── .github/workflows/
│   ├── test.yml                # CI/CD test pipeline
│   └── release.yml             # Release pipeline
├── Dockerfile                  # Docker image (Kali base)
├── docker-compose.yml          # Full stack deployment
└── drakben_evolution.db        # Kalıcı evrim veritabanı
```

---

## Komutlar

| Komut | Açıklama |
|-------|----------|
| `/help` | Yardım menüsü |
| `/target <IP>` | Hedef belirle |
| `/scan` | Otonom tarama başlat |
| `/shell` | İnteraktif kabuk |
| `/status` | Sistem durumunu göster |
| `/llm` | LLM/API ayarları |
| `/clear` | Ekranı temizle |
| `/tr` | Türkçe mod |
| `/en` | English mode |
| `/exit` | Çıkış |
| Doğal dil | AI'a herhangi bir pentest görevi söyle |

---

## Gereksinimler

| Bileşen | Minimum | Önerilen |
|---------|---------|----------|
| Python | 3.10+ | 3.11+ |
| RAM | 2 GB | 4 GB |
| Disk | 200 MB | 500 MB |
| OS | Linux/Windows/macOS | Kali Linux |

### Python Bağımlılıkları
```
rich>=13.0.0         # Terminal UI
requests>=2.28.0     # HTTP client
python-dotenv>=1.0.0 # Environment variables
psutil>=5.9.0        # System monitoring
aiohttp>=3.9.0       # Async HTTP
beautifulsoup4>=4.12.0
dnspython>=2.4.0
pycryptodome>=3.20.0
```

---

## Sorun Giderme

| Problem | Çözüm |
|---------|-------|
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| API çalışmıyor | Offline modda çalışır! Veya `config/api.env` kontrol et |
| Permission denied | Linux'ta `sudo` ile çalıştır |
| Veritabanı hatası | `drakben_evolution.db` dosyasını sil, yeniden başlat |

---

## Test

```bash
# Improvement testlerini çalıştır
python tests/test_improvements.py

# Formal verification audit
python scripts/formal_audit.py

# Proof tests
python scripts/proof_tests.py
```

---

## Lisans

MIT License - [LICENSE](LICENSE)

---

**Made with Python for the security community**

**Sadece yetkili hedeflerde kullanın.**
