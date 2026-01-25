# 🩸 DRAKBEN - Autonomous Pentest AI

Otonom Penetrasyon Test AI Framework - Kalıcı Hafıza & Sistem Tanıma

![Python](https://img.shields.io/badge/Python-3.10+-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

⭐ **Star this repo if it helps you!**

---

## 🚀 Kurulum

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

## 🤖 AI/LLM Kurulumu (Opsiyonel)

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

## 🎯 Kullanım

```bash
python drakben.py

# Doğal dil ile konuş:
💬 "10.0.0.1 portlarını tara"
💬 "example.com sql injection test et"
💬 "192.168.1.1'e shell at"

# Slash komutları:
/target 192.168.1.100   # Hedef belirle
/scan                    # Hedefi tara (otonom mod)
/scan stealth            # Sessiz/stealth tarama
/scan aggressive         # Hızlı/agresif tarama
/shell                   # İnteraktif kabuk
/status                  # Sistem durumu
/llm                     # LLM/API ayarları
/clear                   # Ekranı temizle
/tr                      # Türkçe mod
/en                      # English mode
/help                    # Yardım
/exit                    # Çıkış
```

---

## ✨ Özellikler

### 🧠 Kalıcı Hafıza Sistemi
- **Evolution Memory**: Strateji profilleri ve öğrenilen patternler SQLite'da saklanır
- **Self-Refining Engine**: Başarılı stratejiler öğrenilir, başarısızlar retry edilmez
- **Sistem tanıma**: Kali Linux otomatik algılanır, mevcut araçlar tespit edilir
- **Oturum geçmişi**: Önceki oturumlar ve hedefler `evolution.db`'de saklanır

### 🤖 Otonom Çalışma
- **Self-evolving agent**: Strateji profilleri ile otomatik evrim
- **Policy engine**: Çakışan kurallar için öncelik sistemi
- **Meta-learning**: Araçların performansını değerlendirip otomatik iyileştirme
- **Akıllı retry**: Başarısız komutlar alternatif stratejilerle denenir
- **Non-repetition**: Başarısız profiller tekrar kullanılmaz

### 🛡️ Güvenlik
- **Safety checks**: Tehlikeli komutlar engellenir
- **Risk analizi**: Her komut için risk değerlendirmesi
- **Approval sistemi**: Kritik işlemler için onay

### 🎨 Arayüz
- **Dracula teması**: Mor/pembe/kırmızı terminal UI
- **Türkçe/İngilizce**: Tam çoklu dil desteği
- **Minimal**: Temiz, odaklanmış arayüz

---

## 📋 Komutlar

| Komut | Açıklama |
|-------|----------|
| `/target <IP>` | Hedef belirle |
| `/scan` | Otonom tarama başlat (AI modu seçer) |
| `/scan stealth` | Sessiz/stealth tarama (yavaş, dikkatli) |
| `/scan aggressive` | Hızlı/agresif tarama (hızlı, gürültülü) |
| `/shell` | İnteraktif kabuk modu |
| `/status` | Sistem durumunu göster |
| `/llm` | LLM/API ayarlarını yapılandır |
| `/clear` | Ekranı temizle |
| `/tr` | Türkçe moda geç |
| `/en` | English mode |
| `/help` | Detaylı yardım |
| `/exit` | Çıkış |
| Doğal dil | AI'a herhangi bir pentest görevi söyle |

---

## 📁 Proje Yapısı

```
drakben/
├── drakben.py              # Ana giriş noktası
├── core/
│   ├── refactored_agent.py # Ana agent orchestrator (self-evolving)
│   ├── brain.py            # AI reasoning ve planlama
│   ├── evolution_memory.py # Kalıcı hafıza sistemi (SQLite)
│   ├── self_refining_engine.py  # Self-evolving strateji motoru
│   ├── kali_detector.py    # Sistem tanıma (Kali Linux detection)
│   ├── execution_engine.py # Komut çalıştırma
│   ├── security_utils.py   # Güvenlik kontrolleri
│   ├── config.py           # Konfigürasyon yönetimi
│   ├── menu.py             # İnteraktif menü sistemi
│   ├── planner.py          # Saldırı planlama
│   ├── coder.py            # AI kod üretici
│   ├── computer.py         # Bilgisayar kontrolü (Open Interpreter)
│   ├── interpreter.py      # Komut yorumlayıcı
│   ├── interactive_shell.py # İnteraktif kabuk
│   ├── i18n.py             # Çoklu dil desteği
│   └── ...                 # Diğer yardımcı modüller
├── llm/
│   └── openrouter_client.py # Multi-provider LLM client
├── modules/
│   ├── recon.py            # Keşif modülü
│   ├── exploit.py          # Exploit modülü
│   ├── payload.py          # Payload üretimi
│   ├── metasploit.py       # Metasploit entegrasyonu
│   ├── nuclei.py           # Nuclei tarayıcı
│   ├── subdomain.py        # Subdomain enumeration
│   ├── cve_database.py     # CVE veritabanı
│   └── report_generator.py # Raporlama
├── config/
│   ├── api.env             # API anahtarları (oluşturulur)
│   ├── settings.json       # Ayarlar
│   └── plugins.json        # Plugin registry
├── scripts/                # Yardımcı scriptler
├── tests/                  # Test dosyaları
├── sessions/               # Oturum dosyaları
├── reports/                # Raporlar
└── evolution.db            # Kalıcı hafıza veritabanı (otomatik oluşturulur)
```

---

## 🔧 Sorun Giderme

| Problem | Çözüm |
|---------|-------|
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| API çalışmıyor | Offline modda çalışır! Veya `config/api.env` kontrol et |
| Permission denied | Linux'ta `sudo` ile çalıştır |
| Database lock hatası | `evolution.db-wal` ve `evolution.db-shm` dosyalarını sil |
| Python 3.8+ gerekli | `python3 --version` kontrol et, 3.10+ önerilir |

---

## 📚 Dokümantasyon

- [INSTALLATION.md](INSTALLATION.md) - Detaylı kurulum rehberi
- [MONITORING.md](MONITORING.md) - Sistem izleme ve debug
- [ANALIZ_RAPORU.md](ANALIZ_RAPORU.md) - Proje analiz raporu

---

## 📄 Lisans

MIT License - [LICENSE](LICENSE)

---

**Made with ❤️ for the security community**

⚠️ **Sadece yetkili hedeflerde kullanın.**
