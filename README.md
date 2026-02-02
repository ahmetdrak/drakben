# 🩸 DRAKBEN - Autonomous Pentest AI

Otonom Penetrasyon Test AI Framework - Kalıcı Hafıza & Sistem Tanıma

![Python](https://img.shields.io/badge/Python-3.10+-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

⭐ **Star this repo if it helps you!**

---

## 🚀 Kurulum

### 🐳 Docker (Önerilen)
En kolay ve sorunsuz yöntem. Tüm araçlar hazır gelir!

```bash
# Projeyi indir
git clone https://github.com/ahmetdrak/drakben.git
cd drakben

# Tek komutla başlat (Kali Linux + tüm araçlar dahil)
docker-compose up -d

# DRAKBEN'e bağlan
docker exec -it drakben python3 drakben.py
```

**Docker Avantajları:**
- ✅ Tüm bağımlılıklar otomatik yüklenir
- ✅ Kali Linux araçları (nmap, sqlmap, nikto, hydra) hazır
- ✅ Host sistemi temiz kalır
- ✅ Farklı platformlarda aynı çalışır

```bash
# Yararlı Docker komutları
docker-compose logs -f drakben    # Logları izle
docker-compose down               # Durdur
docker-compose up -d --build      # Yeniden oluştur
```

---

### 📦 Manuel Kurulum (Alternatif)

#### Kali Linux
```bash
# Sistem paketleri
sudo apt update
sudo apt install -y python3-venv python3-pip build-essential libffi-dev

# Projeyi indir ve kur
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 drakben.py
```

#### Ubuntu / Debian
```bash
sudo apt update
sudo apt install -y python3-venv python3-pip build-essential libffi-dev
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 drakben.py
```

#### Windows
```powershell
git clone https://github.com/ahmetdrak/drakben.git
cd drakben
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python drakben.py
```

#### ⚡ Tek Satır (Linux)
```bash
git clone https://github.com/ahmetdrak/drakben.git && cd drakben && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && python3 drakben.py
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
/scan                    # Hedefi tara
/status                  # Sistem durumu
/stats                   # Hafıza istatistikleri
/help                    # Yardım
/exit                    # Çıkış
```

---

## ✨ Özellikler

### 🧠 Kalıcı Hafıza Sistemi
- **Otomatik kayıt**: Tüm komutlar, çıktılar ve konuşmalar otomatik kaydedilir
- **Pattern öğrenme**: Başarılı komutlar öğrenilir, sonraki sefere önerilir
- **Sistem tanıma**: OS, yetkiler, araçlar otomatik algılanır ve hatırlanır
- **Oturum geçmişi**: Önceki oturumlar ve hedefler saklanır

### 🤖 Otonom Çalışma
- **Tek seferlik onay**: İlk kez onay alır, sonra otomatik çalışır
- **Auto-healing**: Hatalar otomatik düzeltilir
- **Araç yükleme**: Eksik araçlar otomatik yüklenir
- **Akıllı retry**: Başarısız komutlar alternatiflerle denenir

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
| `/scan` | Mevcut hedefi tara |
| `/status` | Sistem durumunu göster |
| `/stats` | Hafıza ve AI istatistikleri |
| `/help` | Detaylı yardım |
| `/clear` | Ekranı temizle |
| `/exit` | Çıkış |
| Doğal dil | AI'a herhangi bir pentest görevi söyle |

---

## 📁 Proje Yapısı

```
drakben/
├── drakben.py              # Ana giriş noktası
├── core/
│   ├── agent.py            # Ana agent orchestrator
│   ├── brain.py            # AI reasoning ve planlama
│   ├── memory_manager.py   # Kalıcı hafıza sistemi (SQLite)
│   ├── system_intelligence.py  # Sistem tanıma
│   ├── execution_engine.py # Komut çalıştırma
│   ├── autonomous_solver.py    # Auto-healing
│   ├── security_toolkit.py # Güvenlik kontrolleri
│   ├── config.py           # Konfigürasyon yönetimi
│   └── i18n.py             # Çoklu dil desteği
├── llm/
│   ├── brain.py            # LLM entegrasyonu
│   └── openrouter_client.py    # Multi-provider client
├── modules/
│   ├── recon.py            # Keşif modülü
│   ├── exploit.py          # Exploit modülü
│   ├── payload.py          # Payload üretimi
│   └── report.py           # Raporlama
├── config/
│   ├── api.env             # API anahtarları
│   └── plugins.json        # Plugin registry
└── drakben_memory.db       # Kalıcı hafıza veritabanı
```

---

## 🔧 Sorun Giderme

| Problem | Çözüm |
|---------|-------|
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| `error: command 'gcc' failed` | `sudo apt install build-essential libffi-dev` |
| `curl_cffi` hata | `sudo apt install libcurl4-openssl-dev` |
| API çalışmıyor | Offline modda çalışır! Veya `config/api.env` kontrol et |
| Permission denied | Linux'ta `sudo` ile çalıştır |
| Python sürüm hatası | Python 3.10+ gerekli: `python3 --version` |

### 🔄 Temiz Kurulum
```bash
# Eğer sorun yaşıyorsanız, venv'i sıfırdan oluşturun:
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 📚 Dokümantasyon

- [INSTALLATION.md](INSTALLATION.md) - Detaylı kurulum
- [QUICKSTART.md](QUICKSTART.md) - Hızlı başlangıç
- [CONTRIBUTING.md](CONTRIBUTING.md) - Katkıda bulunma
- [CHANGELOG.md](CHANGELOG.md) - Sürüm geçmişi

---

## 📄 Lisans

MIT License - [LICENSE](LICENSE)

---

**Made with ❤️ for the security community**

⚠️ **Sadece yetkili hedeflerde kullanın.**
