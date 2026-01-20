# 📦 Kurulum Rehberi

DRAKBEN - Otonom Pentest AI Framework Kurulumu

---

## 🐧 Linux (Kali / Ubuntu / Debian)

**Süre: ~2 dakika**

```bash
# 1. Repository'yi klonla
git clone https://github.com/ahmetdrak/drakben.git
cd drakben

# 2. Virtual environment oluştur
python3 -m venv .venv
source .venv/bin/activate

# 3. Bağımlılıkları yükle
pip install -r requirements.txt

# 4. Çalıştır
python3 drakben.py
```

### Opsiyonel: Pentest Araçları
```bash
sudo apt install nmap sqlmap nikto hydra john hashcat
```

---

## 🪟 Windows

**Süre: ~3 dakika**

```powershell
# 1. Repository'yi klonla
git clone https://github.com/ahmetdrak/drakben.git
cd drakben

# 2. Virtual environment oluştur
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Bağımlılıkları yükle
pip install -r requirements.txt

# 4. Çalıştır
python drakben.py
```

---

## 🍎 macOS

**Süre: ~3 dakika**

```bash
# 1. Repository'yi klonla
git clone https://github.com/ahmetdrak/drakben.git
cd drakben

# 2. Virtual environment oluştur
python3 -m venv .venv
source .venv/bin/activate

# 3. Bağımlılıkları yükle
pip install -r requirements.txt

# 4. Çalıştır
python3 drakben.py
```

### Opsiyonel: Homebrew ile Araçlar
```bash
brew install nmap sqlmap nikto hydra john hashcat
```

---

## 🤖 AI/LLM Kurulumu (Opsiyonel)

Framework **%100 offline** çalışır. AI özellikleri için aşağıdakilerden birini yapılandır:

### Seçenek A: Ollama (Ücretsiz, Yerel)

```bash
# 1. Ollama yükle: https://ollama.ai
# 2. Model indir
ollama pull llama3.2

# 3. Yapılandır (ilk çalıştırmada otomatik sorulur)
# veya manuel:
cp .env.example config/api.env
nano config/api.env
```

`config/api.env` içeriği:
```
LOCAL_LLM_URL=http://localhost:11434/api/generate
LOCAL_LLM_MODEL=llama3.2
```

### Seçenek B: OpenRouter (Ücretsiz modeller mevcut)

```bash
# 1. Ücretsiz API key al: https://openrouter.ai
# 2. Yapılandır
cp .env.example config/api.env
nano config/api.env
```

`config/api.env` içeriği:
```
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=deepseek/deepseek-chat
```

### Seçenek C: OpenAI (Ücretli)

```bash
# 1. API key al: https://platform.openai.com
# 2. Yapılandır
cp .env.example config/api.env
nano config/api.env
```

`config/api.env` içeriği:
```
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4o-mini
```

---

## ✅ Kurulumu Doğrula

```bash
# Virtual environment aktif değilse
source .venv/bin/activate  # Linux/Mac
# veya
.\.venv\Scripts\Activate.ps1  # Windows

# Çalıştır
python drakben.py

# Komutları test et
/help
/target 127.0.0.1
/status
/stats
/exit
```

---

## 🔧 Sorun Giderme

### `python3: command not found`
```bash
# Python 3.10+ yükle
sudo apt install python3.11
```

### `ModuleNotFoundError`
```bash
# Bağımlılıkları yeniden yükle
pip install -r requirements.txt
```

### `paramiko` veya `pycryptodome` hatası
```bash
# Opsiyonel, gerekirse yükle
pip install paramiko pycryptodome
```

### Permission denied (Linux)
```bash
sudo python3 drakben.py
# veya
chmod +x drakben.py
```

### API key çalışmıyor
- Uygulama API olmadan da çalışır (offline mod)
- `config/api.env` formatını kontrol et
- Key'in geçerli olduğunu doğrula

---

## 📋 Gereksinimler

| Bileşen | Minimum | Önerilen |
|---------|---------|----------|
| Python | 3.10+ | 3.11+ |
| RAM | 2 GB | 4 GB |
| Disk | 200 MB | 500 MB |
| OS | Linux/Windows/macOS | Kali Linux |

---

## 🧠 Hafıza Sistemi

DRAKBEN kalıcı hafıza kullanır:

- **`drakben_memory.db`**: SQLite veritabanı
- Otomatik oluşturulur, silmeyin
- Tüm komut geçmişi, öğrenilen patternler burada

---

## 🚀 Sonraki Adımlar

1. [README.md](README.md) - Özellikler
2. [QUICKSTART.md](QUICKSTART.md) - Kullanım örnekleri
3. AI yapılandır (yukarıya bak)

---

**Kurulum tamamlandı! İyi hacklemeler! 🎉**

⚠️ **Sadece yetkili hedeflerde kullanın.**
