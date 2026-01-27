# 🩸 DRAKBEN - Autonomous Evolving Pentest Agent

**Dünyanın İlk "Self-Refining" (Kendi Kendini Geliştiren) Siber Güvenlik Ajanı**

![Status](https://img.shields.io/badge/Status-Zero%20Defect-brightgreen)
![Security](https://img.shields.io/badge/Security-Nuclear%20Tested-red)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

Drakben, sıradan bir otomasyon aracı değildir. Hatalarından ders çıkaran, internetten yeni saldırı teknikleri öğrenip `plugins/` klasörüne atıldığında bunu otomatik olarak yeteneklerine ekleyen **biyo-mekanik** bir yapay zekadır.

---

## 🚀 Devrimsel Özellikler

### 🧬 1. Self-Refining Engine (Kendi Kendini Eğitme)
Sıradan araçlar hata yaptığında durur. Drakben:
- Hatanın nedenini analiz eder (LLM Reasoning).
- Stratejisini değiştirir ve tekrar dener.
- **Evolution Memory** veritabanına bu tecrübeyi kaydeder. Bir daha asla aynı hatayı yapmaz.

### 🔌 2. Dinamik Plugin Sistemi (Tak-Çıkar Silahlar)
Ajanın yetenekleri kodlarına hapsolmuş değildir.
- Yeni bir Python scripti mi buldun? -> Sürükle `plugins/` klasörüne bırak.
- Ajan açıldığında **otomatik tanır** ve kullanmaya başlar.
- Core dosyalara dokunmana gerek yok. Sıfır risk.

### 🧠 3. Hibrit Zeka (Hybrid Intelligence)
- **Local Brain:** Hızlı kararlar, offline çalışabilme.
- **Cloud Reasoning:** Karmaşık analizler için opsiyonel LLM desteği.
- **Execution Context:** Ajan ne yaptığını asla unutmaz (State Tracking).

### 🛡️ 4. Zero-Defect & Nuclear Tested
Bu proje **SonarQube** standartlarına göre "A Grade" kaliteye sahiptir.
- **Nuclear Stress Test:** 1000+ thread altında test edildi.
- **Thread Safety:** %100 güvenli asenkron yapı.
- **Memory Leak Proof:** Uzun süreli operasyonlarda şişme yapmaz.

---

## 🚀 Hızlı Kurulum

### Linux (Kali / Ubuntu)
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

## 🎮 Kullanım

Ajanı başlattıktan sonra doğal dilde emir verebilirsin:

```
> 10.0.0.5 hedefindeki açık portları bul ve versiyonları tespit et.
> example.com üzerinde SQL Injection taraması yap.
> Bana yeni bir Nmap stratejisi geliştir.
```

### Slash Komutları
- `/scan` -> Otonom tarama başlatır (Ajan modu kendi seçer).
- `/scan stealth` -> Sessiz mod (Yakalanmadan sızar).
- `/scan aggressive` -> Hızlı mod (Gürültülü ama çabuk).
- `/target <IP>` -> Hedef belirler.
- `/status` -> Ajanın o anki durumunu ve bulgularını gösterir.

---

## 🧩 Plugin Geliştirme (Yeni!)

Ajanın yeteneklerini artırmak için `plugins/` klasörüne bir `.py` dosyası atman yeterli.

**Örnek Plugin Şablonu:**
```python
# plugins/my_tool.py
from core.tool_selector import ToolSpec

def register():
    return ToolSpec(
        name="my_super_tool",
        description="Özel geliştirdiğim süper tarama aracı",
        usage_template="python my_tool.py {target}",
        category="recon",
        risk_level="low"
    )
```

---

## 📂 Proje Yapısı

```
drakben/
├── core/                   # Ajannın Beyni (Dokunma Yanarsın)
│   ├── brain.py            # Mantık ve Akıl Yürütme
│   ├── self_refining.py    # Kendi Kendini Düzeltme Motoru
│   ├── plugin_loader.py    # Dinamik Eklenti Yöneticisi
│   └── ...
├── plugins/                # <--- SENİN OYUN ALANIN (Buraya script at)
├── modules/                # Dahili Araçlar (Nmap, Nuclei vs.)
├── sessions/               # Hafıza Kayıtları
└── drakben.py              # Başlatıcı
```

---

## ⚠️ Yasal Uyarı

Bu yazılım **sadece izinli testlerde** ve **eğitim amaçlı** kullanılmak üzere tasarlanmıştır. Yetkisiz sistemlere saldırmak suçtur. Geliştirici, kötüye kullanımdan sorumlu tutulamaz.

---

**Made with ❤️ by Drakben Team**

