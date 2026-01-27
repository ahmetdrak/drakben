# 🦇 DRAKBEN - Autonomous AI Pentest Agent

**Drakben**, Yeni nesil, kendi kendini yöneten, evrimleşen ve kendi kendini iyileştiren (Self-Healing) bir Otonom Sızma Testi Ajanıdır.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Beta-orange)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black)

## 🚀 Özellikler

Drakben, sıradan bir otomasyon aracı değildir. Biyolojik bir organizma gibi tasarlanmıştır:

*   **🧠 Beyin (Brain):** Gelişmiş LLM entegrasyonu (OpenAI, Anthropic, Local LLM) ile karmaşık karar verme ve planlama.
*   **❤️ Kalp (Heart):** Ajanın yaşam döngüsünü, sağlık durumunu ve enerji yönetimini sağlar.
*   **🩸 Kan (Blood/State):** Tüm sistem durumunu, keşfedilen zafiyetleri ve kazanımları taşıyan merkezi veri yapısı.
*   **💪 Kas (Muscle/Executor):** Komutları güvenli bir şekilde çalıştıran, sandbox destekli yürütme motoru.

### 🌟 Temel Yetenekler

*   **🧬 Evrimsel Öğrenme:** Başarısız stratejilerden ders çıkarır ve kendini optimize eder. (Evolution Engine)
*   **🩹 Kendi Kendini İyileştirme (Self-Healing):** Hata alan araçları analiz eder, parametreleri düzeltir ve tekrar dener.
*   **🕵️‍♂️ Otonom Keşif & İstismar:**
    *   Akıllı Port Tarama (Nmap entegrasyonu)
    *   Web Zafiyet Taraması
    *   Active Directory Saldırıları (Kerberoasting, vb.)
    *   Payload Üretimi (Obfuscation & AV Bypass)
*   **🛡️ Güvenlik:**
    *   Komutlar `shell=False` ile güvenli çalıştırılır.
    *   Tehlikeli komutlar (rm -rf / vb.) engellenir.
    *   Durum takibi (State Persistence) ile veri kaybı önlenir.

## 📦 Kurulum

### Gereksinimler
*   Python 3.8 veya üzeri
*   Nmap, Metasploit (Opsiyonel ama önerilir)
*   Kali Linux (Önerilen İşletim Sistemi) veya Windows

### Adım Adım Kurulum

1.  **Depoyu Klonlayın:**
    ```bash
    git clone https://github.com/ahmetdrak/drakben.git
    cd drakben
    ```

2.  **Sanal Ortam Oluşturun (Önerilir):**
    ```bash
    python -m venv .venv
    # Windows:
    .venv\Scripts\activate
    # Linux/Mac:
    source .venv/bin/activate
    ```

3.  **Bağımlılıkları Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Yapılandırma:**
    `config/api.env` dosyasını düzenleyerek API anahtarlarınızı girin (OpenRouter, OpenAI vb.).
    *Not: API anahtarı olmadan da "Offline Mod"da çalışabilir.*

## 🎮 Kullanım

Ajanı başlatmak için:

```bash
python drakben.py
```

veya Windows için:

```cmd
start.bat
```

### Komutlar

Arayüz açıldığında şu komutları kullanabilirsiniz:

*   `/target <IP>` : Hedef sistemi belirler.
*   `/scan` : Otonom taramayı başlatır.
*   `/scan stealth` : Gizli (yavaş) tarama modu.
*   `/scan aggressive` : Hızlı (gürültülü) tarama modu.
*   `/help` : Tüm komutları listeler.
*   `/tr` : Türkçe diline geçer.

## ⚠️ Yasal Uyarı

Bu yazılım **sadece eğitim ve yasal güvenlik testleri** amacıyla geliştirilmiştir. Sahibi olmadığınız veya yazılı izniniz olmayan sistemlerde kullanmak **YASAKTIR**. Geliştiriciler, bu aracın kötüye kullanımından doğacak zararlardan sorumlu tutulamaz.

## 🤝 Katkıda Bulunma

Pull Request'ler kabul edilir. Büyük değişiklikler için önce bir Issue açarak tartışmanızı öneririz.

## 📜 Lisans

Bu proje MIT Lisansı ile lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakınız.
