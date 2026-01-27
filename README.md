# 🦇 DRAKBEN - Autonomous AI Pentest Agent

<div align="center">

![DRAKBEN Banner](https://capsule-render.vercel.app/api?type=waving&color=auto&height=200&section=header&text=DRAKBEN&fontSize=90&animation=fadeIn&fontAlignY=38&desc=Autonomous%20Self-Refining%20AI%20Hacker&descAlignY=51&descAlign=62)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Status](https://img.shields.io/badge/Status-Stable-success?style=for-the-badge)](https://github.com/ahmetdrak/drakben)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

*Yeni nesil, kendi kendini yöneten, evrimleşen ve iyileştiren Otonom Sızma Testi Ajanı.*

[🇬🇧 English](README_EN.md) | [🇹🇷 Türkçe](README.md)

</div>

---

## 🚀 Nedir?

**Drakben**, sıradan bir otomasyon aracı değildir. Otonom bir yapay zeka ajanıdır.

Geleneksel araçlar (Nmap, Metasploit) birer "çekiç" ise, Drakben o çekici tutan "usta"dır. Hedefi analiz eder, hangi aracı kullanacağına karar verir, hata alırsan stratejisini değiştirir ve sonucu raporlar.

### 🔥 Öne Çıkan Özellikler

*   **🧠 Otonom Zeka (Brain):** LLM (GPT-4o, Claude 3.5, Local Llama) desteği ile karmaşık karar verme yeteneği.
*   **🧬 Evrimsel Öğrenme (Evolution):** Başarısız stratejilerden ders çıkarır. Aynı hatayı iki kez yapmaz.
*   **🩹 Self-Healing (Kendi Kendini Onarma):** Bir araç hata verirse (örn: parametre hatası), ajan bunu fark eder, düzeltir ve tekrar çalıştırır.
*   **🦠 Polimorfik Payload:** Antivirüsleri atlatmak için her seferinde farklı (randomize edilmiş) exploit kodları üretir.
*   **�️ Güvenli Sandbox:** Komutları izole bir ortamda, güvenlik filtrelerinden geçirerek çalıştırır (`shell=False`).

## 🛠️ Yetenekler (Modules)

| Modül | Açıklama |
| :--- | :--- |
| **🔍 Recon** | Akıllı Port Tarama, Subdomain Keşfi (Nmap, Sublist3r entegrasyonu) |
| **💥 Exploit** | Metasploit, SQLMap ve Hydra kullanarak zafiyet sömürme |
| **🔑 Password** | Brute-force saldırıları (SSH, FTP, RDP) için Hydra otomasyonu |
| **🎁 Payload** | Base64, Hex, ve Custom Encoder ile AV Bypass payload üretimi |
| **📄 Rapor** | Bulguları JSON, HTML ve PDF formatında profesyonelce raporlar |

## 📦 Kurulum

### Ön Gereksinimler
*   Python 3.8+
*   Git
*   Kali Linux (Önerilir) veya Windows

### Hızlı Başlangıç

1.  **Depoyu Klonlayın:**
    ```bash
    git clone https://github.com/ahmetdrak/drakben.git
    cd drakben
    ```

2.  **Sanal Ortam Kurun (Tavsiye Edilir):**
    ```bash
    # Linux / Mac
    python3 -m venv .venv
    source .venv/bin/activate

    # Windows
    python -m venv .venv
    .venv\Scripts\activate
    ```

3.  **Bağımlılıkları Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Ayarları Yapın:**
    `config/api.env` dosyasını düzenleyin ve API anahtarınızı (OpenRouter, OpenAI vb.) girin.

## 🎮 Kullanım

Ajanı başlatmak için:

```bash
python drakben.py
```

**(Windows Kullanıcıları için `start.bat` dosyasına çift tıklamak yeterlidir.)**

### 💻 Komutlar

Arayüz açıldığında:

*   `/target <IP>` : 🎯 Hedefi belirler (Örn: `/target 192.168.1.10`)
*   `/scan` : 🕵️‍♂️ Otonom taramayı başlatır (Ajan kontrolü ele alır)
*   `/mode stealth` : 🥷 Gizli (sessiz) modda çalışır
*   `/help` : ❓ Tüm komutları listeler

## ⚠️ Yasal Uyarı

> 🚨 **DİKKAT:** Bu yazılım **sadece eğitim ve yasal güvenlik testleri (Pentest)** amacıyla geliştirilmiştir.
> Sahibi olmadığınız veya yazılı izniniz (Authorized) olmayan sistemlerde kullanmak **YASAKTIR**.
> Geliştirici (@ahmetdrak), bu aracın kötü niyetli kullanımından doğacak hiçbir zarardan sorumlu tutulamaz.

## 🤝 Katkıda Bulunma

Pull Request'leriniz memnuniyetle karşılanır. Büyük değişiklikler için lütfen önce Issue açarak tartışınız..

## 👨‍� Geliştirici

**Ahmet Drak**
*   GitHub: [@ahmetdrak](https://github.com/ahmetdrak)

---
<div align="center">
Made with ❤️ & ☕ by Drakben Team
</div>
