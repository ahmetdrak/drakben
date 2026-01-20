# Changelog

Tüm önemli değişiklikler bu dosyada belgelenir.

## 2026-01-20

### Eklendi
- 🧠 **Kalıcı Hafıza Sistemi** (`core/memory_manager.py`)
  - SQLite tabanlı kalıcı veritabanı
  - Otomatik komut ve çıktı kaydı
  - Pattern öğrenme (intent → command mapping)
  - Oturum yönetimi ve geçmişi
  - Hedef hafızası
  - Terminal çıktı logları
  
- 💻 **Sistem Tanıma**
  - OS, versiyon, hostname otomatik algılama
  - Root/sudo yetki tespiti
  - İnternet bağlantısı kontrolü
  - Mevcut araç listesi
  - Sistem profili kalıcı kayıt

- 📊 **İstatistikler** (`/stats`)
  - Oturum ve global hafıza istatistikleri
  - Öğrenilen pattern sayısı
  - Komut başarı oranları

### İyileştirildi
- Brain'e tam context verme (geçmiş, sistem, komutlar)
- Otomatik hafıza güncelleme (komut gerekmez)
- Oturum kapanışında temiz hafıza kapatma

## 2026-01-19

### Eklendi
- 25+ akıllı modül (core ve modules paketleri)
- Dracula tema UI (mor/pembe/kırmızı terminal)
- Slash komut sistemi (/help, /target, /scan, /status, /clear, /exit)
- Doğal dil işleme (AI ile konuş)
- Auto-healing: hataları otomatik düzelt, eksik araçları yükle
- Tek seferlik onay sistemi (bir kez onayla, sonra otonom)
- Çoklu LLM desteği (OpenRouter, Ollama, OpenAI)
- Sistem zekası: OS algılama, kaynak izleme, araç tarama
- Execution engine: akıllı terminal, retry ve fallback
- Autonomous solver: hata analizi ve kurtarma
- Security toolkit: güvenlik kontrolleri, payload üretimi, raporlama
- İnteraktif LLM setup (ilk çalıştırmada)

### İyileştirildi
- Ultra-minimal UI (tek birleşik panel)
- Profesyonel komut yönetimi (slash vs doğal dil)
- Türkçe/İngilizce tam destek
- Gelişmiş dokümantasyon

## 2026-01-15

### İlk Sürüm
- Temel pentest özellikleri
- Kali Linux entegrasyonu
- Basit exploit otomasyonu
