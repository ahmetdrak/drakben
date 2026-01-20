# Katkıda Bulunma

DRAKBEN projesine katkıda bulunmak istediğiniz için teşekkürler! 🩸

## Nasıl Katkıda Bulunulur

### 1. Fork & Clone

```bash
# GitHub'da fork yap, sonra:
git clone https://github.com/YOUR_USERNAME/drakben.git
cd drakben
```

### 2. Branch Oluştur

```bash
git checkout -b feature/ozellik-adi
```

### 3. Değişiklik Yap

- Mevcut kod stilini takip et
- Fonksiyonlara docstring ekle
- Değişikliklerini test et

### 4. Commit & Push

```bash
git add .
git commit -m "feat: özellik açıklaması"
git push origin feature/ozellik-adi
```

### 5. Pull Request Aç

GitHub'da "New Pull Request" tıkla

---

## Kod Standartları

- **Python**: 3.10+
- **Stil**: PEP 8 takip et
- **Docstring**: Tüm fonksiyonlar için gerekli
- **Type hints**: Önerilir

### Commit Mesaj Formatı

```
type: kısa açıklama

Tipler:
- feat: yeni özellik
- fix: hata düzeltme
- docs: dokümantasyon
- refactor: kod yeniden düzenleme
- test: test ekleme
```

---

## Proje Yapısı

```
drakben/
├── drakben.py              # Ana giriş noktası
├── core/
│   ├── agent.py            # Ana agent - DEĞİŞİKLİKLER DİKKATLİ
│   ├── brain.py            # AI reasoning
│   ├── memory_manager.py   # Hafıza sistemi
│   ├── execution_engine.py # Komut çalıştırma
│   └── ...
├── llm/                    # LLM entegrasyonu
├── modules/                # Pentest modülleri
└── config/                 # Konfigürasyon
```

### Önemli Dosyalar

| Dosya | Açıklama | Dikkat |
|-------|----------|--------|
| `core/agent.py` | Ana orchestrator | Dikkatli değiştir |
| `core/memory_manager.py` | Hafıza sistemi | Veritabanı şemasına dikkat |
| `core/brain.py` | AI reasoning | LLM entegrasyonu |

---

## Nereye Katkıda Bulunulur

### ✅ Kabul Edilenler

- Hata düzeltmeleri
- Yeni pentest modülleri (`modules/` altına)
- Dokümantasyon iyileştirmeleri
- Performans optimizasyonları
- Yeni CVE algılamaları
- Çeviri (i18n) desteği
- Yeni LLM provider desteği

### ❌ Kabul Edilmeyenler

- Zararlı kod
- Testsiz kod
- Tartışmasız breaking changes
- Lisans ihlalleri

---

## Test

```bash
# Tüm testleri çalıştır
pytest -v

# Belirli test
pytest tests/test_brain.py -v

# Coverage ile
pytest --cov=core tests/
```

---

## Yeni Modül Ekleme

`modules/` altına yeni modül eklemek için:

```python
# modules/my_module.py

class MyModule:
    """Modül açıklaması"""
    
    def __init__(self):
        pass
    
    def scan(self, target: str) -> dict:
        """
        Tarama yap.
        
        Args:
            target: Hedef IP/domain
            
        Returns:
            Tarama sonuçları
        """
        # Implementasyon
        return {"status": "success", "findings": []}
```

---

## Hafıza Sistemi

`core/memory_manager.py` değiştirirken:

1. Veritabanı şema değişikliklerini belgele
2. Migration gerekliyse ekle
3. Mevcut verileri korumaya dikkat et

---

## Pull Request Checklist

- [ ] Kod PEP 8 uyumlu
- [ ] Docstringler eklendi
- [ ] Testler yazıldı/güncellendi
- [ ] CHANGELOG güncellendi
- [ ] Dokümantasyon güncellendi

---

## İletişim

- GitHub Issues: Hata raporları ve öneriler
- Pull Requests: Kod katkıları

---

**Teşekkürler! 🩸**
