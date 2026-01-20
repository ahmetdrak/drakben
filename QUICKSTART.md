# ⚡ Hızlı Başlangıç

DRAKBEN - Otonom Pentest AI Framework

---

## 🚀 İlk Çalıştırma

```bash
python drakben.py
```

İlk çalıştırmada:
1. Sistem otomatik algılanır (OS, yetkiler, araçlar)
2. AI kurulumu sorulur (opsiyonel, skip edilebilir)
3. Hoşgeldin ekranı gösterilir

---

## 🎯 Temel Kullanım

### Doğal Dil (AI ile Konuş):
```bash
💬 "10.0.0.1 portlarını tara"
💬 "192.168.1.1'de açık portları bul"
💬 "example.com sql injection test et"
💬 "hedef sistemde XSS ara"
💬 "payload üret 10.0.0.1:4444"
💬 "reverse shell bağlantısı kur"
```

### Slash Komutları (Sistem):
```bash
/target 192.168.1.100    # Hedef belirle
/scan                     # Hedefi tara
/status                   # Sistem durumu
/stats                    # Hafıza istatistikleri
/help                     # Yardım
/clear                    # Ekranı temizle
/exit                     # Çıkış
```

---

## 📋 Komut Referansı

### Slash Komutları
| Komut | Açıklama |
|-------|----------|
| `/help` | Detaylı yardım göster |
| `/target <IP>` | Hedef belirle (örn: /target 192.168.1.1) |
| `/scan` | Mevcut hedefi tara |
| `/status` | Sistem ve agent durumu |
| `/stats` | Hafıza ve AI istatistikleri |
| `/clear` | Ekranı temizle |
| `/exit` | Çıkış |

### Doğal Dil Örnekleri
| Örnek | Ne Yapar |
|-------|----------|
| "10.0.0.1'i tara" | nmap ile port taraması |
| "sql injection test et" | sqlmap ile SQL injection testi |
| "XSS ara" | XSS açığı taraması |
| "shell at" | Reverse shell bağlantısı |
| "payload üret" | msfvenom payload |
| "brute force yap" | Hydra ile parola kırma |

---

## 🧠 Hafıza Sistemi

DRAKBEN her şeyi otomatik hatırlar:

### Otomatik Kaydedilenler:
- ✅ Tüm komutlar ve çıktıları
- ✅ Başarılı/başarısız işlemler
- ✅ Konuşma geçmişi
- ✅ Hedefler ve bulgular
- ✅ Sistem bilgileri

### Öğrenme:
- Başarılı komutlar pattern olarak öğrenilir
- Sonraki sefere benzer isteklerde önerilir
- Approval verilen komutlar hatırlanır

### İstatistikler (`/stats`):
```
🧠 Memory (Session):
  Session ID: 5
  Messages: 24
  Commands: 12 (10 successful)

📚 Memory (Global):
  Total Sessions: 5
  Total Commands: 87
  Learned Patterns: 23
  Known Targets: 8
```

---

## ⚡ Onay Sistemi

### İlk Kez:
```
💡 Command: nmap -sV 192.168.1.1
   Approve? (y/n) [y] y
✅ Approved - similar commands will run automatically
```

### Sonraki Seferler:
Aynı tip komutlar otomatik çalışır, tekrar onay istenmez.

---

## 🔧 Auto-Healing

Hata olursa otomatik düzeltilir:

```
❌ Command failed: nmap not found
🔧 Attempting auto-heal...
📥 Installing nmap...
✅ Auto-healed! Retrying...
```

---

## 🎨 Özellikler

| Özellik | Açıklama |
|---------|----------|
| 🧠 Kalıcı Hafıza | SQLite ile tüm geçmiş saklanır |
| 🤖 Otonom Çalışma | Tek onay, sonra otomatik |
| 🔧 Auto-Healing | Hatalar otomatik düzeltilir |
| 🛡️ Güvenlik | Tehlikeli komutlar engellenir |
| 🎨 Dracula Tema | Mor/pembe terminal UI |
| 🌍 Çoklu Dil | Türkçe/İngilizce |

---

## 📊 Örnek Oturum

```
🩸 DRAKBEN | Ready
💬 /help  /target  /scan  /status  /clear  /exit

💬 > /target 192.168.1.100
🎯 Target: 192.168.1.100

💬 > 192.168.1.100 portlarını tara
🧠 Thinking...
🎯 Intent: port_scan
📋 Plan (3 steps):
  1. Quick port scan
  2. Service detection
  3. Analyze results

💡 Command: nmap -sV 192.168.1.100
   Approve? (y/n) [y] y
✅ Approved

⚡ Executing...
✅ Success! (took 12.34s)

📄 Output:
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2
80/tcp   open  http    Apache 2.4.41
443/tcp  open  https   Apache 2.4.41

💡 Insights:
  • 3 open ports found
  • SSH and web server detected
  • Consider web vulnerability scan

💬 > /stats
📈 STATISTICS
...
```

---

## 🚀 İpuçları

1. **Net ol**: "tara" yerine "port tara" veya "web tara" de
2. **Hedef belirle**: `/target` ile başla
3. **Türkçe kullan**: AI Türkçe anlıyor
4. **`/stats` kontrol et**: Hafıza durumunu gör
5. **Offline çalışır**: API olmadan da kullanılabilir

---

## ⚠️ Uyarı

**Sadece yetkili hedeflerde kullanın!**

- Kendi sistemleriniz
- İzin aldığınız sistemler
- CTF/Lab ortamları

---

**İyi hacklemeler! 🎉**
