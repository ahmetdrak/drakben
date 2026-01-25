# DRAKBEN - Monitoring ve Debug Komutları

Uygulama takıldığında veya hata aldığında başka bir terminalden durumu kontrol etmek için kullanabileceğiniz komutlar.

## 🔍 1. Process Durumunu Kontrol Etme

### Python Process'ini Bul
```bash
# Tüm Python process'lerini listele
ps aux | grep python

# DRAKBEN process'ini bul
ps aux | grep drakben

# Process ID'yi al
pgrep -f drakben.py
```

### Process Detaylarını Gör
```bash
# Process ID ile detaylı bilgi
ps -p $(pgrep -f drakben.py) -o pid,ppid,cmd,%mem,%cpu,etime

# Thread'leri gör
ps -T -p $(pgrep -f drakben.py)
```

### Process Tree (Parent-Child İlişkileri)
```bash
# Process tree'yi gör
pstree -p $(pgrep -f drakben.py)

# Veya
ps -ef | grep drakben
```

---

## 📊 2. System Resource Kullanımı

### CPU ve Memory Kullanımı
```bash
# Real-time monitoring
top -p $(pgrep -f drakben.py)

# Veya htop (daha detaylı)
htop -p $(pgrep -f drakben.py)

# Sadece memory
ps -p $(pgrep -f drakben.py) -o pid,%mem,rss,vsz
```

### I/O Kullanımı
```bash
# Disk I/O
iotop -p $(pgrep -f drakben.py)

# Network I/O
nethogs
```

---

## 🗄️ 3. Database Lock Kontrolü

### SQLite Database Lock Kontrolü
```bash
# Database dosyasını kontrol et
ls -lh evolution.db*

# Database lock durumunu kontrol et
sqlite3 evolution.db "PRAGMA database_list;"

# WAL dosyalarını kontrol et
ls -lh evolution.db-wal evolution.db-shm 2>/dev/null

# Database'deki aktif connection'ları gör (eğer mümkünse)
lsof evolution.db 2>/dev/null
```

### Database Lock Çözme (DİKKAT: Veri kaybı olabilir)
```bash
# Sadece acil durumlarda kullanın!
# Database'i kopyala
cp evolution.db evolution.db.backup

# WAL dosyalarını temizle (dikkatli!)
rm -f evolution.db-wal evolution.db-shm
```

---

## 📝 4. Log Dosyalarını Kontrol Etme

### Log Dosyalarını Bul
```bash
# Log dosyalarını ara
find . -name "*.log" -type f 2>/dev/null

# DRAKBEN log'larını ara
find . -name "*drakben*.log" -o -name "*drakben*.txt" 2>/dev/null

# Son değiştirilen log dosyalarını bul
find . -name "*.log" -mmin -10 2>/dev/null
```

### Log Dosyalarını İzle (Real-time)
```bash
# Son 50 satırı göster
tail -n 50 drakben.log

# Real-time takip (yeni satırlar geldikçe göster)
tail -f drakben.log

# Hata satırlarını filtrele
tail -f drakben.log | grep -i error
tail -f drakben.log | grep -i exception
tail -f drakben.log | grep -i timeout
```

---

## 🔬 5. System Call'ları İzleme (strace)

### Process'in Ne Yaptığını Gör
```bash
# System call'ları izle (çok detaylı!)
strace -p $(pgrep -f drakben.py) -e trace=all

# Sadece file operations
strace -p $(pgrep -f drakben.py) -e trace=file

# Sadece network operations
strace -p $(pgrep -f drakben.py) -e trace=network

# Sadece database operations
strace -p $(pgrep -f drakben.py) -e trace=open,read,write | grep -i "\.db"

# Timeout'ları gör
strace -p $(pgrep -f drakben.py) -e trace=poll,select,epoll_wait
```

### strace Output'unu Dosyaya Kaydet
```bash
strace -p $(pgrep -f drakben.py) -o strace_output.txt -f
```

---

## 🌐 6. Network Bağlantılarını Kontrol Etme

### Aktif Network Bağlantıları
```bash
# Tüm network bağlantılarını gör
netstat -tulpn | grep $(pgrep -f drakben.py)

# Veya ss komutu (daha hızlı)
ss -tulpn | grep $(pgrep -f drakben.py)

# Sadece ESTABLISHED bağlantılar
netstat -tnp | grep $(pgrep -f drakben.py) | grep ESTABLISHED
```

### Network Trafiğini İzle
```bash
# tcpdump ile network trafiğini izle
sudo tcpdump -i any -n host www.ardaninmutfagi.com

# Veya wireshark (GUI)
wireshark
```

---

## 🐍 7. Python-Specific Debugging

### Python Stack Trace'i Gör
```bash
# Python process'ine signal gönder (SIGUSR1 - stack trace)
kill -USR1 $(pgrep -f drakben.py)

# Veya py-spy ile profiling
py-spy top --pid $(pgrep -f drakben.py)
```

### Python Thread'lerini Gör
```bash
# Python thread'lerini listele
py-spy dump --pid $(pgrep -f drakben.py)
```

### Python Memory Profiling
```bash
# Memory kullanımını gör
py-spy record --pid $(pgrep -f drakben.py) --output profile.svg --format svg
```

---

## 🔒 8. File Lock Kontrolü

### Hangi Dosyalar Açık?
```bash
# Process'in açtığı tüm dosyaları gör
lsof -p $(pgrep -f drakben.py)

# Sadece database dosyalarını gör
lsof -p $(pgrep -f drakben.py) | grep -i "\.db"

# Lock'lu dosyaları gör
lsof -p $(pgrep -f drakben.py) | grep -i lock
```

---

## ⚡ 9. Hızlı Durum Kontrolü (Tek Komut)

### Tüm Önemli Bilgileri Bir Arada Gör
```bash
PID=$(pgrep -f drakben.py)
echo "=== PROCESS INFO ==="
ps -p $PID -o pid,ppid,cmd,%mem,%cpu,etime,state
echo ""
echo "=== THREADS ==="
ps -T -p $PID
echo ""
echo "=== OPEN FILES ==="
lsof -p $PID | head -20
echo ""
echo "=== NETWORK ==="
netstat -tulpn | grep $PID
echo ""
echo "=== DATABASE FILES ==="
ls -lh evolution.db* 2>/dev/null
```

---

## 🛑 10. Process'i Sonlandırma (Acil Durum)

### Graceful Termination
```bash
# SIGTERM gönder (graceful shutdown)
kill $(pgrep -f drakben.py)

# 5 saniye bekle, hala çalışıyorsa force kill
sleep 5 && kill -9 $(pgrep -f drakben.py) 2>/dev/null
```

### Force Kill (Tüm Process Tree)
```bash
# Process group'u kill et
kill -TERM -$(ps -o pgid= -p $(pgrep -f drakben.py))

# Veya pkill ile
pkill -f drakben.py
```

---

## 📋 11. Özel DRAKBEN Kontrolleri

### Evolution Database Kontrolü
```bash
# Database içeriğini kontrol et
sqlite3 evolution.db "SELECT COUNT(*) FROM strategies;"
sqlite3 evolution.db "SELECT COUNT(*) FROM strategy_profiles;"
sqlite3 evolution.db "SELECT COUNT(*) FROM policies;"
```

### Log Dosyası Kontrolü (Eğer varsa)
```bash
# Python logging output'unu kontrol et
journalctl -u python* 2>/dev/null

# Veya syslog'u kontrol et
grep drakben /var/log/syslog 2>/dev/null | tail -20
```

---

## 🎯 12. En Yaygın Sorunlar ve Çözümleri

### Sorun: Process takılıyor
```bash
# 1. Hangi system call'da takılıyor?
strace -p $(pgrep -f drakben.py) -c

# 2. Database lock var mı?
lsof evolution.db

# 3. Network bağlantısı bekliyor mu?
netstat -tnp | grep $(pgrep -f drakben.py) | grep SYN_SENT
```

### Sorun: Memory leak
```bash
# Memory kullanımını izle
watch -n 1 'ps -p $(pgrep -f drakben.py) -o pid,%mem,rss'
```

### Sorun: CPU %100
```bash
# Hangi thread CPU kullanıyor?
top -H -p $(pgrep -f drakben.py)
```

---

## 💡 İpuçları

1. **strace çok verbose olabilir** - Output'u dosyaya kaydedin
2. **Database lock** - En yaygın sorun, `lsof evolution.db` ile kontrol edin
3. **Network timeout** - `strace` ile `poll/select` call'larını izleyin
4. **Thread deadlock** - `py-spy dump` ile thread stack'lerini görün
5. **Memory leak** - `watch` ile memory kullanımını sürekli izleyin

---

## 📚 Ek Kaynaklar

- `man strace` - System call tracing
- `man lsof` - List open files
- `man netstat` - Network statistics
- `py-spy` - Python profiling tool (pip install py-spy)
