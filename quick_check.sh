#!/bin/bash
# DRAKBEN Quick Status Check
# PID: 1206226

PID=1206226

echo "=== DRAKBEN Process Status (PID: $PID) ==="
echo ""

# 1. Process Detayları
echo "=== PROCESS INFO ==="
ps -p $PID -o pid,ppid,cmd,%mem,%cpu,etime,state,wchan 2>/dev/null || echo "Process bulunamadı!"
echo ""

# 2. Thread'ler
echo "=== THREADS ==="
ps -T -p $PID -o tid,pid,cmd,%cpu,%mem,state 2>/dev/null | head -10
echo ""

# 3. Açık Dosyalar (ilk 15)
echo "=== OPEN FILES (first 15) ==="
lsof -p $PID 2>/dev/null | head -15 || echo "lsof bulunamadı veya permission denied"
echo ""

# 4. Database Dosyaları
echo "=== DATABASE FILES ==="
ls -lh evolution.db* 2>/dev/null || echo "Database dosyaları bulunamadı"
echo ""

# 5. Database Lock Kontrolü
echo "=== DATABASE LOCK CHECK ==="
lsof evolution.db 2>/dev/null | grep -v "^COMMAND" || echo "Database lock yok veya lsof bulunamadı"
echo ""

# 6. Log Dosyaları
echo "=== LOG FILES ==="
if [ -d "logs" ]; then
    ls -lh logs/*.log 2>/dev/null | tail -3
    echo ""
    echo "=== LAST 10 LOG LINES ==="
    tail -n 10 logs/drakben.log 2>/dev/null || echo "Log dosyası bulunamadı"
else
    echo "logs/ klasörü bulunamadı"
fi
echo ""

# 7. Network Bağlantıları
echo "=== NETWORK CONNECTIONS ==="
netstat -tnp 2>/dev/null | grep $PID | head -5 || ss -tnp 2>/dev/null | grep $PID | head -5 || echo "Network bilgisi alınamadı"
echo ""

# 8. System Call Check (hangi call'da takılıyor?)
echo "=== CURRENT SYSTEM CALL (what is it waiting for?) ==="
strace -p $PID -e trace=all -c -f 2>&1 | head -20 &
STRACE_PID=$!
sleep 3
kill $STRACE_PID 2>/dev/null
echo ""

echo "=== CHECK COMPLETE ==="
echo "Eğer process takılıyorsa, yukarıdaki 'wchan' sütunu hangi system call'da beklediğini gösterir."
