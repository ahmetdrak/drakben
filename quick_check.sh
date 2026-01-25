#!/bin/bash
# DRAKBEN Quick Status Check
# Auto-detect PID or use provided PID

if [ -z "$1" ]; then
    # Auto-detect PID
    PID=$(pgrep -f drakben.py | head -1)
    if [ -z "$PID" ]; then
        echo "❌ DRAKBEN process bulunamadı!"
        exit 1
    fi
    echo "🔍 Auto-detected PID: $PID"
else
    PID=$1
    echo "📌 Using provided PID: $PID"
fi

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

# 4. Process'in çalıştığı dizini bul
PROCESS_CWD=$(lsof -p $PID 2>/dev/null | grep "cwd" | awk '{print $NF}' | head -1)
if [ -z "$PROCESS_CWD" ]; then
    # Fallback: drakben klasörünü ara
    if [ -d "drakben" ]; then
        PROCESS_CWD="$PWD/drakben"
    elif [ -d "$HOME/drakben" ]; then
        PROCESS_CWD="$HOME/drakben"
    else
        PROCESS_CWD="$PWD"
    fi
fi

echo "=== PROCESS WORKING DIRECTORY ==="
echo "$PROCESS_CWD"
echo ""

# 5. Database Dosyaları (process'in çalıştığı dizinde)
echo "=== DATABASE FILES ==="
if [ -n "$PROCESS_CWD" ] && [ -d "$PROCESS_CWD" ]; then
    cd "$PROCESS_CWD" 2>/dev/null
    ls -lh evolution.db* drakben_evolution.db* 2>/dev/null || echo "Database dosyaları bulunamadı"
    cd - > /dev/null
else
    echo "Process working directory bulunamadı"
fi
echo ""

# 6. Database Lock Kontrolü
echo "=== DATABASE LOCK CHECK ==="
if [ -n "$PROCESS_CWD" ] && [ -d "$PROCESS_CWD" ]; then
    cd "$PROCESS_CWD" 2>/dev/null
    if [ -f "evolution.db" ]; then
        lsof evolution.db 2>/dev/null | grep -v "^COMMAND" || echo "Database lock yok"
    else
        echo "evolution.db dosyası bulunamadı"
    fi
    cd - > /dev/null
else
    echo "Process working directory bulunamadı"
fi
echo ""

# 7. Log Dosyaları (process'in çalıştığı dizinde)
echo "=== LOG FILES ==="
if [ -n "$PROCESS_CWD" ] && [ -d "$PROCESS_CWD" ]; then
    cd "$PROCESS_CWD" 2>/dev/null
    if [ -d "logs" ]; then
        ls -lh logs/*.log 2>/dev/null | tail -3
        echo ""
        echo "=== LAST 10 LOG LINES ==="
        tail -n 10 logs/drakben.log 2>/dev/null || echo "Log dosyası bulunamadı"
    else
        echo "logs/ klasörü bulunamadı"
    fi
    cd - > /dev/null
else
    echo "Process working directory bulunamadı"
fi
echo ""

# 8. Network Bağlantıları
echo "=== NETWORK CONNECTIONS ==="
netstat -tnp 2>/dev/null | grep $PID | head -5 || ss -tnp 2>/dev/null | grep $PID | head -5 || echo "Network bilgisi alınamadı"
echo ""

# 9. System Call Check (hangi call'da takılıyor?)
echo "=== CURRENT SYSTEM CALL (what is it waiting for?) ==="
if command -v strace >/dev/null 2>&1; then
    strace -p $PID -e trace=all -c -f 2>&1 | head -20 &
    STRACE_PID=$!
    sleep 3
    kill $STRACE_PID 2>/dev/null
else
    echo "strace bulunamadı (yüklemek için: sudo apt install strace)"
fi
echo ""

echo "=== CHECK COMPLETE ==="
echo "Eğer process takılıyorsa, yukarıdaki 'wchan' sütunu hangi system call'da beklediğini gösterir."
