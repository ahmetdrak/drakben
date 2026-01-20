#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# core/memory_manager.py
# DRAKBEN Memory Manager - Kalıcı Hafıza Sistemi

import sqlite3
import json
import os
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path
import threading


class MemoryManager:
    """
    DRAKBEN Hafıza Yöneticisi
    
    Özellikler:
    - Kalıcı veritabanı hafızası (SQLite)
    - Konuşma geçmişi
    - Komut geçmişi
    - Terminal çıktı geçmişi
    - Öğrenilen kalıplar
    - Oturum bazlı veri
    """
    
    def __init__(self, db_path: str = "drakben_memory.db"):
        self.db_path = Path(db_path)
        self.connection = None
        self._lock = threading.Lock()
        self.current_session_id = None
        self._init_database()
        self._start_new_session()
    
    def _init_database(self):
        """Veritabanını başlat ve tabloları oluştur"""
        with self._lock:
            self.connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            cursor = self.connection.cursor()
            
            # Oturumlar tablosu
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ended_at TIMESTAMP,
                    target TEXT,
                    commands_count INTEGER DEFAULT 0,
                    notes TEXT
                )
            """)
            
            # Konuşma geçmişi tablosu
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                )
            """)
            
            # Komut geçmişi tablosu
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    command TEXT NOT NULL,
                    stdout TEXT,
                    stderr TEXT,
                    return_code INTEGER,
                    duration REAL,
                    success BOOLEAN,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    context TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                )
            """)
            
            # Öğrenilen kalıplar tablosu (intent -> command mapping)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learned_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    intent TEXT NOT NULL,
                    command TEXT NOT NULL,
                    success_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    context TEXT,
                    UNIQUE(intent, command)
                )
            """)
            
            # Onaylanmış komutlar tablosu
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS approved_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_signature TEXT UNIQUE NOT NULL,
                    approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    approval_count INTEGER DEFAULT 1
                )
            """)
            
            # Hedefler ve bulgular tablosu
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE NOT NULL,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT,
                    findings TEXT
                )
            """)
            
            # Kısa süreli hafıza (son işlemler)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS short_term_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    expires_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            self.connection.commit()
    
    def _start_new_session(self) -> int:
        """Yeni oturum başlat"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("INSERT INTO sessions DEFAULT VALUES")
            self.connection.commit()
            self.current_session_id = cursor.lastrowid
        return self.current_session_id
    
    def end_session(self, notes: str = ""):
        """Oturumu sonlandır"""
        if not self.current_session_id:
            return
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE sessions SET ended_at = ?, notes = ?
                WHERE id = ?
            """, (datetime.now(), notes, self.current_session_id))
            self.connection.commit()
    
    # ==================== KONUŞMA HAFıZASI ====================
    
    def add_conversation(self, role: str, content: str, metadata: Dict = None):
        """Konuşma ekle (user/assistant/system)"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO conversations (session_id, role, content, metadata)
                VALUES (?, ?, ?, ?)
            """, (self.current_session_id, role, content, json.dumps(metadata or {})))
            self.connection.commit()
    
    def get_conversation_history(self, limit: int = 20) -> List[Dict]:
        """Konuşma geçmişini getir"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT role, content, timestamp, metadata 
                FROM conversations
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (self.current_session_id, limit))
            rows = cursor.fetchall()
        
        history = []
        for row in reversed(rows):
            history.append({
                "role": row["role"],
                "content": row["content"],
                "timestamp": row["timestamp"],
                "metadata": json.loads(row["metadata"]) if row["metadata"] else {}
            })
        return history
    
    def get_context_for_llm(self, max_messages: int = 10) -> List[Dict]:
        """LLM için context oluştur"""
        history = self.get_conversation_history(max_messages)
        return [{"role": msg["role"], "content": msg["content"]} for msg in history]
    
    # ==================== KOMUT HAFıZASI ====================
    
    def log_command(self, command: str, stdout: str = "", stderr: str = "",
                   return_code: int = 0, duration: float = 0.0, 
                   success: bool = True, context: Dict = None) -> int:
        """Komut çalıştırma sonucunu kaydet"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO command_history 
                (session_id, command, stdout, stderr, return_code, duration, success, context)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (self.current_session_id, command, stdout, stderr, 
                  return_code, duration, success, json.dumps(context or {})))
            
            # Oturum komut sayısını artır
            cursor.execute("""
                UPDATE sessions SET commands_count = commands_count + 1
                WHERE id = ?
            """, (self.current_session_id,))
            
            self.connection.commit()
            return cursor.lastrowid
    
    def get_command_history(self, limit: int = 50) -> List[Dict]:
        """Komut geçmişini getir"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT command, stdout, stderr, return_code, duration, success, executed_at, context
                FROM command_history
                WHERE session_id = ?
                ORDER BY executed_at DESC
                LIMIT ?
            """, (self.current_session_id, limit))
            rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    
    def get_last_command_output(self) -> Optional[Dict]:
        """Son komut çıktısını getir"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT command, stdout, stderr, return_code, success
                FROM command_history
                WHERE session_id = ?
                ORDER BY executed_at DESC
                LIMIT 1
            """, (self.current_session_id,))
            row = cursor.fetchone()
        return dict(row) if row else None
    
    def search_commands(self, keyword: str) -> List[Dict]:
        """Komut geçmişinde ara"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT command, stdout, success, executed_at
                FROM command_history
                WHERE command LIKE ?
                ORDER BY executed_at DESC
                LIMIT 20
            """, (f"%{keyword}%",))
            rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    # ==================== ÖĞRENME HAFıZASI ====================
    
    def learn_pattern(self, intent: str, command: str, success: bool, context: Dict = None):
        """Intent-command eşlemesini öğren"""
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("""
                    INSERT INTO learned_patterns (intent, command, context)
                    VALUES (?, ?, ?)
                """, (intent, command, json.dumps(context or {})))
            except sqlite3.IntegrityError:
                # Var olan pattern - sayacı güncelle
                if success:
                    cursor.execute("""
                        UPDATE learned_patterns 
                        SET success_count = success_count + 1, last_used = ?
                        WHERE intent = ? AND command = ?
                    """, (datetime.now(), intent, command))
                else:
                    cursor.execute("""
                        UPDATE learned_patterns 
                        SET fail_count = fail_count + 1, last_used = ?
                        WHERE intent = ? AND command = ?
                    """, (datetime.now(), intent, command))
            self.connection.commit()
    
    def get_best_command_for_intent(self, intent: str) -> Optional[str]:
        """Intent için en iyi komutu getir"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT command, success_count, fail_count
                FROM learned_patterns
                WHERE intent LIKE ?
                ORDER BY (success_count - fail_count) DESC, last_used DESC
                LIMIT 1
            """, (f"%{intent}%",))
            row = cursor.fetchone()
        return row["command"] if row else None
    
    # ==================== ONAY HAFıZASI ====================
    
    def approve_command(self, command_signature: str):
        """Komutu onayla"""
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("""
                    INSERT INTO approved_commands (command_signature)
                    VALUES (?)
                """, (command_signature,))
            except sqlite3.IntegrityError:
                cursor.execute("""
                    UPDATE approved_commands 
                    SET approval_count = approval_count + 1
                    WHERE command_signature = ?
                """, (command_signature,))
            self.connection.commit()
    
    def is_approved(self, command_signature: str) -> bool:
        """Komutun onaylı olup olmadığını kontrol et"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT id FROM approved_commands
                WHERE command_signature = ?
            """, (command_signature,))
            row = cursor.fetchone()
        return row is not None
    
    def get_all_approved_commands(self) -> List[str]:
        """Tüm onaylı komutları getir"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("SELECT command_signature FROM approved_commands")
            rows = cursor.fetchall()
        return [row["command_signature"] for row in rows]
    
    # ==================== HEDEF HAFıZASI ====================
    
    def remember_target(self, target: str, notes: str = "", findings: Dict = None):
        """Hedefi hatırla"""
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("""
                    INSERT INTO targets (target, notes, findings)
                    VALUES (?, ?, ?)
                """, (target, notes, json.dumps(findings or {})))
            except sqlite3.IntegrityError:
                cursor.execute("""
                    UPDATE targets 
                    SET last_seen = ?, notes = ?, findings = ?
                    WHERE target = ?
                """, (datetime.now(), notes, json.dumps(findings or {}), target))
            
            # Oturuma hedefi ekle
            cursor.execute("""
                UPDATE sessions SET target = ?
                WHERE id = ?
            """, (target, self.current_session_id))
            
            self.connection.commit()
    
    def get_target_info(self, target: str) -> Optional[Dict]:
        """Hedef bilgilerini getir"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT target, first_seen, last_seen, notes, findings
                FROM targets
                WHERE target = ?
            """, (target,))
            row = cursor.fetchone()
        if row:
            result = dict(row)
            result["findings"] = json.loads(result["findings"]) if result["findings"] else {}
            return result
        return None
    
    def get_all_targets(self) -> List[Dict]:
        """Tüm hedefleri getir"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT target, first_seen, last_seen, notes
                FROM targets
                ORDER BY last_seen DESC
            """)
            rows = cursor.fetchall()
        return [dict(row) for row in rows]
    
    # ==================== KISA SÜRE HAFıZA ====================
    
    def set_temp(self, key: str, value: Any, ttl_seconds: int = 3600):
        """Geçici değer kaydet"""
        expires_at = datetime.now().timestamp() + ttl_seconds
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("""
                    INSERT INTO short_term_memory (key, value, expires_at)
                    VALUES (?, ?, datetime(?, 'unixepoch'))
                """, (key, json.dumps(value), expires_at))
            except sqlite3.IntegrityError:
                cursor.execute("""
                    UPDATE short_term_memory 
                    SET value = ?, expires_at = datetime(?, 'unixepoch')
                    WHERE key = ?
                """, (json.dumps(value), expires_at, key))
            self.connection.commit()
    
    def get_temp(self, key: str) -> Optional[Any]:
        """Geçici değer getir"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT value FROM short_term_memory
                WHERE key = ? AND expires_at > datetime('now')
            """, (key,))
            row = cursor.fetchone()
        return json.loads(row["value"]) if row else None
    
    def clear_expired_temp(self):
        """Süresi dolmuş geçici değerleri temizle"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                DELETE FROM short_term_memory
                WHERE expires_at <= datetime('now')
            """)
            self.connection.commit()
    
    # ==================== İSTATİSTİKLER ====================
    
    def get_session_stats(self) -> Dict:
        """Oturum istatistiklerini getir"""
        with self._lock:
            cursor = self.connection.cursor()
            
            # Toplam konuşma
            cursor.execute("""
                SELECT COUNT(*) as count FROM conversations
                WHERE session_id = ?
            """, (self.current_session_id,))
            conv_count = cursor.fetchone()["count"]
            
            # Toplam komut
            cursor.execute("""
                SELECT COUNT(*) as total, 
                       SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful
                FROM command_history
                WHERE session_id = ?
            """, (self.current_session_id,))
            cmd_stats = dict(cursor.fetchone())
            
            # Oturum bilgisi
            cursor.execute("""
                SELECT started_at, target FROM sessions
                WHERE id = ?
            """, (self.current_session_id,))
            session_info = dict(cursor.fetchone())
        
        return {
            "session_id": self.current_session_id,
            "started_at": session_info["started_at"],
            "target": session_info["target"],
            "conversation_count": conv_count,
            "commands_total": cmd_stats["total"] or 0,
            "commands_successful": cmd_stats["successful"] or 0
        }
    
    def get_global_stats(self) -> Dict:
        """Genel istatistikleri getir"""
        with self._lock:
            cursor = self.connection.cursor()
            
            # Toplam oturum
            cursor.execute("SELECT COUNT(*) as count FROM sessions")
            session_count = cursor.fetchone()["count"]
            
            # Toplam komut
            cursor.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful
                FROM command_history
            """)
            cmd_stats = dict(cursor.fetchone())
            
            # Toplam hedef
            cursor.execute("SELECT COUNT(*) as count FROM targets")
            target_count = cursor.fetchone()["count"]
            
            # Öğrenilmiş kalıp sayısı
            cursor.execute("SELECT COUNT(*) as count FROM learned_patterns")
            pattern_count = cursor.fetchone()["count"]
        
        return {
            "total_sessions": session_count,
            "total_commands": cmd_stats["total"] or 0,
            "successful_commands": cmd_stats["successful"] or 0,
            "total_targets": target_count,
            "learned_patterns": pattern_count
        }
    
    def get_memory_summary(self) -> str:
        """Hafıza özetini text olarak getir"""
        stats = self.get_session_stats()
        global_stats = self.get_global_stats()
        
        summary = f"""
📊 Oturum Hafızası:
  • Oturum ID: {stats['session_id']}
  • Başlangıç: {stats['started_at']}
  • Hedef: {stats['target'] or 'Belirlenmedi'}
  • Konuşma: {stats['conversation_count']} mesaj
  • Komut: {stats['commands_total']} ({stats['commands_successful']} başarılı)

📈 Genel Hafıza:
  • Toplam Oturum: {global_stats['total_sessions']}
  • Toplam Komut: {global_stats['total_commands']}
  • Öğrenilmiş Kalıp: {global_stats['learned_patterns']}
  • Bilinen Hedef: {global_stats['total_targets']}
"""
        return summary.strip()
    
    # ==================== SİSTEM TANIMA ====================
    
    def save_system_profile(self, profile: Dict):
        """Sistem profilini kaydet"""
        self.set_temp("system_profile", profile, ttl_seconds=86400)  # 24 saat
        
        # Ayrıca kalıcı olarak da sakla
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    is_root BOOLEAN,
                    has_internet BOOLEAN,
                    available_tools TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    full_profile TEXT
                )
            """)
            cursor.execute("""
                INSERT INTO system_profiles 
                (hostname, os_name, os_version, is_root, has_internet, available_tools, full_profile)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.get("hostname", "unknown"),
                profile.get("os", "unknown"),
                profile.get("os_version", "unknown"),
                profile.get("is_root", False),
                profile.get("has_internet", False),
                json.dumps(profile.get("available_tools", [])),
                json.dumps(profile)
            ))
            self.connection.commit()
    
    def get_system_profile(self) -> Optional[Dict]:
        """Son sistem profilini getir"""
        # Önce temp'den dene
        profile = self.get_temp("system_profile")
        if profile:
            return profile
        
        # Yoksa veritabanından
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("""
                    SELECT full_profile FROM system_profiles
                    ORDER BY detected_at DESC
                    LIMIT 1
                """)
                row = cursor.fetchone()
                if row:
                    return json.loads(row["full_profile"])
            except:
                pass
        return None
    
    # ==================== TERMİNAL İZLEME ====================
    
    def log_terminal_output(self, terminal_id: str, output: str, command: str = ""):
        """Terminal çıktısını kaydet"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS terminal_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    terminal_id TEXT,
                    command TEXT,
                    output TEXT,
                    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                INSERT INTO terminal_logs (session_id, terminal_id, command, output)
                VALUES (?, ?, ?, ?)
            """, (self.current_session_id, terminal_id, command, output[:10000]))
            self.connection.commit()
    
    def get_recent_terminal_output(self, limit: int = 5) -> List[Dict]:
        """Son terminal çıktılarını getir"""
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("""
                    SELECT terminal_id, command, output, logged_at
                    FROM terminal_logs
                    WHERE session_id = ?
                    ORDER BY logged_at DESC
                    LIMIT ?
                """, (self.current_session_id, limit))
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except:
                return []
    
    # ==================== AKILLI ARAMA ====================
    
    def search_all(self, keyword: str) -> Dict:
        """Tüm hafızada ara"""
        results = {
            "commands": [],
            "conversations": [],
            "patterns": [],
            "targets": []
        }
        
        with self._lock:
            cursor = self.connection.cursor()
            
            # Komutlarda ara
            cursor.execute("""
                SELECT command, success, executed_at FROM command_history
                WHERE command LIKE ? OR stdout LIKE ?
                ORDER BY executed_at DESC LIMIT 10
            """, (f"%{keyword}%", f"%{keyword}%"))
            results["commands"] = [dict(row) for row in cursor.fetchall()]
            
            # Konuşmalarda ara
            cursor.execute("""
                SELECT role, content, timestamp FROM conversations
                WHERE content LIKE ?
                ORDER BY timestamp DESC LIMIT 10
            """, (f"%{keyword}%",))
            results["conversations"] = [dict(row) for row in cursor.fetchall()]
            
            # Patternlarda ara
            cursor.execute("""
                SELECT intent, command, success_count FROM learned_patterns
                WHERE intent LIKE ? OR command LIKE ?
                ORDER BY success_count DESC LIMIT 5
            """, (f"%{keyword}%", f"%{keyword}%"))
            results["patterns"] = [dict(row) for row in cursor.fetchall()]
            
            # Hedeflerde ara
            cursor.execute("""
                SELECT target, notes FROM targets
                WHERE target LIKE ? OR notes LIKE ?
                ORDER BY last_seen DESC LIMIT 5
            """, (f"%{keyword}%", f"%{keyword}%"))
            results["targets"] = [dict(row) for row in cursor.fetchall()]
        
        return results
    
    def get_full_context_for_ai(self) -> Dict:
        """AI için tam context oluştur - konuşma, sistem, hedefler dahil"""
        context = {
            "conversation_history": self.get_context_for_llm(15),
            "system_profile": self.get_system_profile(),
            "current_target": None,
            "recent_commands": [],
            "learned_patterns_count": 0
        }
        
        with self._lock:
            cursor = self.connection.cursor()
            
            # Hedef
            cursor.execute("""
                SELECT target FROM sessions WHERE id = ?
            """, (self.current_session_id,))
            row = cursor.fetchone()
            if row:
                context["current_target"] = row["target"]
            
            # Son 5 komut
            cursor.execute("""
                SELECT command, success FROM command_history
                WHERE session_id = ?
                ORDER BY executed_at DESC LIMIT 5
            """, (self.current_session_id,))
            context["recent_commands"] = [dict(row) for row in cursor.fetchall()]
            
            # Öğrenilmiş kalıp sayısı
            cursor.execute("SELECT COUNT(*) as count FROM learned_patterns")
            context["learned_patterns_count"] = cursor.fetchone()["count"]
        
        return context
    
    def close(self):
        """Veritabanı bağlantısını kapat"""
        self.end_session()
        if self.connection:
            self.connection.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Global memory instance
_memory_instance: Optional[MemoryManager] = None


def get_memory() -> MemoryManager:
    """Global hafıza instance'ı al"""
    global _memory_instance
    if _memory_instance is None:
        _memory_instance = MemoryManager()
    return _memory_instance


def reset_memory():
    """Hafızayı sıfırla (test için)"""
    global _memory_instance
    if _memory_instance:
        _memory_instance.close()
    _memory_instance = None
