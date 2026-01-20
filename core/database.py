# core/database.py
# DRAKBEN Database Manager - SQLite Session Persistence

import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class ScanResult:
    """Scan result record"""
    id: int = None
    session_id: int = None
    target: str = ""
    scan_type: str = ""
    tool: str = ""
    output: str = ""
    findings: str = ""  # JSON string
    created_at: str = ""


@dataclass
class Vulnerability:
    """Vulnerability record"""
    id: int = None
    session_id: int = None
    target: str = ""
    cve: str = ""
    severity: str = ""
    description: str = ""
    verified: bool = False
    exploited: bool = False
    created_at: str = ""


@dataclass
class Session:
    """Pentest session record"""
    id: int = None
    name: str = ""
    target: str = ""
    strategy: str = "balanced"
    status: str = "active"  # active, paused, completed
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""


class DatabaseManager:
    """
    SQLite database manager for DRAKBEN
    Handles session persistence, scan results, vulnerabilities
    """
    
    def __init__(self, db_path: str = "sessions/drakben.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Connect to database"""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
    
    def _create_tables(self):
        """Create database tables"""
        cursor = self.conn.cursor()
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                target TEXT,
                strategy TEXT DEFAULT 'balanced',
                status TEXT DEFAULT 'active',
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scan results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                target TEXT,
                scan_type TEXT,
                tool TEXT,
                output TEXT,
                findings TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        
        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                target TEXT,
                cve TEXT,
                severity TEXT,
                description TEXT,
                verified INTEGER DEFAULT 0,
                exploited INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        
        # Commands history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                command TEXT,
                output TEXT,
                success INTEGER,
                execution_time REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        
        # Notes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                title TEXT,
                content TEXT,
                tags TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        
        self.conn.commit()
    
    # ==================
    # Session Operations
    # ==================
    
    def create_session(self, name: str = None, target: str = None, strategy: str = "balanced") -> int:
        """Create a new pentest session"""
        cursor = self.conn.cursor()
        
        if not name:
            name = f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        cursor.execute("""
            INSERT INTO sessions (name, target, strategy, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (name, target, strategy, datetime.now().isoformat(), datetime.now().isoformat()))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_session(self, session_id: int) -> Optional[Session]:
        """Get session by ID"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        row = cursor.fetchone()
        
        if row:
            return Session(**dict(row))
        return None
    
    def get_active_session(self) -> Optional[Session]:
        """Get most recent active session"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM sessions 
            WHERE status = 'active' 
            ORDER BY updated_at DESC 
            LIMIT 1
        """)
        row = cursor.fetchone()
        
        if row:
            return Session(**dict(row))
        return None
    
    def get_all_sessions(self, limit: int = 50) -> List[Session]:
        """Get all sessions"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM sessions 
            ORDER BY created_at DESC 
            LIMIT ?
        """, (limit,))
        
        return [Session(**dict(row)) for row in cursor.fetchall()]
    
    def update_session(self, session_id: int, **kwargs):
        """Update session fields"""
        allowed_fields = ["name", "target", "strategy", "status", "notes"]
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return
        
        updates["updated_at"] = datetime.now().isoformat()
        
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [session_id]
        
        cursor = self.conn.cursor()
        cursor.execute(f"UPDATE sessions SET {set_clause} WHERE id = ?", values)
        self.conn.commit()
    
    def close_session(self, session_id: int):
        """Mark session as completed"""
        self.update_session(session_id, status="completed")
    
    # ==================
    # Scan Results
    # ==================
    
    def add_scan_result(self, session_id: int, target: str, scan_type: str, 
                        tool: str, output: str, findings: Dict = None) -> int:
        """Add scan result"""
        cursor = self.conn.cursor()
        
        findings_json = json.dumps(findings) if findings else "{}"
        
        cursor.execute("""
            INSERT INTO scan_results (session_id, target, scan_type, tool, output, findings)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session_id, target, scan_type, tool, output, findings_json))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_scan_results(self, session_id: int) -> List[ScanResult]:
        """Get scan results for session"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_results 
            WHERE session_id = ? 
            ORDER BY created_at DESC
        """, (session_id,))
        
        return [ScanResult(**dict(row)) for row in cursor.fetchall()]
    
    # ==================
    # Vulnerabilities
    # ==================
    
    def add_vulnerability(self, session_id: int, target: str, cve: str,
                         severity: str, description: str) -> int:
        """Add vulnerability"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO vulnerabilities (session_id, target, cve, severity, description)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, target, cve, severity, description))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_vulnerabilities(self, session_id: int) -> List[Vulnerability]:
        """Get vulnerabilities for session"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM vulnerabilities 
            WHERE session_id = ? 
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    WHEN 'low' THEN 4 
                    ELSE 5 
                END
        """, (session_id,))
        
        return [Vulnerability(**dict(row)) for row in cursor.fetchall()]
    
    def mark_vulnerability_verified(self, vuln_id: int):
        """Mark vulnerability as verified"""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE vulnerabilities SET verified = 1 WHERE id = ?", (vuln_id,))
        self.conn.commit()
    
    def mark_vulnerability_exploited(self, vuln_id: int):
        """Mark vulnerability as exploited"""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE vulnerabilities SET exploited = 1 WHERE id = ?", (vuln_id,))
        self.conn.commit()
    
    # ==================
    # Command History
    # ==================
    
    def add_command(self, session_id: int, command: str, output: str, 
                   success: bool, execution_time: float) -> int:
        """Add command to history"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO command_history (session_id, command, output, success, execution_time)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, command, output, int(success), execution_time))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_command_history(self, session_id: int, limit: int = 100) -> List[Dict]:
        """Get command history for session"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM command_history 
            WHERE session_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        """, (session_id, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================
    # Notes
    # ==================
    
    def add_note(self, session_id: int, title: str, content: str, tags: List[str] = None) -> int:
        """Add note to session"""
        cursor = self.conn.cursor()
        
        tags_str = ",".join(tags) if tags else ""
        
        cursor.execute("""
            INSERT INTO notes (session_id, title, content, tags)
            VALUES (?, ?, ?, ?)
        """, (session_id, title, content, tags_str))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_notes(self, session_id: int) -> List[Dict]:
        """Get notes for session"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM notes 
            WHERE session_id = ? 
            ORDER BY created_at DESC
        """, (session_id,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================
    # Reports
    # ==================
    
    def get_session_report(self, session_id: int) -> Dict:
        """Get complete session report"""
        session = self.get_session(session_id)
        if not session:
            return {}
        
        scans = self.get_scan_results(session_id)
        vulns = self.get_vulnerabilities(session_id)
        commands = self.get_command_history(session_id)
        notes = self.get_notes(session_id)
        
        return {
            "session": asdict(session),
            "scan_results": [asdict(s) for s in scans],
            "vulnerabilities": [asdict(v) for v in vulns],
            "command_count": len(commands),
            "notes": notes,
            "summary": {
                "total_scans": len(scans),
                "total_vulnerabilities": len(vulns),
                "critical_vulns": sum(1 for v in vulns if v.severity == "critical"),
                "high_vulns": sum(1 for v in vulns if v.severity == "high"),
                "verified_vulns": sum(1 for v in vulns if v.verified),
                "exploited_vulns": sum(1 for v in vulns if v.exploited)
            }
        }
    
    def export_session(self, session_id: int, filepath: str):
        """Export session to JSON file"""
        report = self.get_session_report(session_id)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    # ==================
    # Cleanup
    # ==================
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Global database instance
_db: Optional[DatabaseManager] = None


def get_database() -> DatabaseManager:
    """Get global database instance"""
    global _db
    if _db is None:
        _db = DatabaseManager()
    return _db
