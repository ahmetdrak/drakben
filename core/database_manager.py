#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# core/database_manager.py
# DRAKBEN Database Manager - SQLite Integration

import sqlite3
import json
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging
from pathlib import Path
import threading

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    SQLite database manager for DRAKBEN
    Solves: No Database Backend Issue
    """
    
    def __init__(self, db_path: str = "drakben.db"):
        self.db_path = Path(db_path)
        self.connection = None
        self._lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize database and create tables"""
        with self._lock:
            self.connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            cursor = self.connection.cursor()

            # Pentest sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    strategy TEXT DEFAULT 'balanced',
                    status TEXT DEFAULT 'active',
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    notes TEXT
                )
            """)

            # Vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    vuln_type TEXT,
                    severity TEXT,
                    cve_id TEXT,
                    description TEXT,
                    proof_of_concept TEXT,
                    discovered_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                )
            """)

            # Executed commands table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    command TEXT NOT NULL,
                    status TEXT,
                    stdout TEXT,
                    stderr TEXT,
                    return_code INTEGER,
                    execution_time REAL,
                    executed_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                )
            """)

            # Exploit results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    exploit_name TEXT,
                    target TEXT,
                    payload TEXT,
                    result TEXT,
                    success BOOLEAN,
                    executed_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                )
            """)

            # Payloads table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_type TEXT,
                    language TEXT,
                    obfuscation TEXT,
                    payload_content TEXT,
                    hash TEXT UNIQUE,
                    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            self.connection.commit()
        logger.info(f"Database initialized at {self.db_path}")
    
    def create_session(self, target: str, strategy: str = "balanced", 
                      notes: str = "") -> int:
        """Create new pentest session"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO sessions (target, strategy, notes)
                VALUES (?, ?, ?)
            """, (target, strategy, notes))
            self.connection.commit()
            session_id = cursor.lastrowid
        logger.info(f"Created session {session_id} for target {target}")
        return session_id
    
    def log_command(self, session_id: int, command: str, 
                   status: str, stdout: str = "", 
                   stderr: str = "", return_code: int = 0,
                   execution_time: float = 0.0) -> int:
        """Log executed command"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO commands (session_id, command, status, stdout, stderr, 
                                    return_code, execution_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (session_id, command, status, stdout, stderr, return_code, execution_time))
            self.connection.commit()
            return cursor.lastrowid
    
    def log_vulnerability(self, session_id: int, vuln_type: str,
                         severity: str, cve_id: str = "",
                         description: str = "",
                         proof_of_concept: str = "") -> int:
        """Log discovered vulnerability"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO vulnerabilities (session_id, vuln_type, severity, cve_id,
                                            description, proof_of_concept)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, vuln_type, severity, cve_id, description, proof_of_concept))
            self.connection.commit()
        logger.info(f"Logged {vuln_type} vulnerability ({severity}) for session {session_id}")
        return cursor.lastrowid

    def add_vulnerability(self, session_id: int, target: str = "", cve: str = "",
                          severity: str = "", description: str = "",
                          vuln_type: str = "CVE") -> int:
        """Backwards-compatible wrapper for log_vulnerability."""
        return self.log_vulnerability(
            session_id=session_id,
            vuln_type=vuln_type,
            severity=severity,
            cve_id=cve,
            description=description,
            proof_of_concept=""
        )
    
    def log_exploit(self, session_id: int, exploit_name: str,
                   target: str, payload: str, result: str,
                   success: bool) -> int:
        """Log exploit execution"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                INSERT INTO exploits (session_id, exploit_name, target, payload, result, success)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, exploit_name, target, payload, result, success))
            self.connection.commit()
        logger.info(f"Logged exploit {exploit_name} - Success: {success}")
        return cursor.lastrowid
    
    def save_payload(self, payload_type: str, language: str,
                    obfuscation: str, payload_content: str,
                    payload_hash: str) -> int:
        """Save payload to database"""
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("""
                    INSERT INTO payloads (payload_type, language, obfuscation, 
                                        payload_content, hash)
                    VALUES (?, ?, ?, ?, ?)
                """, (payload_type, language, obfuscation, payload_content, payload_hash))
                self.connection.commit()
                logger.info(f"Saved payload: {payload_type}/{language}")
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                logger.warning(f"Payload with hash {payload_hash} already exists")
                return -1
    
    def get_session_summary(self, session_id: int) -> Dict:
        """Get session summary"""
        with self._lock:
            cursor = self.connection.cursor()

            # Session info
            cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            session = dict(cursor.fetchone())

            # Vulnerabilities count
            cursor.execute("""
                SELECT severity, COUNT(*) as count FROM vulnerabilities 
                WHERE session_id = ? GROUP BY severity
            """, (session_id,))
            vulns = {row[0]: row[1] for row in cursor.fetchall()}

            # Commands count
            cursor.execute("""
                SELECT status, COUNT(*) as count FROM commands 
                WHERE session_id = ? GROUP BY status
            """, (session_id,))
            commands = {row[0]: row[1] for row in cursor.fetchall()}

            # Exploits success rate
            cursor.execute("""
                SELECT COUNT(*) as total, SUM(CASE WHEN success THEN 1 ELSE 0 END) as successes
                FROM exploits WHERE session_id = ?
            """, (session_id,))
            exploits = dict(cursor.fetchone())
        
        return {
            "session": session,
            "vulnerabilities": vulns,
            "commands": commands,
            "exploits": exploits
        }

    def get_all_sessions(self) -> List[Dict]:
        """Get all sessions"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM sessions ORDER BY start_time DESC")
            return [dict(row) for row in cursor.fetchall()]
    
    def get_all_vulnerabilities(self, session_id: int) -> List[Dict]:
        """Get all vulnerabilities from session"""
        with self._lock:
            cursor = self.connection.cursor()
            cursor.execute("""
                SELECT * FROM vulnerabilities WHERE session_id = ?
                ORDER BY discovered_time DESC
            """, (session_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def export_session_report(self, session_id: int, 
                             output_format: str = "json") -> str:
        """Export session report"""
        summary = self.get_session_summary(session_id)
        vulns = self.get_all_vulnerabilities(session_id)
        
        if output_format == "json":
            return json.dumps({
                "summary": summary,
                "vulnerabilities": vulns
            }, indent=2, default=str)
        else:
            # Markdown format
            report = f"# DRAKBEN Session Report\n\n"
            report += f"**Target:** {summary['session']['target']}\n"
            report += f"**Strategy:** {summary['session']['strategy']}\n"
            report += f"**Status:** {summary['session']['status']}\n\n"
            report += f"## Vulnerabilities Found\n"
            for vuln_type, count in summary['vulnerabilities'].items():
                report += f"- {vuln_type}: {count}\n"
            return report
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Example Usage
if __name__ == "__main__":
    with DatabaseManager("test_drakben.db") as db:
        # Create session
        session_id = db.create_session(
            target="192.168.1.100",
            strategy="balanced",
            notes="Test penetration testing"
        )
        
        # Log command
        db.log_command(
            session_id=session_id,
            command="nmap -sS 192.168.1.100",
            status="success",
            stdout="Port 80 open\nPort 443 open\n",
            execution_time=5.2
        )
        
        # Log vulnerability
        db.log_vulnerability(
            session_id=session_id,
            vuln_type="SQLi",
            severity="high",
            cve_id="CVE-2021-12345",
            description="SQL injection in login form"
        )
        
        # Get summary
        summary = db.get_session_summary(session_id)
        print(json.dumps(summary, indent=2, default=str))
