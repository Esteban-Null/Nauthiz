import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path("data/database.db")

def init_db():
    """Initialize database with tables"""
    DB_PATH.parent.mkdir(exist_ok=True, mode=0o700)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ioc_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
            risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
            sources TEXT,
            vt TEXT,
            st TEXT,
            whois TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            first_seen_global TEXT,
            last_updated TEXT,
            burned_infra INTEGER DEFAULT 0,
            activity_phase TEXT DEFAULT 'unknown'
        )
    """)
    
    conn.commit()
    conn.close()
    DB_PATH.chmod(0o600)

def save_query(ioc: str, ioc_type: str, score: int, risk_level: str, sources: list, vt: dict, st: dict, whois: dict):
    """Save query to database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO ioc_queries (ioc, ioc_type, score, risk_level, sources, vt, st, whois, first_seen_global, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ioc, ioc_type, score, risk_level,
        json.dumps(sources), json.dumps(vt or {}), json.dumps(st or {}), json.dumps(whois or {}),
        datetime.utcnow().isoformat(), datetime.utcnow().isoformat()
    ))
    
    conn.commit()
    conn.close()

def get_ioc_summary(ioc: str) -> dict:
    """Get latest summary for IOC"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT ioc, ioc_type, score, risk_level, sources, vt, st, whois, created_at
        FROM ioc_queries WHERE ioc = ? ORDER BY created_at DESC LIMIT 1
    """, (ioc,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return {
        "ioc": row[0], "ioc_type": row[1], "score": row[2], "risk_level": row[3],
        "sources": json.loads(row[4]), "vt": json.loads(row[5]), "st": json.loads(row[6]),
        "whois": json.loads(row[7]), "created_at": row[8]
    }

def get_ioc_history(ioc: str) -> list:
    """Get query history for IOC"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT ioc, ioc_type, score, risk_level, sources, created_at
        FROM ioc_queries WHERE ioc = ? ORDER BY created_at DESC LIMIT 50
    """, (ioc,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {"ioc": row[0], "ioc_type": row[1], "score": row[2], "risk_level": row[3],
         "sources": json.loads(row[4]), "created_at": row[5]}
        for row in rows
    ]

def get_ioc_timeline(ioc: str) -> list:
    """Get timeline (with phases) for IOC"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT created_at, score, risk_level, activity_phase, burned_infra
        FROM ioc_queries WHERE ioc = ? ORDER BY created_at DESC LIMIT 100
    """, (ioc,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {"timestamp": row[0], "score": row[1], "risk_level": row[2],
         "phase": row[3], "burned": bool(row[4])}
        for row in rows
    ]
