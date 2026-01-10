import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path("data/database.db")

def dict_factory(cursor, row):
    """Convierte filas SQLite a diccionarios y parsea JSON fields"""
    d = {}
    for idx, col in enumerate(cursor.description):
        value = row[idx]
        # Parse JSON fields
        if col[0] in ['sources', 'vt', 'st', 'whois'] and isinstance(value, str):
            try:
                value = json.loads(value)
            except:
                value = None
        d[col[0]] = value
    return d

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ioc_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc TEXT NOT NULL,
        ioc_type TEXT NOT NULL,
        score INTEGER NOT NULL CHECK(score >= 0 AND score <= 100),
        risk_level TEXT NOT NULL CHECK(risk_level IN ('low', 'medium', 'high', 'critical')),
        sources TEXT,
        vt TEXT,
        st TEXT,
        whois TEXT,
        first_seen_global TEXT,
        last_updated TEXT,
        burned_infra INTEGER DEFAULT 0,
        activity_phase TEXT DEFAULT 'unknown',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()
    print("DB initialized")

def save_query(ioc, ioc_type, score, risk_level, sources, vt_data, st_data, whois_data):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    created_at = datetime.utcnow().isoformat()
    
    cursor.execute("""
    INSERT INTO ioc_queries 
    (ioc, ioc_type, score, risk_level, sources, vt, st, whois, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ioc,
        ioc_type,
        score,
        risk_level,
        json.dumps(sources) if sources else None,
        json.dumps(vt_data) if vt_data else None,
        json.dumps(st_data) if st_data else None,
        json.dumps(whois_data) if whois_data else None,
        created_at
    ))
    
    conn.commit()
    conn.close()

def get_ioc_summary(ioc):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = dict_factory
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ioc_queries WHERE ioc = ? ORDER BY created_at DESC LIMIT 1", (ioc,))
    row = cursor.fetchone()
    conn.close()
    return row

def get_ioc_history(ioc):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = dict_factory
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ioc_queries WHERE ioc = ? ORDER BY created_at DESC", (ioc,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_ioc_timeline(ioc):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = dict_factory
    cursor = conn.cursor()
    cursor.execute("""
    SELECT 
        created_at as timestamp, 
        score, 
        risk_level, 
        activity_phase as phase, 
        burned_infra as burned
    FROM ioc_queries 
    WHERE ioc = ? 
    ORDER BY created_at ASC
    """, (ioc,))
    rows = cursor.fetchall()
    conn.close()
    return rows
