import sqlite3
import os

DB_PATH = os.environ.get("DATABASE_PATH", "malware_vault.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_filename TEXT NOT NULL,
        vault_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        sha256 TEXT NOT NULL UNIQUE,
        md5 TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        file_format TEXT NOT NULL,
        description TEXT,
        analysis_notes TEXT,
        entropy REAL DEFAULT 0.0,
        entropy_level TEXT DEFAULT '',
        magic_type TEXT DEFAULT '',
        extracted_strings TEXT DEFAULT '',
        hex_dump TEXT DEFAULT '',
        yara_rule TEXT DEFAULT '',
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()
