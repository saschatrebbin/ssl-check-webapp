import sqlite3
import json
from datetime import datetime

def dict_factory(cursor, row):
    """Konvertiert Datenbankzeilen in Dictionaries"""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

class Database:
    def __init__(self, db_path='ssl_checks.db'):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialisiert die Datenbankstruktur"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS ssl_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    batch_id TEXT,
                    timestamp TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    hostname_valid INTEGER NOT NULL,
                    chain_valid INTEGER NOT NULL,
                    days_left INTEGER,
                    result_json TEXT NOT NULL,
                    UNIQUE(domain, batch_id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS batch_jobs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    total_domains INTEGER NOT NULL,
                    completed_domains INTEGER DEFAULT 0,
                    status TEXT NOT NULL
                )
            ''')
    
    def get_connection(self):
        """Erstellt eine Datenbankverbindung mit Dictionary-Factory"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = dict_factory
        return conn