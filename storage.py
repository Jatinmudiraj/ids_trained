import sqlite3
import time
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "ids_history.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    domain TEXT,
                    stage TEXT,
                    confidence REAL,
                    src_ip TEXT,
                    raw_log TEXT
                )''')
    conn.commit()
    conn.close()

def log_incident(data):
    """
    Expects data dict from monitor callback:
    {timestamp, is_attack, stage, confidence, norm: {src_ip, domain, ...}, raw}
    """
    if not data.get('is_attack'):
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO incidents (timestamp, domain, stage, confidence, src_ip, raw_log)
                 VALUES (?, ?, ?, ?, ?, ?)''', (
                     data['timestamp'],
                     data['norm'].get('domain', 'unknown'),
                     data['stage'],
                     data['confidence'],
                     data['norm'].get('src_ip', 'unknown'),
                     data['raw']
                 ))
    conn.commit()
    conn.close()

def get_top_attackers(limit=5):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT src_ip, COUNT(*) as count 
                 FROM incidents 
                 GROUP BY src_ip 
                 ORDER BY count DESC 
                 LIMIT ?''', (limit,))
    res = c.fetchall()
    conn.close()
    return res

def get_recent_incidents(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?', (limit,))
    res = c.fetchall()
    conn.close()
    return res

# Initialize on import
init_db()
