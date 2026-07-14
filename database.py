import sqlite3
from datetime import datetime

DB_NAME = "history.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk TEXT NOT NULL,
            score INTEGER NOT NULL,
            checked_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_scan(url, risk, score):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (url, risk, score, checked_at) VALUES (?, ?, ?, ?)",
        (url, risk, score, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def get_recent_scans(limit=10):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "SELECT url, risk, score, checked_at FROM scans ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return rows