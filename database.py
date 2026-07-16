"""SQLite persistence for scan history."""
import json
import sqlite3
from datetime import datetime

DB_NAME = "history.db"


def _connect():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with _connect() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, risk TEXT NOT NULL,
            score INTEGER NOT NULL, checked_at TEXT NOT NULL, confidence INTEGER NOT NULL DEFAULT 0,
            flags TEXT NOT NULL DEFAULT '[]', duration_ms INTEGER NOT NULL DEFAULT 0)""")
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        for name, definition in (("confidence", "INTEGER NOT NULL DEFAULT 0"),
                                 ("flags", "TEXT NOT NULL DEFAULT '[]'"),
                                 ("duration_ms", "INTEGER NOT NULL DEFAULT 0")):
            if name not in columns:
                connection.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")


def save_scan(result):
    with _connect() as connection:
        connection.execute("""INSERT INTO scans
            (url, risk, score, checked_at, confidence, flags, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (result["url"], result["risk"], result["score"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             result.get("confidence", 0), json.dumps(result.get("flags", [])), result.get("duration_ms", 0)))


def get_recent_scans(limit=100):
    with _connect() as connection:
        return [dict(row) for row in connection.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]


def delete_scan(scan_id):
    with _connect() as connection:
        return connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount > 0


def clear_history():
    with _connect() as connection:
        connection.execute("DELETE FROM scans")
