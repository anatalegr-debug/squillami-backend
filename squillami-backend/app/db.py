"""Database SQLite: schema e connessione."""
import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.environ.get("DB_PATH", "squillami.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    phone_lookup TEXT UNIQUE NOT NULL,     -- HMAC del numero: IDENTIFICA l'utente (univoco)
    code_hash TEXT NOT NULL,               -- HMAC del codice: VERIFICA (libero, non univoco)
    api_token_hash TEXT NOT NULL,          -- hash del token usato dall'app
    failed_attempts INTEGER DEFAULT 0,
    locked_until TEXT,                     -- ISO datetime; account bloccato fino a
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    platform TEXT,                         -- android | ios
    push_token TEXT,
    model TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    caller TEXT,                           -- numero di chi ha chiamato l'IVR
    status TEXT DEFAULT 'pending',         -- pending | ringing | located | failed
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    event_id INTEGER REFERENCES events(id),
    lat REAL NOT NULL,
    lon REAL NOT NULL,
    accuracy_m REAL,
    battery INTEGER,
    kind TEXT DEFAULT 'fix',               -- fix | cached
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS call_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    caller TEXT,
    success INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


@contextmanager
def get_db():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
