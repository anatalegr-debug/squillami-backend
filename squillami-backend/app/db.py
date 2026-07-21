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
    location_enabled INTEGER DEFAULT 1,    -- 1 = il telefono può essere geolocalizzato; 0 = solo squillo
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
    caller TEXT,                           -- chi ha avviato (numero IVR o web:IP)
    status TEXT DEFAULT 'pending',         -- pending | ringing | located | failed
    find_token TEXT,                       -- token effimero per leggere la posizione via web
    location_shared INTEGER DEFAULT 1,     -- snapshot: la posizione è condivisa per QUESTO evento
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

CREATE TABLE IF NOT EXISTS pow_used (
    seed TEXT PRIMARY KEY,                  -- sfida proof-of-work già consumata (uso singolo)
    created_at TEXT DEFAULT (datetime('now'))
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_column(conn, table: str, col: str, ddl: str) -> None:
    """Aggiunge una colonna se manca (migrazione leggera per DB già esistenti)."""
    existing = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    if col not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        # Migrazioni per database creati con versioni precedenti dello schema
        _ensure_column(conn, "users", "location_enabled", "location_enabled INTEGER DEFAULT 1")
        _ensure_column(conn, "events", "location_shared", "location_shared INTEGER DEFAULT 1")


@contextmanager
def get_db():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
