"""
Database initialization and connection management for vuln-app-lab.
Uses an in-memory SQLite database initialized with mock user and note fixtures.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

_DB_CONNECTION: Optional[sqlite3.Connection] = None


def get_db() -> sqlite3.Connection:
    """Returns a shared in-memory SQLite database connection."""
    global _DB_CONNECTION
    if _DB_CONNECTION is None:
        _DB_CONNECTION = sqlite3.connect(":memory:", check_same_thread=False)
        _DB_CONNECTION.row_factory = sqlite3.Row
        init_db(_DB_CONNECTION)
    return _DB_CONNECTION


def init_db(conn: sqlite3.Connection) -> None:
    """Creates schema and seeds test fixtures."""
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            bio TEXT
        )
    """)

    # Notes table (for IDOR demonstration)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            is_private BOOLEAN NOT NULL DEFAULT 1,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    # Seed users (Alice, Bob, Admin)
    cursor.executemany("""
        INSERT INTO users (username, email, role, bio) VALUES (?, ?, ?, ?)
    """, [
        ("admin", "admin@internal.corp", "admin", "System Administrator"),
        ("alice", "alice@example.com", "user", "Software Developer"),
        ("bob", "bob@example.com", "user", "Security Enthusiast"),
    ])

    # Seed notes
    cursor.executemany("""
        INSERT INTO notes (owner_id, title, content, is_private) VALUES (?, ?, ?, ?)
    """, [
        (2, "Alice's Grocery List", "Apples, Milk, Whole Grain Bread", 0),
        (2, "Alice's Confidential Medical Note", "Diagnosis: Migraine with aura; Prescribed Sumatriptan", 1),
        (3, "Bob's Financial Credentials", "Cryptocurrency wallet recovery seed phrase: [DEMO-MNEMONIC-DO-NOT-USE]", 1),
        (1, "Infrastructure Master Key", "Internal AWS IAM Backup Role ARN: arn:aws:iam::123456789012:role/admin-breakglass", 1),
    ])

    conn.commit()


def reset_db() -> None:
    """Resets database state (used in test teardown)."""
    global _DB_CONNECTION
    if _DB_CONNECTION is not None:
        _DB_CONNECTION.close()
        _DB_CONNECTION = None
