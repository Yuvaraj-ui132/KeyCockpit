"""SQLite storage (standard library only): vehicles, keys, audit log, profiles."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta     (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS vehicles (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, owner_token_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS keys (
    key_id TEXT PRIMARY KEY, vehicle_id TEXT NOT NULL, holder TEXT NOT NULL,
    role TEXT NOT NULL, not_after INTEGER NOT NULL, revoked_at INTEGER,
    certificate TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, vehicle_id TEXT NOT NULL,
    key_id TEXT, holder TEXT, command TEXT, ok INTEGER NOT NULL, reason TEXT);
CREATE TABLE IF NOT EXISTS profiles (
    vehicle_id TEXT NOT NULL, holder TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (vehicle_id, holder));
"""


def hash_token(token: str) -> str:
    # Owner tokens are 256 random bits, so a plain fast hash is enough here.
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # -- meta (issuer key survives restarts when a file database is used) ----
    def get_meta(self, key: str) -> Optional[str]:
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row["v"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (key, value))
        self.db.commit()

    # -- vehicles ------------------------------------------------------------
    def add_vehicle(self, vehicle_id: str, name: str, token: str) -> None:
        self.db.execute(
            "INSERT INTO vehicles (id, name, owner_token_hash) VALUES (?, ?, ?)",
            (vehicle_id, name, hash_token(token)),
        )
        self.db.commit()

    def get_vehicle(self, vehicle_id: str):
        return self.db.execute("SELECT * FROM vehicles WHERE id=?", (vehicle_id,)).fetchone()

    def list_vehicles(self):
        return self.db.execute("SELECT * FROM vehicles").fetchall()

    def check_owner(self, vehicle_id: str, token: str) -> bool:
        row = self.get_vehicle(vehicle_id)
        if row is None or not token:
            return False
        return hmac.compare_digest(row["owner_token_hash"], hash_token(token))

    # -- keys ------------------------------------------------------------------
    def add_key(self, certificate: dict) -> None:
        p = certificate["payload"]
        self.db.execute(
            "INSERT INTO keys (key_id, vehicle_id, holder, role, not_after, certificate) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (p["key_id"], p["vehicle_id"], p["holder"], p["role"], p["not_after"],
             json.dumps(certificate)),
        )
        self.db.commit()

    def list_keys(self, vehicle_id: str):
        return self.db.execute(
            "SELECT key_id, holder, role, not_after, revoked_at FROM keys "
            "WHERE vehicle_id=? ORDER BY rowid", (vehicle_id,)
        ).fetchall()

    def get_key(self, vehicle_id: str, key_id: str):
        return self.db.execute(
            "SELECT * FROM keys WHERE vehicle_id=? AND key_id=?", (vehicle_id, key_id)
        ).fetchone()

    def revoke_key(self, vehicle_id: str, key_id: str, now: int) -> bool:
        """Mark revoked. False if the key is unknown or was already revoked."""
        cur = self.db.execute(
            "UPDATE keys SET revoked_at=? WHERE vehicle_id=? AND key_id=? AND revoked_at IS NULL",
            (now, vehicle_id, key_id),
        )
        self.db.commit()
        return cur.rowcount == 1

    def revoked_ids(self, vehicle_id: str) -> list[str]:
        rows = self.db.execute(
            "SELECT key_id FROM keys WHERE vehicle_id=? AND revoked_at IS NOT NULL", (vehicle_id,)
        ).fetchall()
        return [r["key_id"] for r in rows]

    # -- audit log -------------------------------------------------------------
    def log(self, vehicle_id: str, ok: bool, reason: Optional[str], command=None,
            key_id=None, holder=None, ts: Optional[float] = None) -> None:
        self.db.execute(
            "INSERT INTO audit (ts, vehicle_id, key_id, holder, command, ok, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts if ts is not None else time.time(), vehicle_id, key_id, holder,
             command if isinstance(command, str) else None, int(ok), reason),
        )
        self.db.commit()

    def recent_audit(self, vehicle_id: str, limit: int = 20) -> list[dict]:
        rows = self.db.execute(
            "SELECT ts, key_id, holder, command, ok, reason FROM audit "
            "WHERE vehicle_id=? ORDER BY id DESC LIMIT ?", (vehicle_id, limit)
        ).fetchall()
        return [dict(r) | {"ok": bool(r["ok"])} for r in rows]

    # -- driver profiles -------------------------------------------------------
    def set_profile(self, vehicle_id: str, holder: str, data: dict) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO profiles (vehicle_id, holder, data) VALUES (?, ?, ?)",
            (vehicle_id, holder, json.dumps(data)),
        )
        self.db.commit()

    def get_profile(self, vehicle_id: str, holder: str) -> Optional[dict]:
        row = self.db.execute(
            "SELECT data FROM profiles WHERE vehicle_id=? AND holder=?", (vehicle_id, holder)
        ).fetchone()
        return json.loads(row["data"]) if row else None
