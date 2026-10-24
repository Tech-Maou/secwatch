"""SQLite state database: schema, migrations and small helpers."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger(__name__)

MIGRATIONS: list[str] = [
    # 1: initial schema
    """
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE findings (
        key TEXT PRIMARY KEY,
        host TEXT NOT NULL,
        source TEXT NOT NULL,
        kind TEXT NOT NULL,
        vuln_id TEXT NOT NULL,
        package TEXT NOT NULL DEFAULT '',
        installed TEXT NOT NULL DEFAULT '',
        fixed_version TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT 'unknown',
        cvss REAL,
        title TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL DEFAULT '',
        component TEXT NOT NULL DEFAULT '',
        extra TEXT NOT NULL DEFAULT '{}',
        kev INTEGER NOT NULL DEFAULT 0,
        epss REAL,
        epss_pct REAL,
        state TEXT NOT NULL DEFAULT 'open',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        fixed_at TEXT,
        reason TEXT NOT NULL DEFAULT '',
        until TEXT,
        state_changed_at TEXT,
        reopened INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX findings_host_state ON findings(host, state);
    CREATE INDEX findings_source ON findings(host, source, kind);
    CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        trigger TEXT NOT NULL DEFAULT 'timer',
        status TEXT NOT NULL DEFAULT 'running',
        summary TEXT NOT NULL DEFAULT '{}',
        collectors TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE scan_items (scan_id INTEGER NOT NULL, key TEXT NOT NULL, PRIMARY KEY (scan_id, key));
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        scan_id INTEGER,
        host TEXT NOT NULL,
        key TEXT NOT NULL,
        type TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX events_ts ON events(ts);
    CREATE INDEX events_key ON events(key);
    CREATE TABLE history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        scan_id INTEGER,
        host TEXT NOT NULL,
        counts TEXT NOT NULL
    );
    CREATE INDEX history_ts ON history(ts);
    CREATE TABLE notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        event TEXT NOT NULL,
        key TEXT NOT NULL,
        channel TEXT NOT NULL,
        ok INTEGER NOT NULL,
        info TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX notifications_lookup ON notifications(event, key, channel, ts);
    CREATE TABLE reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        period TEXT NOT NULL,
        created_at TEXT NOT NULL,
        json_path TEXT NOT NULL,
        html_path TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '{}',
        UNIQUE (kind, period)
    );
    CREATE TABLE tools (
        host TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL DEFAULT '',
        db_age TEXT,
        info TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL,
        PRIMARY KEY (host, name)
    );
    CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY,
        csrf TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE TABLE auth_stats (
        day TEXT NOT NULL,
        host TEXT NOT NULL,
        source TEXT NOT NULL,
        ip TEXT NOT NULL DEFAULT '',
        count INTEGER NOT NULL,
        PRIMARY KEY (day, host, source, ip)
    );
    CREATE TABLE hosts (
        host TEXT PRIMARY KEY,
        role TEXT NOT NULL DEFAULT 'standalone',
        last_scan TEXT,
        last_contact TEXT,
        status TEXT NOT NULL DEFAULT 'unknown',
        info TEXT NOT NULL DEFAULT '{}'
    );
    """,
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return utcnow().replace(microsecond=0).isoformat()


def parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class DB:
    def __init__(self, path: Path | str, readonly: bool = False):
        self.path = Path(path)
        self.readonly = readonly
        self.lock = threading.RLock()  # the web app shares one connection between threads
        if not readonly:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        if readonly:
            self.conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=15,
                                        check_same_thread=False)
        else:
            self.conn = sqlite3.connect(str(self.path), timeout=15, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=15000")
        if not readonly:
            try:
                self.conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
            self.migrate()
            if new:
                try:
                    os.chmod(self.path, 0o660)  # shared between web (secwatch) and scan (root)
                except OSError:
                    pass

    def close(self) -> None:
        self.conn.close()

    def migrate(self) -> None:
        cur = self.conn.execute("PRAGMA user_version").fetchone()[0]
        for i, script in enumerate(MIGRATIONS[cur:], start=cur + 1):
            log.info("applying db migration %d", i)
            with self.conn:
                self.conn.executescript(script)
                self.conn.execute(f"PRAGMA user_version={i}")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self.lock, self.conn:
            yield self.conn

    def q(self, sql: str, args: tuple | list = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def one(self, sql: str, args: tuple | list = ()) -> sqlite3.Row | None:
        with self.lock:
            return self.conn.execute(sql, args).fetchone()

    def exec(self, sql: str, args: tuple | list = ()) -> sqlite3.Cursor:
        with self.lock, self.conn:
            return self.conn.execute(sql, args)

    # meta
    def get_meta(self, key: str, default: Any = None) -> Any:
        r = self.one("SELECT value FROM meta WHERE key=?", (key,))
        if r is None:
            return default
        try:
            return json.loads(r["value"])
        except (TypeError, ValueError):
            return r["value"]

    def set_meta(self, key: str, value: Any) -> None:
        self.exec("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, json.dumps(value)))


def row_to_finding_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    try:
        d["extra"] = json.loads(d.get("extra") or "{}")
    except ValueError:
        d["extra"] = {}
    d["id"] = d.pop("vuln_id")
    d["fixed"] = d.pop("fixed_version")
    d["kev"] = bool(d.get("kev"))
    return d


def open_db(path: Path, readonly: bool = False) -> DB | None:
    """Open the DB; in read-only mode return None when it does not exist yet."""
    if readonly and not Path(path).exists():
        return None
    try:
        return DB(path, readonly=readonly)
    except sqlite3.Error as e:
        log.error("cannot open db %s: %s", path, e)
        return None
