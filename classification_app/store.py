import hashlib
import hmac
import getpass
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def current_operator() -> str:
    domain = os.environ.get("USERDOMAIN")
    username = os.environ.get("USERNAME") or getpass.getuser()
    return f"{domain}\\{username}" if domain else username


class Store:
    def __init__(self, database: str | os.PathLike[str]):
        path = Path(database)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS file_hashes (
                    sha256 TEXT PRIMARY KEY,
                    level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 3)
                );
                CREATE TABLE IF NOT EXISTS path_rules (
                    pattern TEXT PRIMARY KEY,
                    level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 3)
                );
                CREATE TABLE IF NOT EXISTS network_rules (
                    cidr TEXT PRIMARY KEY,
                    action TEXT NOT NULL CHECK(action IN ('allow', 'deny'))
                );
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    event TEXT NOT NULL,
                    level INTEGER NOT NULL,
                    operator TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                );
                """
            )
            self._db.execute(
                "INSERT OR IGNORE INTO state(key, value) VALUES ('current_level', '0')"
            )

    @contextmanager
    def transaction(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def get_state(self, key: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None

    def set_state(self, key: str, value: str | None) -> None:
        with self.transaction() as db:
            if value is None:
                db.execute("DELETE FROM state WHERE key = ?", (key,))
            else:
                db.execute(
                    "INSERT INTO state(key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )

    def current_level(self) -> int:
        value = self.get_state("current_level")
        return int(value) if value is not None else 0

    def set_current_level(self, level: int) -> None:
        self.set_state("current_level", str(level))

    def file_level(self, sha256: str) -> int | None:
        with self._lock:
            row = self._db.execute(
                "SELECT level FROM file_hashes WHERE sha256 = ?", (sha256,)
            ).fetchone()
            return int(row["level"]) if row else None

    def path_levels(self) -> list[tuple[str, int]]:
        with self._lock:
            rows = self._db.execute("SELECT pattern, level FROM path_rules").fetchall()
            return [(row["pattern"], int(row["level"])) for row in rows]

    def network_rules(self) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._db.execute("SELECT cidr, action FROM network_rules").fetchall()
            return [(row["cidr"], row["action"]) for row in rows]

    def audit(self, event: str, level: int, operator: str, detail: object) -> None:
        detail_json = json.dumps(detail, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        with self.transaction() as db:
            row = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            previous = row["hash"] if row else "0" * 64
            material = json.dumps(
                [previous, timestamp, event, int(level), operator, detail_json],
                separators=(",", ":"),
                ensure_ascii=True,
            )
            digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
            db.execute(
                "INSERT INTO audit(ts, event, level, operator, detail, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (timestamp, event, int(level), operator, detail_json, previous, digest),
            )

    def verify_audit(self) -> tuple[bool, int]:
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, ts, event, level, operator, detail, prev_hash, hash "
                "FROM audit ORDER BY seq"
            ).fetchall()
        previous = "0" * 64
        for row in rows:
            if row["prev_hash"] != previous:
                return False, int(row["seq"])
            material = json.dumps(
                [
                    previous,
                    row["ts"],
                    row["event"],
                    int(row["level"]),
                    row["operator"],
                    row["detail"],
                ],
                separators=(",", ":"),
                ensure_ascii=True,
            )
            expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(expected, row["hash"]):
                return False, int(row["seq"])
            previous = row["hash"]
        return True, len(rows)

    def replace_rules(
        self,
        version: int,
        hashes: list[tuple[str, int]],
        paths: list[tuple[str, int]],
        networks: list[tuple[str, str]],
    ) -> None:
        with self.transaction() as db:
            db.execute("DELETE FROM file_hashes")
            db.execute("DELETE FROM path_rules")
            db.execute("DELETE FROM network_rules")
            db.executemany("INSERT INTO file_hashes(sha256, level) VALUES (?, ?)", hashes)
            db.executemany("INSERT INTO path_rules(pattern, level) VALUES (?, ?)", paths)
            db.executemany(
                "INSERT INTO network_rules(cidr, action) VALUES (?, ?)", networks
            )
            db.execute(
                "INSERT INTO state(key, value) VALUES ('rules_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(version),),
            )
