"""Incremental, disposable catalog metadata shared by workspace readers.

Files remain authoritative. Every refresh checks fingerprints; only changed
files are read, and only changed content is parsed. Cache failures fall back to
the live files. No file I/O or parsing occurs under a SQLite write transaction.
"""

import hashlib
import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

log = logging.getLogger(__name__)
Parser = Callable[[Path, str], Dict[str, Any]]
Tokens = Callable[[Dict[str, Any]], Iterable[Tuple[str, str]]]


def file_fingerprint(path: Path) -> Tuple[int, ...]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _encode(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return {"__hecate_catalog_date__": type(value).__name__, "value": value.isoformat()}
    raise TypeError(f"Unsupported catalog value: {type(value).__name__}")


def _decode(value: Dict[str, Any]) -> Any:
    if set(value) == {"__hecate_catalog_date__", "value"}:
        if value["__hecate_catalog_date__"] == "datetime":
            return datetime.fromisoformat(value["value"])
        if value["__hecate_catalog_date__"] == "date":
            return date.fromisoformat(value["value"])
    return value


@dataclass
class CatalogEntry:
    path: Path
    mtime_ns: int
    data: Dict[str, Any]


class CatalogIndex:
    """Use a versioned ``kind`` when parser output or token semantics change."""

    def __init__(self, root: Path, kind: str) -> None:
        self.root = root.resolve()
        self.namespace = f"{self.root}:{kind}"
        self.database = self.root.parent / ".hecate/catalog.sqlite3"
        self._rows: Dict[str, Tuple[str, str, int, Optional[str]]] = {}
        self._persistent = False
        self._uncached: Dict[str, Dict[str, Any]] = {}

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.database, timeout=0.2)
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS documents (
                namespace TEXT NOT NULL, path TEXT NOT NULL, signature TEXT NOT NULL,
                digest TEXT NOT NULL, mtime_ns INTEGER NOT NULL, payload TEXT,
                PRIMARY KEY(namespace,path))""")
            conn.execute("""CREATE TABLE IF NOT EXISTS lookups (
                namespace TEXT NOT NULL, kind TEXT NOT NULL, token TEXT NOT NULL, path TEXT NOT NULL,
                PRIMARY KEY(namespace,kind,token,path))""")
            return conn
        except BaseException:
            conn.close()
            raise

    def refresh(
        self,
        paths: Iterable[Path],
        parser: Parser,
        *,
        tokens: Optional[Tokens] = None,
        prune: bool = True,
    ) -> None:
        paths = sorted({path.absolute() for path in paths})
        self._uncached = {}
        conn = None
        try:
            conn = self._connect()
            if not prune and len(paths) == 1:
                rows = conn.execute(
                    "SELECT path,signature,digest,mtime_ns,payload FROM documents WHERE namespace=? AND path=?",
                    (self.namespace, str(paths[0])),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT path,signature,digest,mtime_ns,payload FROM documents WHERE namespace=?",
                    (self.namespace,),
                ).fetchall()
            self._rows = {row[0]: (row[1], row[2], row[3], row[4]) for row in rows}
            for key, row in list(self._rows.items()):
                if row[3] is not None:
                    try:
                        if not isinstance(json.loads(row[3], object_hook=_decode), dict):
                            raise ValueError("Invalid catalog payload")
                    except (ValueError, TypeError):
                        self._rows[key] = ("", "", row[2], None)
            self._persistent = True
        except (OSError, sqlite3.Error):
            if conn is not None:
                conn.close()
            conn = None
            self._rows = {}
            self._persistent = False

        live = set()
        changed = []
        for path in paths:
            key = str(path)
            try:
                signature = file_fingerprint(path)
            except OSError:
                continue
            live.add(key)
            old = self._rows.get(key)
            encoded_signature = json.dumps(signature)
            if old and old[0] == encoded_signature:
                continue
            payload = None
            digest = ""
            try:
                for _ in range(2):
                    content = path.read_text(encoding="utf-8")
                    after = file_fingerprint(path)
                    if signature == after:
                        break
                    signature = after
                else:
                    raise OSError("File changed during catalog refresh")
                encoded_signature = json.dumps(signature)
                digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
                if old and old[1] == digest and old[3] is not None:
                    payload = old[3]
                else:
                    parsed = parser(path, content)
                    try:
                        payload = json.dumps(parsed, default=_encode)
                    except (TypeError, ValueError):
                        self._uncached[key] = parsed
                        encoded_signature = ""
            except Exception as exc:
                # A malformed or unreadable document must not retain old data.
                log.debug("Could not index %s (%s)", path, type(exc).__name__)
                encoded_signature = ""  # Retry transient failures on the next refresh.
            row = (encoded_signature, digest, signature[3], payload)
            self._rows[key] = row
            changed.append((key, row))

        removed = set(self._rows) - live if prune else {str(path) for path in paths} - live
        for key in removed:
            self._rows.pop(key, None)
        if conn is None:
            return
        lookup_updates = {
            key: list(tokens(json.loads(row[3], object_hook=_decode))) for key, row in changed if tokens and row[3] is not None
        }
        try:
            with conn:
                for key in removed:
                    conn.execute("DELETE FROM lookups WHERE namespace=? AND path=?", (self.namespace, key))
                    conn.execute("DELETE FROM documents WHERE namespace=? AND path=?", (self.namespace, key))
                for key, row in changed:
                    conn.execute("INSERT OR REPLACE INTO documents VALUES(?,?,?,?,?,?)", (self.namespace, key, *row))
                    conn.execute("DELETE FROM lookups WHERE namespace=? AND path=?", (self.namespace, key))
                    if key in lookup_updates:
                        conn.executemany(
                            "INSERT OR IGNORE INTO lookups VALUES(?,?,?,?)",
                            ((self.namespace, kind, token, key) for kind, token in lookup_updates[key]),
                        )
        except (OSError, sqlite3.Error):
            self._persistent = False  # Fresh in-memory rows are still usable.
        finally:
            conn.close()

    def entries(self) -> List[CatalogEntry]:
        return [
            CatalogEntry(
                Path(path), row[2], json.loads(row[3], object_hook=_decode) if row[3] is not None else self._uncached[path]
            )
            for path, row in sorted(self._rows.items())
            if row[3] is not None or path in self._uncached
        ]

    def prune(self, paths: Iterable[Path]) -> None:
        """Remove stale selectively cached documents without rereading live ones."""
        live = {str(path.absolute()) for path in paths}
        conn = None
        try:
            conn = self._connect()
            removed = [
                row[0]
                for row in conn.execute("SELECT path FROM documents WHERE namespace=?", (self.namespace,))
                if row[0] not in live
            ]
            with conn:
                conn.executemany(
                    "DELETE FROM documents WHERE namespace=? AND path=?", ((self.namespace, path) for path in removed)
                )
                conn.executemany(
                    "DELETE FROM lookups WHERE namespace=? AND path=?", ((self.namespace, path) for path in removed)
                )
        except (OSError, sqlite3.Error):
            pass
        finally:
            if conn is not None:
                conn.close()

    def lookup(self, kind: str, token: str, *, since_ns: int = 0) -> List[Path]:
        if self._persistent and not self._uncached:
            conn = None
            try:
                conn = self._connect()
                rows = conn.execute(
                    """SELECT d.path FROM lookups l JOIN documents d
                    ON d.namespace=l.namespace AND d.path=l.path
                    WHERE l.namespace=? AND l.kind=? AND l.token=? AND d.mtime_ns>=?""",
                    (self.namespace, kind, token, since_ns),
                ).fetchall()
                return [Path(row[0]) for row in rows]
            except (OSError, sqlite3.Error):
                pass
            finally:
                if conn is not None:
                    conn.close()
        return [entry.path for entry in self.entries() if entry.mtime_ns >= since_ns and token in entry.data.get(kind, [])]
