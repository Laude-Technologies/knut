"""SQLite flow history shared by the proxy, repeater, fuzzer and scanner."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .models import HttpRequest, HttpResponse

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  source TEXT NOT NULL,
  method TEXT NOT NULL,
  url TEXT NOT NULL,
  req_headers TEXT NOT NULL,
  req_body BLOB,
  status INTEGER,
  resp_headers TEXT,
  resp_body BLOB,
  elapsed REAL
);
"""


class Store:
    """Thread-safe: the CLI only ever touches this from one thread, but a host
    like knuth-web calls it from FastAPI's worker threads and the asyncio event
    loop thread interchangeably, and a bare sqlite3.Connection isn't safe to
    share across threads even with check_same_thread=False - that flag only
    lifts sqlite's own same-thread check, it doesn't serialize access. The lock
    here does the serializing.
    """

    def __init__(self, home: Path):
        home = Path(home)
        home.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(home / "history.db", check_same_thread=False)
        with self._lock:
            self.db.executescript(SCHEMA)

    def add(self, req: HttpRequest, resp: HttpResponse | None, source: str) -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO flows (ts, source, method, url, req_headers, req_body, status,"
                " resp_headers, resp_body, elapsed) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    time.time(), source, req.method, req.url, json.dumps(req.headers), req.body,
                    resp.status if resp else None,
                    json.dumps(resp.headers) if resp else None,
                    resp.body if resp else None,
                    resp.elapsed if resp else None,
                ),
            )
            self.db.commit()
            return int(cur.lastrowid)

    def get(self, flow_id: int) -> tuple[HttpRequest, HttpResponse | None]:
        with self._lock:
            row = self.db.execute(
                "SELECT method,url,req_headers,req_body,status,resp_headers,resp_body,elapsed"
                " FROM flows WHERE id=?", (flow_id,)
            ).fetchone()
        if not row:
            raise KeyError(f"no flow with id {flow_id}")
        method, url, rh, rb, status, sh, sb, el = row
        req = HttpRequest(method, url, [tuple(x) for x in json.loads(rh)], rb or b"")
        resp = None
        if status is not None:
            resp = HttpResponse(status, [tuple(x) for x in json.loads(sh)], sb or b"", el or 0.0)
        return req, resp

    def list(self, limit: int = 50, host: str | None = None, grep: str | None = None):
        q = "SELECT id,ts,source,method,url,status,length(resp_body),elapsed FROM flows"
        where, args = [], []
        if host:
            where.append("url LIKE ?")
            args.append(f"%{host}%")
        if grep:
            where.append("(url LIKE ? OR CAST(resp_body AS TEXT) LIKE ?)")
            args += [f"%{grep}%", f"%{grep}%"]
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            return list(reversed(self.db.execute(q, args).fetchall()))
