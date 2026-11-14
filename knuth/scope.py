"""Target scope. Every outbound request from knuth passes through Scope.require().

An empty scope denies everything, so nothing leaves the machine until the
operator has explicitly declared what is authorised. Deny rules win over allow.
Patterns are fnmatch globs matched against `host` and `host:port`.
"""
from __future__ import annotations

import fnmatch
import json
import threading
from pathlib import Path
from urllib.parse import urlsplit


class OutOfScope(Exception):
    pass


class Scope:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()  # a host like knuth-web calls add/check from several threads
        self.allow: list[str] = []
        self.deny: list[str] = []
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.allow = list(data.get("allow", []))
            self.deny = list(data.get("deny", []))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"allow": self.allow, "deny": self.deny}, indent=2))

    def add(self, pattern: str, deny: bool = False) -> None:
        pattern = pattern.lower().strip()
        with self._lock:
            bucket = self.deny if deny else self.allow
            if pattern not in bucket:
                bucket.append(pattern)
            self.save()

    def remove(self, pattern: str) -> bool:
        pattern = pattern.lower().strip()
        with self._lock:
            hit = False
            for bucket in (self.allow, self.deny):
                if pattern in bucket:
                    bucket.remove(pattern)
                    hit = True
            self.save()
            return hit

    @staticmethod
    def _keys(url: str) -> list[str]:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            return []
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return [host, f"{host}:{port}"]

    def check(self, url: str) -> bool:
        keys = self._keys(url)
        if not keys:
            return False
        with self._lock:
            if any(fnmatch.fnmatchcase(k, p) for k in keys for p in self.deny):
                return False
            return any(fnmatch.fnmatchcase(k, p) for k in keys for p in self.allow)

    def require(self, url: str) -> None:
        if not self.check(url):
            raise OutOfScope(
                f"{url} is out of scope (allow={self.allow or 'empty'}, deny={self.deny or 'empty'}). "
                "Add it with: knuth scope add <host-pattern>"
            )