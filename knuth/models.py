from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str, default: str | None = None) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return default

    def to_raw(self) -> str:
        p = urlsplit(self.url)
        target = (p.path or "/") + (f"?{p.query}" if p.query else "")
        lines = [f"{self.method} {target} HTTP/1.1"]
        if self.header("host") is None:
            lines.append(f"Host: {p.netloc}")
        lines += [f"{k}: {v}" for k, v in self.headers]
        text = "\n".join(lines) + "\n\n"
        return text + self.body.decode("utf-8", "replace")


@dataclass
class HttpResponse:
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    elapsed: float = 0.0

    def header(self, name: str, default: str | None = None) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return default

    def headers_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def parse_raw(text: str, scheme: str = "https") -> HttpRequest:
    """Parse a Burp-style raw request. The URL is rebuilt from the Host header."""
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    method, target, *_ = lines[0].split(" ")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.append((k.strip(), v.strip()))
    host = next((v for k, v in headers if k.lower() == "host"), None)
    if target.startswith(("http://", "https://")):
        url = target
    elif host:
        url = f"{scheme}://{host}{target}"
    else:
        raise ValueError("raw request has no Host header and no absolute URL")
    return HttpRequest(method.upper(), url, headers, body.encode("utf-8"))
