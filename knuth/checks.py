"""Crawler plus passive and light-touch active checks.

Active checks are detection probes only (a canary, a stray quote, an Origin header,
a redirect target on a reserved .invalid domain). Nothing here exploits or alters
server state beyond issuing the request being tested, so POST forms are only
probed when --active-post is given.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .client import SendError, Session
from .models import HttpRequest, HttpResponse

ERROR_SIGNATURES = [
    ("mysql", re.compile(r"You have an error in your SQL syntax|mysql_fetch|MySqlException|check the manual that corresponds to your (MySQL|MariaDB)", re.I)),
    ("postgres", re.compile(r"PG::SyntaxError|unterminated quoted string at or near|pg_query\(\)|PSQLException", re.I)),
    ("mssql", re.compile(r"Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|SqlException", re.I)),
    ("oracle", re.compile(r"ORA-\d{5}|quoted string not properly terminated", re.I)),
    ("sqlite", re.compile(r"SQLite3?::|sqlite3\.OperationalError|unrecognized token:|SQLITE_ERROR", re.I)),
    ("traceback", re.compile(r"Traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)|Fatal error: .* on line \d+|Stack trace:", re.I)),
]

REDIRECT_PARAMS = re.compile(r"^(url|redirect|redirect_uri|redirect_url|next|return|return_to|returnurl|dest|destination|continue|goto|target|link)$", re.I)
SENSITIVE_PATHS = [
    ("/.git/HEAD", re.compile(r"^ref: refs/")),
    ("/.env", re.compile(r"^[A-Z][A-Z0-9_]+=", re.M)),
    ("/.DS_Store", re.compile(r"Bud1")),
    ("/server-status", re.compile(r"Apache Server Status")),
    ("/phpinfo.php", re.compile(r"phpinfo\(\)|PHP Version")),
]


@dataclass
class Finding:
    check: str
    severity: str  # info | low | medium | high
    title: str
    url: str
    detail: str = ""
    param: str = ""

    def key(self) -> tuple:
        return (self.check, self.url.split("?")[0], self.param)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Endpoint:
    method: str
    url: str  # query string included for GET
    params: list[str] = field(default_factory=list)
    kind: str = "query"  # query | form


class _Links(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.links: list[str] = []
        self.forms: list[Endpoint] = []
        self._form: Endpoint | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(urljoin(self.base, a["href"]))
        elif tag == "form":
            self._form = Endpoint((a.get("method") or "GET").upper(),
                                  urljoin(self.base, a.get("action") or self.base), [], "form")
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form.params.append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


async def crawl(session: Session, starts: list[str], depth: int = 2, max_pages: int = 100):
    """Same-host BFS. Returns (pages: {url: HttpResponse}, endpoints)."""
    seen: set[str] = set()
    pages: dict[str, HttpResponse] = {}
    endpoints: dict[tuple, Endpoint] = {}
    for u in starts:
        session.scope.require(u)  # fail loudly rather than reporting a clean scan of nothing
    hosts = {urlsplit(u).netloc for u in starts}
    frontier = [(u, 0) for u in starts]
    while frontier and len(pages) < max_pages:
        url, d = frontier.pop(0)
        norm = urlunsplit(urlsplit(url)._replace(fragment=""))
        if norm in seen:
            continue
        seen.add(norm)
        try:
            r = await session.send(HttpRequest("GET", norm))
        except SendError:
            continue
        pages[norm] = r
        q = [k for k, _ in parse_qsl(urlsplit(norm).query, keep_blank_values=True)]
        if q:
            endpoints[("GET", norm.split("?")[0], tuple(sorted(q)))] = Endpoint("GET", norm, q, "query")
        ctype = (r.header("content-type") or "").lower()
        if "html" not in ctype or d >= depth:
            continue
        p = _Links(norm)
        try:
            p.feed(r.text)
        except Exception:
            continue
        for f in p.forms:
            if f.params and urlsplit(f.url).netloc in hosts:
                endpoints[(f.method, f.url.split("?")[0], tuple(sorted(f.params)))] = f
        for link in p.links:
            if urlsplit(link).scheme in ("http", "https") and urlsplit(link).netloc in hosts \
                    and session.scope.check(link):
                frontier.append((link, d + 1))
    return pages, list(endpoints.values())


# ---------------------------------------------------------------- passive

def passive(url: str, r: HttpResponse) -> list[Finding]:
    out: list[Finding] = []
    https = url.startswith("https://")
    ctype = (r.header("content-type") or "").lower()
    is_html = "html" in ctype

    def add(check, sev, title, detail=""):
        out.append(Finding(check, sev, title, url, detail))

    if is_html:
        csp = r.header("content-security-policy")
        if not csp:
            add("missing-csp", "low", "No Content-Security-Policy header")
        if not r.header("x-frame-options") and not (csp and "frame-ancestors" in csp):
            add("clickjacking", "low", "No clickjacking protection (X-Frame-Options / frame-ancestors)")
        if not r.header("referrer-policy"):
            add("missing-referrer-policy", "info", "No Referrer-Policy header")
    if (r.header("x-content-type-options") or "").lower() != "nosniff":
        add("missing-nosniff", "low", "X-Content-Type-Options: nosniff not set")
    if https and not r.header("strict-transport-security"):
        add("missing-hsts", "medium", "No Strict-Transport-Security header on HTTPS response")
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        v = r.header(name)
        if v and re.search(r"\d", v):
            add("version-disclosure", "info", f"{name} header discloses version", f"{name}: {v}")
    for c in r.headers_all("set-cookie"):
        cname = c.split("=", 1)[0].strip()
        low = c.lower()
        flags = []
        if "httponly" not in low:
            flags.append("HttpOnly")
        if https and "secure" not in low:
            flags.append("Secure")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            sev = "medium" if re.search(r"sess|auth|token|jwt|sid", cname, re.I) and flags[0] != "SameSite" else "low"
            add("cookie-flags", sev, f"Cookie '{cname}' missing {', '.join(flags)}", c)
    if is_html or "text" in ctype or "json" in ctype:
        for name, rx in ERROR_SIGNATURES:
            m = rx.search(r.text)
            if m:
                add("error-disclosure", "medium", f"Verbose error / stack trace ({name})", m.group(0)[:120])
                break
        if re.search(r"<title>\s*Index of /", r.text, re.I):
            add("directory-listing", "medium", "Directory listing enabled")
    acao, acac = r.header("access-control-allow-origin"), (r.header("access-control-allow-credentials") or "").lower()
    if acao == "*" and acac == "true":
        add("cors-wildcard-credentials", "high", "CORS: wildcard origin with credentials")
    return out


# ----------------------------------------------------------------- active

def _with_param(url: str, name: str, value: str) -> str:
    p = urlsplit(url)
    q = [(k, value if k == name else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunsplit(p._replace(query=urlencode(q)))


async def _probe(session: Session, ep: Endpoint, name: str, value: str) -> HttpResponse | None:
    try:
        if ep.method == "GET":
            base = ep.url
            if name not in [k for k, _ in parse_qsl(urlsplit(base).query, keep_blank_values=True)]:
                p = urlsplit(base)
                base = urlunsplit(p._replace(query=urlencode(parse_qsl(p.query, keep_blank_values=True) + [(name, "1")])))
            return await session.send(HttpRequest("GET", _with_param(base, name, value)))
        body = urlencode([(k, value if k == name else "1") for k in ep.params]).encode()
        return await session.send(HttpRequest(
            ep.method, ep.url, [("Content-Type", "application/x-www-form-urlencoded")], body))
    except SendError:
        return None


async def active(session: Session, endpoints: list[Endpoint], origin_urls: list[str],
                 allow_post: bool = False) -> list[Finding]:
    out: list[Finding] = []
    for ep in endpoints:
        if ep.method != "GET" and not allow_post:
            continue
        for name in ep.params:
            canary = "knuth" + "x7q2z"
            base = await _probe(session, ep, name, "1")
            r = await _probe(session, ep, name, canary)
            if r and canary in r.text:
                r2 = await _probe(session, ep, name, f"{canary}<\"'>")
                if r2 and f'{canary}<"' in r2.text:
                    out.append(Finding("reflected-xss", "medium",
                                       "Input reflected with HTML metacharacters unescaped",
                                       ep.url, "needs manual confirmation of execution context", name))
                else:
                    out.append(Finding("reflection", "info", "Input reflected in response",
                                       ep.url, "metacharacters appear encoded", name))
            r = await _probe(session, ep, name, "1'")
            if r:
                for sig, rx in ERROR_SIGNATURES[:5]:
                    if rx.search(r.text) and not (base and rx.search(base.text)):
                        out.append(Finding("sqli-error", "high", f"Possible SQL injection ({sig} error on stray quote)",
                                           ep.url, "database error message triggered by a single quote", name))
                        break
            if REDIRECT_PARAMS.match(name):
                r = await _probe(session, ep, name, "https://knuth.invalid/x")
                if r and 300 <= r.status < 400 and (r.header("location") or "").startswith(
                        ("https://knuth.invalid", "//knuth.invalid")):
                    out.append(Finding("open-redirect", "medium", "Open redirect via parameter",
                                       ep.url, f"Location: {r.header('location')}", name))
    for url in origin_urls:
        try:
            r = await session.send(HttpRequest("GET", url, [("Origin", "https://knuth.invalid")]))
        except SendError:
            continue
        if r.header("access-control-allow-origin") == "https://knuth.invalid":
            creds = (r.header("access-control-allow-credentials") or "").lower() == "true"
            out.append(Finding("cors-reflected-origin", "high" if creds else "low",
                               "CORS reflects arbitrary Origin" + (" with credentials" if creds else ""), url))
    return out


async def sensitive_paths(session: Session, base: str) -> list[Finding]:
    out = []
    p = urlsplit(base)
    root = f"{p.scheme}://{p.netloc}"
    for path, rx in SENSITIVE_PATHS:
        try:
            r = await session.send(HttpRequest("GET", root + path))
        except SendError:
            continue
        if r.status == 200 and rx.search(r.text[:4096]):
            out.append(Finding("exposed-file", "high", f"Exposed file {path}", root + path))
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if f.key() not in seen:
            seen.add(f.key())
            out.append(f)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(out, key=lambda f: (order[f.severity], f.check, f.url))


def to_markdown(findings: list[Finding], targets: list[str]) -> str:
    lines = ["# knuth scan report", "", "Targets: " + ", ".join(targets), ""]
    if not findings:
        lines.append("No findings.")
    for f in findings:
        lines.append(f"## [{f.severity.upper()}] {f.title}")
        lines.append(f"- check: `{f.check}`")
        lines.append(f"- url: {f.url}")
        if f.param:
            lines.append(f"- parameter: `{f.param}`")
        if f.detail:
            lines.append(f"- detail: {f.detail}")
        lines.append("")
    return "\n".join(lines)
